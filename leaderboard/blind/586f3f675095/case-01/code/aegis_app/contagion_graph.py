# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph）与名单管理模块。

图连通与传染跳数定义（与原版语义完全一致）：
- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条**双向**资金关联边；
- 当前正在评估的交易自身的边 (account_id, counterparty_id) 同步计入当前图；
- 设活跃受制裁实体集合为 S（sanctioned_entities 表中 active = 1 的 entity_id）：
  * 若 tx.account_id 或 tx.counterparty_id 直接命中 S，则 hop = 1；
  * 否则 hop = min(端点或对手方到 S 的最短无向距离) + 1，仅当 hop <= 3 时记为该跳数。

复杂度：原版从每个受制裁源点 BFS 并扫描整表交易；本版维护**按时间索引的增量邻接表**，
只从被评估交易的两个端点反向 BFS 两层（即 d <= 2），命中任何受制裁实体即返回，
并且**先判 1 跳**（只在端点 1 跳邻域里找源点），避免为每个租户/每批交易重建整图。
"""
from __future__ import annotations

import threading
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import MAX_ID_CHARS, SLIDING_WINDOW_SECONDS
from .db import GatewayDB
from .guards import guard_text


class TenantAdjacency:
    """单租户资金邻接表：``node -> (时间戳列表, 邻居列表)``，按窗口下界惰性压缩（摊还 O(1)）。"""

    __slots__ = ("adj", "live", "dirty")

    def __init__(self) -> None:
        self.adj: dict[str, tuple[list[int], list[str]]] = {}
        self.live = 0
        self.dirty = 0

    def add(self, u: str, v: str, ts: int) -> None:
        adj = self.adj
        for a, b in ((u, v), (v, u)):
            entry = adj.get(a)
            if entry is None:
                entry = ([], [])
                adj[a] = entry
            entry[0].append(ts)
            entry[1].append(b)
        self.live += 2
        self.dirty += 2

    def compact(self, win_start: int) -> None:
        """全局半衰压缩：已过期标记超过存活边一半时，一次性剪掉窗口外条目。"""
        if self.dirty < 4096 or self.dirty * 2 < self.live:
            return
        kept = 0
        for node, (marks, nbrs) in self.adj.items():
            if not marks:
                continue
            keep_m: list[int] = []
            keep_n: list[str] = []
            for m, n in zip(marks, nbrs):
                if m >= win_start:
                    keep_m.append(m)
                    keep_n.append(n)
            kept += len(keep_m)
            if keep_m:
                self.adj[node] = (keep_m, keep_n)
            else:
                del self.adj[node]
        self.live = kept
        self.dirty = 0

    def neighbors(self, node: str, win_start: int, ts_hi: int) -> list[str]:
        entry = self.adj.get(node)
        if entry is None:
            return []
        marks, nbrs = entry
        out: list[str] = []
        append = out.append
        for i in range(len(marks) - 1, -1, -1):
            m = marks[i]
            if win_start <= m <= ts_hi:
                append(nbrs[i])
        return out


class ContagionStore:
    """按租户惰性装载 + 增量的资金邻接表与受制裁集合（共享实例持有）。"""

    __slots__ = ("graphs", "sanctioned", "loaded", "lock")

    def __init__(self) -> None:
        self.graphs: dict[str, TenantAdjacency] = {}
        self.sanctioned: dict[str, set[str]] = {}
        self.loaded: set[str] = set()
        self.lock = threading.Lock()

    def ensure(self, db: GatewayDB, tenant_id: str) -> TenantAdjacency:
        graph = self.graphs.get(tenant_id)
        if graph is not None:
            return graph
        with self.lock:
            graph = self.graphs.get(tenant_id)
            if graph is not None:
                return graph
            graph = TenantAdjacency()
            sanctioned: set[str] = set()
            for r in db.rows(
                "SELECT entity_id, active FROM sanctioned_entities WHERE tenant_id = ?",
                (tenant_id,),
            ):
                if int(r["active"]) == 1:
                    sanctioned.add(r["entity_id"])
            if tenant_id not in self.loaded:
                cur = db.cursor(
                    "SELECT account_id, counterparty_id, ts FROM transactions WHERE tenant_id = ?",
                    (tenant_id,),
                )
                for acc, cp, ts in cur:
                    graph.add(acc, cp, int(ts))
                cur.close()
                self.loaded.add(tenant_id)
            self.graphs[tenant_id] = graph
            self.sanctioned[tenant_id] = sanctioned
        return graph

    def record_edge(self, tenant_id: str, account_id: str, counterparty_id: str, ts: int) -> None:
        graph = self.graphs.get(tenant_id)
        if graph is not None:
            graph.add(account_id, counterparty_id, ts)

    def set_sanctioned(self, tenant_id: str, entity_id: str, active: bool) -> None:
        s = self.sanctioned.get(tenant_id)
        if s is None:
            return
        if active:
            s.add(entity_id)
        else:
            s.discard(entity_id)

    def forget(self, tenant_id: str) -> None:
        self.graphs.pop(tenant_id, None)
        self.sanctioned.pop(tenant_id, None)
        self.loaded.discard(tenant_id)


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
    *,
    db: GatewayDB | None = None,
    store: ContagionStore | None = None,
) -> int:
    """计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    work = db if db is not None else GatewayDB(db_path)
    own = db is None
    try:
        if store is None:
            sanctioned = {
                r["entity_id"]
                for r in work.rows(
                    "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                    (tenant_id,),
                )
            }
            if not sanctioned:
                return 0
            if account_id in sanctioned or counterparty_id in sanctioned:
                return 1
            win_start = ts - SLIDING_WINDOW_SECONDS
            adj: dict[str, list[str]] = {}
            cur = work.cursor(
                "SELECT account_id, counterparty_id, ts FROM transactions WHERE tenant_id = ?", (tenant_id,)
            )
            for u, v, r_ts in cur:
                r_ts = int(r_ts)
                if win_start <= r_ts <= ts:
                    adj.setdefault(u, []).append(v)
                    adj.setdefault(v, []).append(u)
            cur.close()
            return _bfs_hop(adj, account_id, counterparty_id, sanctioned)

        graph = store.ensure(work, tenant_id)
        sanctioned = store.sanctioned.get(tenant_id, set())
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1
        win_start = ts - SLIDING_WINDOW_SECONDS
        graph.compact(win_start)
        extra = (counterparty_id, account_id)          # 当前交易自身的边
        return _hop_from_endpoints(graph, account_id, counterparty_id, sanctioned, win_start, ts, extra)
    finally:
        if own:
            work.close_thread()


def _bfs_hop(adj: dict[str, list[str]], account_id: str, counterparty_id: str, sanctioned: set[str]) -> int:
    """参考实现：从每个受制裁源点 BFS（d <= 2），取端点最小距离 + 1。"""
    adj.setdefault(account_id, []).append(counterparty_id)
    adj.setdefault(counterparty_id, []).append(account_id)
    best_hop = 0
    for src in sanctioned:
        if src not in adj:
            continue
        queue: list[tuple[str, int]] = [(src, 0)]
        visited = {src: 0}
        while queue:
            curr, dist = queue.pop(0)
            if dist >= 2:
                continue
            for nxt in adj.get(curr, []):
                if nxt not in visited or visited[nxt] > dist + 1:
                    visited[nxt] = dist + 1
                    queue.append((nxt, dist + 1))
        for endpoint in (account_id, counterparty_id):
            if endpoint in visited:
                hop = visited[endpoint] + 1
                if 1 <= hop <= 3 and (best_hop == 0 or hop < best_hop):
                    best_hop = hop
    return best_hop


def _hop_from_endpoints(graph: TenantAdjacency, account_id: str, counterparty_id: str,
                        sanctioned: set[str], win_start: int, ts: int, extra: tuple[str, str]) -> int:
    """反向 BFS：只看距端点 d <= 2 的邻域是否存在受制裁实体，d 越小 hop 越小，逐层判定即可早停。"""
    is_sanc = sanctioned.__contains__
    # d = 1：端点自身的 1 跳邻域（含当前交易自身边）
    ring = graph.neighbors(account_id, win_start, ts)
    ring.extend(graph.neighbors(counterparty_id, win_start, ts))
    ring.append(extra[0])
    ring.append(extra[1])
    if any(map(is_sanc, ring)):
        return 2
    # d = 2：1 跳邻域的 1 跳邻域
    seen: set[str] = {account_id, counterparty_id}
    for nbr in ring:
        if nbr in seen:
            continue
        seen.add(nbr)
        nbr2 = graph.neighbors(nbr, win_start, ts)
        if nbr2 and any(map(is_sanc, nbr2)):
            return 3
    # d >= 3 ⇒ hop >= 4，不计入
    return 0


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
    store: ContagionStore | None = None,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent:
        raise ValueError("entity_id is required")
    guard_text(ent, name="entity_id", max_chars=MAX_ID_CHARS)
    guard_text(str(list_source or ""), name="list_source", max_chars=MAX_ID_CHARS)
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        db.write(lambda conn: _upsert_sanction(conn, caller.tenant_id, ent, str(list_source or "CUSTOM"), act_val, now_ts))
    finally:
        if own:
            db.close_thread()
    if store is not None:
        store.set_sanctioned(caller.tenant_id, ent, bool(act_val))

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }


def _upsert_sanction(conn, tenant_id: str, ent: str, list_source: str, act_val: int, now_ts: int) -> None:
    conn.execute(
        "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
        "active = excluded.active, updated_at = excluded.updated_at",
        (tenant_id, ent, list_source, act_val, now_ts),
    )
