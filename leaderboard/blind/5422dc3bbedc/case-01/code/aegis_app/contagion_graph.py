# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph）与名单管理模块。

图连通与传染跳数定义（与原版逐位一致）：
- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条双向资金关联边；
- 当前正在评估的交易自身的边 (tx.account_id, tx.counterparty_id) 同步计入当前图；
- 设活跃受制裁实体集合为 S：交易两端直接命中名单则 hop = 1；否则取两端到 S 的
  最短无向边路径 d_min，hop = d_min + 1；hop > 3 或不可达记 0。

性能契约：
- 全局多源 BFS（深度 ≤ 2）替代原版"逐制裁源点重复 BFS"，复杂度由 O(|S|·(V+E))
  降为 O(V+E)；
- 批次场景使用 ``ContagionEdgeTracker``：按 ts 排序的边集 + 双指针滑窗增量构建
  邻接表，乱序时间戳自动精确回退重建，彻底消除原版逐笔全表扫描。
"""
from __future__ import annotations

import time
from bisect import bisect_left, bisect_right
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import open_connection
from .index_cache import get_state


def _multi_source_hop(adj: dict[str, list[str]], sanctioned: set[str], endpoints: tuple[str, str]) -> int:
    """全局多源 BFS（深度 ≤ 2）：返回两端点到制裁集合的最短 (d_min + 1) 跳数。"""
    visited: dict[str, int] = {}
    frontier: list[str] = []
    for src in sanctioned:
        if src in adj and src not in visited:
            visited[src] = 0
            frontier.append(src)
    for depth in (1, 2):
        if not frontier:
            break
        nxt: list[str] = []
        for node in frontier:
            for nb in adj.get(node, ()):
                if nb not in visited:
                    visited[nb] = depth
                    nxt.append(nb)
        frontier = nxt

    best = 0
    for endpoint in endpoints:
        dist = visited.get(endpoint)
        if dist is not None:
            hop = dist + 1
            if 1 <= hop <= 3 and (best == 0 or hop < best):
                best = hop
    return best


class ContagionEdgeTracker:
    """批次滑窗传染图：按 ts 排序边集 + 双指针增量邻接表（乱序时间戳精确回退）。"""

    __slots__ = ("_ets", "_eu", "_ev", "adj", "cur_lo", "cur_hi", "prev_ts", "_dirty")

    def __init__(self, edges: Iterable[tuple[int, str, str]]) -> None:
        sorted_edges = sorted(edges, key=lambda e: e[0])
        self._ets = [e[0] for e in sorted_edges]
        self._eu = [e[1] for e in sorted_edges]
        self._ev = [e[2] for e in sorted_edges]
        self.adj: dict[str, list[str]] = {}
        self.cur_lo = 0
        self.cur_hi = 0
        self.prev_ts: int | None = None
        self._dirty = False

    def append_edge(self, ts: int, u: str, v: str) -> None:
        """批次内先序交易边增量入图（与原版"先落库后评估"的窗口可见性语义一致）。"""
        pos = bisect_right(self._ets, ts)
        self._ets.insert(pos, ts)
        self._eu.insert(pos, u)
        self._ev.insert(pos, v)
        if pos < self.cur_hi:
            self._dirty = True  # 插入点落在当前窗口内，指针索引失效，下次精确重建

    def _add(self, idx: int) -> None:
        u = self._eu[idx]
        v = self._ev[idx]
        lst = self.adj.get(u)
        if lst is None:
            self.adj[u] = [v]
        else:
            lst.append(v)
        lst = self.adj.get(v)
        if lst is None:
            self.adj[v] = [u]
        else:
            lst.append(u)

    def _remove(self, idx: int) -> None:
        u = self._eu[idx]
        v = self._ev[idx]
        lst = self.adj.get(u)
        if lst is not None:
            try:
                lst.remove(v)
            except ValueError:
                pass
        lst = self.adj.get(v)
        if lst is not None:
            try:
                lst.remove(u)
            except ValueError:
                pass

    def update(self, ts: int) -> None:
        """将邻接表同步到 [ts - 86400, ts] 精确窗口（增量 O(进出边数)，乱序重建）。"""
        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect_left(self._ets, win_start)
        hi = bisect_right(self._ets, ts)
        if (
            self._dirty
            or self.prev_ts is None
            or ts < self.prev_ts
            or lo < self.cur_lo
            or hi < self.cur_hi
        ):
            self.adj = {}
            for i in range(lo, hi):
                self._add(i)
        else:
            # 增量进出窗：仅处理与旧窗口相交部分；lo > cur_hi 时空档区间绝不入图
            evict_end = min(lo, self.cur_hi)
            for i in range(self.cur_lo, evict_end):
                self._remove(i)
            add_start = max(self.cur_hi, lo)
            for j in range(add_start, hi):
                self._add(j)
        self.cur_lo = lo
        self.cur_hi = hi
        self.prev_ts = ts
        self._dirty = False

    def hop_for(self, sanctioned: set[str], account_id: str, counterparty_id: str) -> int:
        """在当前窗口图上加入当前交易边后执行多源 BFS，随后精确移除该临时边。"""
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1

        adj = self.adj
        lst = adj.get(account_id)
        if lst is None:
            adj[account_id] = [counterparty_id]
            added_u = True
        else:
            lst.append(counterparty_id)
            added_u = False
        lst = adj.get(counterparty_id)
        if lst is None:
            adj[counterparty_id] = [account_id]
            added_v = True
        else:
            lst.append(account_id)
            added_v = False
        try:
            return _multi_source_hop(adj, sanctioned, (account_id, counterparty_id))
        finally:
            if added_u:
                adj.pop(account_id, None)
            else:
                try:
                    lst_u = adj.get(account_id)
                    if lst_u is not None:
                        lst_u.remove(counterparty_id)
                except ValueError:
                    pass
            if added_v:
                adj.pop(counterparty_id, None)
            else:
                try:
                    lst_v = adj.get(counterparty_id)
                    if lst_v is not None:
                        lst_v.remove(account_id)
                except ValueError:
                    pass


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    sanctions = tstate.sanctions(db_path)
    sanctioned = {ent for ent, flag in sanctions.items() if flag == 1}
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    conn = open_connection(db_path)
    try:
        tx_rows = conn.execute(
            "SELECT account_id, counterparty_id, ts FROM transactions "
            "WHERE tenant_id = ? AND ts <= ?",
            (tenant_id, int(ts)),
        ).fetchall()
    finally:
        conn.close()

    edges = [
        (int(r["ts"]), r["account_id"], r["counterparty_id"])
        for r in tx_rows
        if int(r["ts"]) >= ts - SLIDING_WINDOW_SECONDS
    ]
    tracker = ContagionEdgeTracker(edges)
    tracker.update(int(ts))
    return tracker.hop_for(sanctioned, account_id, counterparty_id)


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent:
        raise ValueError("entity_id is required")
    if len(ent) > 128 or len(list_source) > 64:
        raise ValueError("entity_id or list_source exceeds length limit")
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0
    conn = open_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
            "active = excluded.active, updated_at = excluded.updated_at",
            (caller.tenant_id, ent, str(list_source or "CUSTOM"), act_val, now_ts),
        )
        conn.commit()
    finally:
        conn.close()

    get_state(db_path).tenant(caller.tenant_id).bump_sanctions()

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
