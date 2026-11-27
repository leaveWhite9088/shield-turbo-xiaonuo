# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph · 内存增量邻接表 + 双向两步邻域交集 + 原子回滚）。

图连通与传染跳数定义：
- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条双向资金关联边；
- 当前正在评估的交易自身的边 (tx.account_id, tx.counterparty_id) 同步计入当前图；
- 设活跃受制裁实体集合为 S（sanctioned_entities 表中 active=1 的 entity_id）：
  * 若 tx.account_id in S 或 tx.counterparty_id in S，则传染跳数 hop = 1；
  * 否则若 tx.account_id 或 tx.counterparty_id 与 S 中任一实体直接相邻（1 跳邻居集合 N1(S)），则 hop = 2；
  * 否则若 tx.account_id 或 tx.counterparty_id 的邻居中包含 N1(S) 中的节点，则 hop = 3；
  * 否则记为 0（无三跳内制裁传染）。
"""
from __future__ import annotations

import bisect
from collections import deque
import time
from typing import Any, Callable

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import (
    bump_sanction_epoch,
    get_tenant_epochs,
    get_tenant_risk_lock,
    normalize_db_key,
    open_connection,
    register_reset_callback,
)
from .middleware import strict_bool


class TenantContagionGraph:
    """租户 24 小时活跃资金关联图与三跳制裁传染增量计算器（支持单调流滑动过期、乱序二分回退与原子回滚）。"""

    __slots__ = (
        "tenant_id",
        "sanction_epoch",
        "sanctioned",
        "all_edges",
        "max_ts",
        "edge_deque",
        "adj_counts",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.sanction_epoch: int = -1
        self.sanctioned: set[str] = set()
        # 按 ts 升序排列的完整交易边: (ts, account_id, counterparty_id)
        self.all_edges: list[tuple[int, str, str]] = []
        self.max_ts: int = -1
        self.edge_deque: deque[tuple[int, str, str]] = deque()
        self.adj_counts: dict[str, dict[str, int]] = {}

    def _inc_adj(self, u: str, v: str) -> None:
        nbs = self.adj_counts.get(u)
        if nbs is None:
            self.adj_counts[u] = {v: 1}
        else:
            nbs[v] = nbs.get(v, 0) + 1

    def _dec_adj(self, u: str, v: str) -> None:
        nbs = self.adj_counts.get(u)
        if nbs is not None:
            c = nbs.get(v, 0)
            if c <= 1:
                nbs.pop(v, None)
                if not nbs:
                    self.adj_counts.pop(u, None)
            else:
                nbs[v] = c - 1

    def _rebuild_active_graph_for_max_ts(self) -> None:
        self.edge_deque.clear()
        self.adj_counts.clear()
        if not self.all_edges:
            self.max_ts = -1
            return
        self.max_ts = self.all_edges[-1][0]
        win_start = self.max_ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(self.all_edges, (win_start, "", ""))
        for idx in range(lo, len(self.all_edges)):
            ed = self.all_edges[idx]
            _, u, v = ed
            self.edge_deque.append(ed)
            self._inc_adj(u, v)
            self._inc_adj(v, u)

    def sync_sanctions(self, db_path: str) -> None:
        cur_ep = get_tenant_epochs(db_path, self.tenant_id).sanction_epoch
        if self.sanction_epoch == cur_ep:
            return
        conn = open_connection(db_path)
        try:
            s_rows = conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (self.tenant_id,),
            ).fetchall()
        finally:
            conn.close()
        self.sanctioned = {str(r["entity_id"]) for r in s_rows}
        self.sanction_epoch = cur_ep

    def _compute_hop_from_adj(
        self,
        adj_map: dict[str, dict[str, int]] | dict[str, set[str]],
        account_id: str,
        counterparty_id: str,
    ) -> int:
        sanc = self.sanctioned
        if not sanc:
            return 0
        if account_id in sanc or counterparty_id in sanc:
            return 1

        # 双向邻域交集：收集所有活跃受制裁实体的一跳邻居集合 N1(S)
        n1_s: set[str] = set()
        for s in sanc:
            nbs = adj_map.get(s)
            if nbs:
                n1_s.update(nbs)
        if not n1_s:
            return 0

        if account_id in n1_s or counterparty_id in n1_s:
            return 2

        acct_nbs = adj_map.get(account_id)
        if acct_nbs and any(nb in n1_s for nb in acct_nbs):
            return 3
        cp_nbs = adj_map.get(counterparty_id)
        if cp_nbs and any(nb in n1_s for nb in cp_nbs):
            return 3
        return 0

    def stage_and_evaluate(
        self,
        db_path: str,
        account_id: str,
        counterparty_id: str,
        ts: int,
        undo_log: list[Callable[[], None]],
    ) -> int:
        """在活跃窗口图上纳入当前交易边 (account_id, counterparty_id, ts)，计算三跳制裁传染等级并登记原子回滚动作。"""
        self.sync_sanctions(db_path)
        new_edge = (int(ts), str(account_id), str(counterparty_id))

        if ts >= self.max_ts:
            prev_max_ts = self.max_ts
            win_start = ts - SLIDING_WINDOW_SECONDS
            evicted: list[tuple[int, str, str]] = []

            while self.edge_deque and self.edge_deque[0][0] < win_start:
                old_ed = self.edge_deque.popleft()
                evicted.append(old_ed)
                _, ou, ov = old_ed
                self._dec_adj(ou, ov)
                self._dec_adj(ov, ou)

            self.max_ts = ts
            self.all_edges.append(new_edge)
            self.edge_deque.append(new_edge)
            self._inc_adj(account_id, counterparty_id)
            self._inc_adj(counterparty_id, account_id)

            def _undo_monotonic() -> None:
                self.all_edges.pop()
                self.edge_deque.pop()
                self._dec_adj(account_id, counterparty_id)
                self._dec_adj(counterparty_id, account_id)
                for rev_ed in reversed(evicted):
                    _, ru, rv = rev_ed
                    self.edge_deque.appendleft(rev_ed)
                    self._inc_adj(ru, rv)
                    self._inc_adj(rv, ru)
                self.max_ts = prev_max_ts

            undo_log.append(_undo_monotonic)
            return self._compute_hop_from_adj(self.adj_counts, account_id, counterparty_id)

        # 乱序时间戳（ts < max_ts）二分切片路径
        ins_idx = bisect.bisect_right(self.all_edges, new_edge)
        self.all_edges.insert(ins_idx, new_edge)
        self._rebuild_active_graph_for_max_ts()

        def _undo_out_of_order() -> None:
            self.all_edges.pop(ins_idx)
            self._rebuild_active_graph_for_max_ts()

        undo_log.append(_undo_out_of_order)

        if not self.sanctioned:
            return 0
        if account_id in self.sanctioned or counterparty_id in self.sanctioned:
            return 1

        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(self.all_edges, (win_start, "", ""))
        hi = bisect.bisect_right(self.all_edges, (ts, "\uffff", "\uffff"))
        temp_adj: dict[str, set[str]] = {}
        for idx in range(lo, hi):
            _, eu, ev = self.all_edges[idx]
            temp_adj.setdefault(eu, set()).add(ev)
            temp_adj.setdefault(ev, set()).add(eu)
        return self._compute_hop_from_adj(temp_adj, account_id, counterparty_id)


_MAX_CONTAGION_GRAPHS = 128
_CONTAGION_GRAPHS: dict[tuple[str, str], TenantContagionGraph] = {}


def _reset_contagion_graphs(db_key: str) -> None:
    for k in [k for k in _CONTAGION_GRAPHS if k[0] == db_key]:
        _CONTAGION_GRAPHS.pop(k, None)


register_reset_callback(_reset_contagion_graphs)


def get_or_load_contagion_graph(db_path: str, tenant_id: str) -> TenantContagionGraph:
    db_key = normalize_db_key(db_path)
    cache_key = (db_key, tenant_id)
    graph = _CONTAGION_GRAPHS.get(cache_key)
    if graph is not None:
        graph.sync_sanctions(db_path)
        return graph

    graph = TenantContagionGraph(tenant_id)
    conn = open_connection(db_path)
    try:
        tx_rows = conn.execute(
            "SELECT account_id, counterparty_id, ts "
            "FROM transactions WHERE tenant_id = ? ORDER BY ts ASC, rowid ASC",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    for r in tx_rows:
        graph.all_edges.append((int(r["ts"]), str(r["account_id"]), str(r["counterparty_id"])))
    graph._rebuild_active_graph_for_max_ts()
    graph.sync_sanctions(db_path)

    if len(_CONTAGION_GRAPHS) >= _MAX_CONTAGION_GRAPHS and cache_key not in _CONTAGION_GRAPHS:
        _CONTAGION_GRAPHS.pop(next(iter(_CONTAGION_GRAPHS)), None)
    _CONTAGION_GRAPHS[cache_key] = graph
    return graph


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（无副作用只读评估）。"""
    with get_tenant_risk_lock(db_path, tenant_id):
        graph = get_or_load_contagion_graph(db_path, tenant_id)
        temp_undo: list[Callable[[], None]] = []
        try:
            return graph.stage_and_evaluate(db_path, account_id, counterparty_id, int(ts), temp_undo)
        finally:
            for fn in reversed(temp_undo):
                fn()


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单（仅递增 sanction_epoch）。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent or len(ent) > 128:
        raise ValueError("Valid entity_id is required")
    src = str(list_source or "CUSTOM").strip()
    if not src or len(src) > 64:
        raise ValueError("Valid list_source is required")
    act_bool = strict_bool(active, "active")
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if act_bool else 0

    with get_tenant_risk_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, ent, src, act_val, now_ts),
            )
            conn.commit()
        finally:
            conn.close()
        bump_sanction_epoch(db_path, caller.tenant_id)
        db_key = normalize_db_key(db_path)
        graph = _CONTAGION_GRAPHS.get((db_key, caller.tenant_id))
        if graph is not None:
            if act_bool:
                graph.sanctioned.add(ent)
            else:
                graph.sanctioned.discard(ent)
            graph.sanction_epoch = get_tenant_epochs(db_path, caller.tenant_id).sanction_epoch

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": src,
        "active": act_bool,
        "updated_at": now_ts,
    }
