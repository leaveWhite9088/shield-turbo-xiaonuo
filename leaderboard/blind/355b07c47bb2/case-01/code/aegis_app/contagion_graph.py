# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（滑动窗口动态图 + 端点侧 2 跳早停）与名单管理模块。"""
from __future__ import annotations

import bisect
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .middleware import parse_strict_bool
from .runtime import GatewayRuntime, get_runtime


def _check_hop_in_adj(
    adj: dict[str, Any],
    account_id: str,
    counterparty_id: str,
    sanctioned: set[str],
) -> int:
    """从交易两端点出发执行最多 2 层邻接交集判定并立即早停。"""
    n1_a = adj.get(account_id)
    n1_b = adj.get(counterparty_id)
    if (n1_a and not sanctioned.isdisjoint(n1_a)) or (n1_b and not sanctioned.isdisjoint(n1_b)):
        return 2

    if not n1_a and not n1_b:
        return 0

    n1_nodes: set[str] = set()
    if n1_a:
        n1_nodes.update(n1_a)
    if n1_b:
        n1_nodes.update(n1_b)
    n1_nodes.discard(account_id)
    n1_nodes.discard(counterparty_id)

    for mid in n1_nodes:
        n2 = adj.get(mid)
        if n2 and not sanctioned.isdisjoint(n2):
            return 3
    return 0


class TenantContagionGraph:
    """租户 24 小时动态资金传染图：单调窗口 O(1) 边滑窗维护 + 乱序时间戳精确回退 + 原子回滚。"""

    __slots__ = ("ts_list", "edges", "max_ts", "left_idx", "adj")

    def __init__(self) -> None:
        self.ts_list: list[int] = []
        self.edges: list[tuple[int, str, str]] = []  # (ts, u, v)
        self.max_ts: int = -1
        self.left_idx: int = 0
        self.adj: dict[str, dict[str, int]] = {}

    def _add_adj_edge(self, u: str, v: str) -> None:
        mu = self.adj.get(u)
        if mu is None:
            self.adj[u] = {v: 1}
        else:
            mu[v] = mu.get(v, 0) + 1
        mv = self.adj.get(v)
        if mv is None:
            self.adj[v] = {u: 1}
        else:
            mv[u] = mv.get(u, 0) + 1

    def _remove_adj_edge(self, u: str, v: str) -> None:
        mu = self.adj.get(u)
        if mu is not None:
            c = mu.get(v, 0) - 1
            if c <= 0:
                mu.pop(v, None)
                if not mu:
                    self.adj.pop(u, None)
            else:
                mu[v] = c
        mv = self.adj.get(v)
        if mv is not None:
            c = mv.get(u, 0) - 1
            if c <= 0:
                mv.pop(u, None)
                if not mv:
                    self.adj.pop(v, None)
            else:
                mv[u] = c

    def load_sorted_edges(self, sorted_edges: list[tuple[int, str, str]]) -> None:
        self.edges = list(sorted_edges)
        self.ts_list = [e[0] for e in self.edges]
        self.rebuild_fast_state()

    def rebuild_fast_state(self) -> None:
        self.adj.clear()
        if not self.edges:
            self.max_ts = -1
            self.left_idx = 0
            return
        self.max_ts = self.ts_list[-1]
        win_start = self.max_ts - SLIDING_WINDOW_SECONDS
        self.left_idx = bisect.bisect_left(self.ts_list, win_start)
        for i in range(self.left_idx, len(self.edges)):
            _, u, v = self.edges[i]
            self._add_adj_edge(u, v)

    def _push_edge_monotonic(self, ts: int, u: str, v: str) -> None:
        self.max_ts = ts
        win_start = ts - SLIDING_WINDOW_SECONDS
        ts_list = self.ts_list
        edges = self.edges
        n_cur = len(edges)
        while self.left_idx < n_cur and ts_list[self.left_idx] < win_start:
            _, old_u, old_v = edges[self.left_idx]
            self._remove_adj_edge(old_u, old_v)
            self.left_idx += 1
        ts_list.append(ts)
        edges.append((ts, u, v))
        self._add_adj_edge(u, v)

    def _push_edge_out_of_order(self, ts: int, u: str, v: str) -> None:
        insert_pos = bisect.bisect_right(self.ts_list, ts)
        self.ts_list.insert(insert_pos, ts)
        self.edges.insert(insert_pos, (ts, u, v))
        if insert_pos <= self.left_idx:
            if ts >= self.max_ts - SLIDING_WINDOW_SECONDS:
                self._add_adj_edge(u, v)
            else:
                self.left_idx += 1
        else:
            self._add_adj_edge(u, v)

    def query_and_push(
        self,
        account_id: str,
        counterparty_id: str,
        ts: int,
        sanctioned: set[str],
    ) -> int:
        """在 [ts - 86400, ts] 活跃图上计算当前交易的 3 跳传染等级，并将本交易边增量入图。"""
        win_start = ts - SLIDING_WINDOW_SECONDS
        is_monotonic = ts >= self.max_ts

        if not sanctioned:
            hop = 0
            if is_monotonic:
                self._push_edge_monotonic(ts, account_id, counterparty_id)
            else:
                self._push_edge_out_of_order(ts, account_id, counterparty_id)
            return hop

        if account_id in sanctioned or counterparty_id in sanctioned:
            hop = 1
            if is_monotonic:
                self._push_edge_monotonic(ts, account_id, counterparty_id)
            else:
                self._push_edge_out_of_order(ts, account_id, counterparty_id)
            return hop

        if is_monotonic:
            # 单调递增快路径：先淘汰过期边，再做端点侧 2 跳交集判定
            self.max_ts = ts
            ts_list = self.ts_list
            edges = self.edges
            n_cur = len(edges)
            while self.left_idx < n_cur and ts_list[self.left_idx] < win_start:
                _, old_u, old_v = edges[self.left_idx]
                self._remove_adj_edge(old_u, old_v)
                self.left_idx += 1
            hop = _check_hop_in_adj(self.adj, account_id, counterparty_id, sanctioned)
            ts_list.append(ts)
            edges.append((ts, account_id, counterparty_id))
            self._add_adj_edge(account_id, counterparty_id)
            return hop

        # 乱序时间戳精确回退路径：二分定位 [ts - 86400, ts] 精确建局部邻接表
        lo = bisect.bisect_left(self.ts_list, win_start)
        hi = bisect.bisect_right(self.ts_list, ts)
        local_adj: dict[str, set[str]] = {}
        for i in range(lo, hi):
            _, u, v = self.edges[i]
            local_adj.setdefault(u, set()).add(v)
            local_adj.setdefault(v, set()).add(u)
        hop = _check_hop_in_adj(local_adj, account_id, counterparty_id, sanctioned)
        self._push_edge_out_of_order(ts, account_id, counterparty_id)
        return hop

    def rollback_edges(self, added_edges: list[tuple[int, str, str]]) -> None:
        """批次失败回滚时精准移除本批次新增的所有边并重建快路径邻接表。"""
        for edge in reversed(added_edges):
            e_ts = edge[0]
            lo = bisect.bisect_left(self.ts_list, e_ts)
            hi = bisect.bisect_right(self.ts_list, e_ts)
            for idx in range(hi - 1, lo - 1, -1):
                if self.edges[idx] == edge:
                    del self.edges[idx]
                    del self.ts_list[idx]
                    break
        self.rebuild_fast_state()


def get_sanctioned_entities(db_path: str, tenant_id: str) -> set[str]:
    rt = get_runtime(db_path)
    cached = rt.sanction_cache.get(tenant_id)
    if cached is not None:
        return set(cached)
    with rt.sanction_lock(tenant_id):
        cached = rt.sanction_cache.get(tenant_id)
        if cached is None:
            with rt.read_conn() as conn:
                rows = conn.execute(
                    "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                    (tenant_id,),
                ).fetchall()
            cached = {str(r["entity_id"]) for r in rows}
            rt.sanction_cache[tenant_id] = cached
        return set(cached)


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """独立查询入口：基于索引范围查询与端点侧 2 跳早停计算三跳制裁传染等级。"""
    sanctioned = get_sanctioned_entities(db_path, tenant_id)
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    win_start = int(ts) - SLIDING_WINDOW_SECONDS
    rt = get_runtime(db_path)
    with rt.read_conn() as conn:
        tx_rows = conn.execute(
            "SELECT account_id, counterparty_id FROM transactions "
            "WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
            (tenant_id, win_start, int(ts)),
        ).fetchall()

    adj: dict[str, set[str]] = {}
    for r in tx_rows:
        u = str(r["account_id"])
        v = str(r["counterparty_id"])
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)

    return _check_hop_in_adj(adj, account_id, counterparty_id, sanctioned)


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单，并增量刷新黑名单缓存。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent or len(ent) > 128:
        raise ValueError("entity_id is required and must be <= 128 chars")
    act_bool = parse_strict_bool(active, "active")
    src_str = str(list_source or "CUSTOM").strip()
    if len(src_str) > 64:
        raise ValueError("list_source exceeds maximum length")
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if act_bool else 0

    rt = get_runtime(db_path)
    with rt.sanction_lock(caller.tenant_id):
        with rt.write_tx() as conn:
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, ent, src_str, act_val, now_ts),
            )
        cached = rt.sanction_cache.get(caller.tenant_id)
        if cached is not None:
            if act_bool:
                cached.add(ent)
            else:
                cached.discard(ent)
        rt.epochs(caller.tenant_id).sanction_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": src_str,
        "active": act_bool,
        "updated_at": now_ts,
    }
