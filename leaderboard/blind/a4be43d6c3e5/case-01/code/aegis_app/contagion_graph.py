# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（2-Hop 双向邻域 BFS + 增量时间边索引）与名单管理模块。"""
from __future__ import annotations

import bisect
from collections import deque
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .state import GatewayState, TenantState, get_gateway_state
from .window_stats import AccountWindowTracker


class TenantRiskGraphState:
    """单租户交易资金图与账户滑动窗口统一内存状态（支持事务级增量与回滚）。"""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.sanction_epoch: int = -1
        self.sanctioned: set[str] = set()
        self.adj: dict[str, dict[str, list[int]]] = {}
        self.accounts: dict[str, AccountWindowTracker] = {}

    def load_from_db(self, gw_state: GatewayState, t_state: TenantState) -> None:
        with gw_state.pool.borrow() as conn:
            s_rows = conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (self.tenant_id,),
            ).fetchall()
            tx_rows = conn.execute(
                "SELECT account_id, counterparty_id, amount_cents, ts FROM transactions WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchall()

        self.sanctioned = {r["entity_id"] for r in s_rows}
        self.sanction_epoch = t_state.sanction_epoch

        acct_raw: dict[str, list[tuple[int, int, str]]] = {}
        for r in tx_rows:
            u = r["account_id"]
            v = r["counterparty_id"]
            amt = int(r["amount_cents"])
            r_ts = int(r["ts"])
            acct_raw.setdefault(u, []).append((r_ts, amt, v))
            self.adj.setdefault(u, {}).setdefault(v, []).append(r_ts)
            self.adj.setdefault(v, {}).setdefault(u, []).append(r_ts)

        for neighbors in self.adj.values():
            for ts_list in neighbors.values():
                ts_list.sort()

        for acct_id, recs in acct_raw.items():
            self.accounts[acct_id] = AccountWindowTracker(recs)

    def refresh_sanctions_if_needed(self, gw_state: GatewayState, t_state: TenantState) -> None:
        if self.sanction_epoch == t_state.sanction_epoch:
            return
        with gw_state.pool.borrow() as conn:
            s_rows = conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (self.tenant_id,),
            ).fetchall()
        self.sanctioned = {r["entity_id"] for r in s_rows}
        self.sanction_epoch = t_state.sanction_epoch

    def add_edge(self, u: str, v: str, ts: int) -> None:
        bisect.insort(self.adj.setdefault(u, {}).setdefault(v, []), ts)
        bisect.insort(self.adj.setdefault(v, {}).setdefault(u, []), ts)

    def rollback_edges(self, edges: list[tuple[str, str, int]]) -> None:
        for u, v, ts in edges:
            for a, b in ((u, v), (v, u)):
                neighbors = self.adj.get(a)
                if not neighbors:
                    continue
                ts_list = neighbors.get(b)
                if not ts_list:
                    continue
                pos = bisect.bisect_left(ts_list, ts)
                if pos < len(ts_list) and ts_list[pos] == ts:
                    ts_list.pop(pos)
                    if not ts_list:
                        del neighbors[b]


def get_or_load_risk_graph(gw_state: GatewayState, t_state: TenantState) -> TenantRiskGraphState:
    rg = t_state.risk_graph_state
    if rg is None:
        rg = TenantRiskGraphState(t_state.tenant_id)
        rg.load_from_db(gw_state, t_state)
        t_state.risk_graph_state = rg
    else:
        rg.refresh_sanctions_if_needed(gw_state, t_state)
    return rg


def _edge_active(ts_list: list[int], win_start: int, ts: int) -> bool:
    idx = bisect.bisect_left(ts_list, win_start)
    return idx < len(ts_list) and ts_list[idx] <= ts


def compute_hop_from_graph(
    sanctioned: set[str],
    adj: dict[str, dict[str, list[int]]],
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """从交易两端出发执行最多 2 层时间窗邻域 BFS，等价求三跳制裁传染最小跳数。"""
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    win_start = ts - SLIDING_WINDOW_SECONDS
    visited: dict[str, int] = {account_id: 0}
    q: deque[tuple[str, int]] = deque([(account_id, 0)])
    if counterparty_id != account_id:
        visited[counterparty_id] = 0
        q.append((counterparty_id, 0))

    while q:
        curr, dist = q.popleft()
        if dist >= 2:
            continue
        neighbors = adj.get(curr)
        if not neighbors:
            continue
        nd = dist + 1
        for nxt, ts_list in neighbors.items():
            if nxt in visited:
                continue
            if not _edge_active(ts_list, win_start, ts):
                continue
            if nxt in sanctioned:
                return nd + 1
            visited[nxt] = nd
            if nd < 2:
                q.append((nxt, nd))
    return 0


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(tenant_id)
    with t_state.risk_lock:
        rg = get_or_load_risk_graph(gw_state, t_state)
        return compute_hop_from_graph(rg.sanctioned, rg.adj, account_id, counterparty_id, ts)


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
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    with t_state.sanction_lock:
        with gw_state.pool.borrow() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, ent, str(list_source or "CUSTOM"), act_val, now_ts),
            )
            conn.commit()
        t_state.sanction_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
