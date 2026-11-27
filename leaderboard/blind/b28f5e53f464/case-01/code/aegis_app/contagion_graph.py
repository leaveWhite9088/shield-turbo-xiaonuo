# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（双向自适应 1-Hop 图索引版）与名单管理模块。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .runtime import GatewayRuntime, TenantRiskState, get_runtime


def _collect_active_neighbors(
    risk_state: TenantRiskState,
    node: str,
    win_start: int,
    ts: int,
    staged_edges: dict[str, dict[str, list[int]]] | None = None,
) -> set[str]:
    neighbors: set[str] = set()
    adj_map = risk_state.adj.get(node)
    if adj_map:
        for nbr, ts_list in adj_map.items():
            if TenantRiskState.has_edge_in_window(ts_list, win_start, ts):
                neighbors.add(nbr)
    if staged_edges:
        s_map = staged_edges.get(node)
        if s_map:
            for nbr, ts_list in s_map.items():
                if nbr not in neighbors and TenantRiskState.has_edge_in_window(ts_list, win_start, ts):
                    neighbors.add(nbr)
    return neighbors


def _has_active_edge_to_target_set(
    risk_state: TenantRiskState,
    node: str,
    target_set: set[str],
    win_start: int,
    ts: int,
    staged_edges: dict[str, dict[str, list[int]]] | None = None,
) -> bool:
    adj_map = risk_state.adj.get(node)
    if adj_map:
        for nbr, ts_list in adj_map.items():
            if nbr in target_set and TenantRiskState.has_edge_in_window(ts_list, win_start, ts):
                return True
    if staged_edges:
        s_map = staged_edges.get(node)
        if s_map:
            for nbr, ts_list in s_map.items():
                if nbr in target_set and TenantRiskState.has_edge_in_window(ts_list, win_start, ts):
                    return True
    return False


def compute_sanction_contagion_hop_fast(
    risk_state: TenantRiskState,
    account_id: str,
    counterparty_id: str,
    ts: int,
    *,
    staged_edges: dict[str, dict[str, list[int]]] | None = None,
) -> int:
    """利用内存邻接表与双向自适应 1-Hop 扩展在 O(min(deg(S), deg(N1))) 内计算 3-Hop 传染跳数。"""
    sanctioned = risk_state.sanctioned_set
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    win_start = ts - SLIDING_WINDOW_SECONDS
    n1 = _collect_active_neighbors(risk_state, account_id, win_start, ts, staged_edges)
    n1 |= _collect_active_neighbors(risk_state, counterparty_id, win_start, ts, staged_edges)
    if not n1:
        return 0
    if n1 & sanctioned:
        return 2

    cost_s = sum(
        len(risk_state.adj.get(s, ())) + (len(staged_edges.get(s, ())) if staged_edges else 0)
        for s in sanctioned
    )
    cost_n1 = sum(
        len(risk_state.adj.get(x, ())) + (len(staged_edges.get(x, ())) if staged_edges else 0)
        for x in n1
    )

    if cost_s <= cost_n1:
        for s in sanctioned:
            if _has_active_edge_to_target_set(risk_state, s, n1, win_start, ts, staged_edges):
                return 3
    else:
        for x in n1:
            if _has_active_edge_to_target_set(risk_state, x, sanctioned, win_start, ts, staged_edges):
                return 3
    return 0


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
    *,
    runtime: GatewayRuntime | None = None,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    rt = runtime or get_runtime(db_path)
    with rt.risk_lock(tenant_id):
        risk_state = rt.get_risk_state(tenant_id)
        if not risk_state.sanctions_loaded:
            with rt.connection() as conn:
                risk_state.load_sanctions(conn, tenant_id)
        if not risk_state.sanctioned_set:
            return 0
        if account_id in risk_state.sanctioned_set or counterparty_id in risk_state.sanctioned_set:
            return 1
        if not risk_state.graph_loaded:
            with rt.connection() as conn:
                risk_state.load_graph(conn, tenant_id)
        return compute_sanction_contagion_hop_fast(
            risk_state, account_id, counterparty_id, int(ts)
        )


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单（仅更新制裁纪元）。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent or len(ent) > 128:
        raise ValueError("Valid entity_id is required")
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")

    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0
    src_val = str(list_source or "CUSTOM").strip() or "CUSTOM"
    rt = runtime or get_runtime(db_path)

    with rt.risk_lock(caller.tenant_id):
        risk_state = rt.get_risk_state(caller.tenant_id)
        with rt.write_tx() as conn:
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, ent, src_val, act_val, now_ts),
            )
        if risk_state.sanctions_loaded:
            if active:
                risk_state.sanctioned_set.add(ent)
            else:
                risk_state.sanctioned_set.discard(ent)
        risk_state.sanction_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
