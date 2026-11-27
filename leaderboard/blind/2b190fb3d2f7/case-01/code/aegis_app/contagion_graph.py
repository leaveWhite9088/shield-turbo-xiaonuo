# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（增量内存邻接图 + 反向 2 跳 BFS）与名单管理模块。"""
from __future__ import annotations

from collections import deque
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import borrow_connection, write_transaction
from .runtime_state import get_runtime


def get_active_sanctions(db_path: str, tenant_id: str) -> frozenset[str]:
    tstate = get_runtime(db_path).get_tenant(tenant_id)
    cached = tstate.sanctions_cache
    if cached is not None and tstate.sanctions_cache_epoch == tstate.sanction_epoch:
        return cached
    with tstate.meta_lock:
        if tstate.sanctions_cache is not None and tstate.sanctions_cache_epoch == tstate.sanction_epoch:
            return tstate.sanctions_cache
        target_epoch = tstate.sanction_epoch
        with borrow_connection(db_path) as conn:
            rows = conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
        s_set = frozenset(str(r["entity_id"]) for r in rows)
        tstate.sanctions_cache = s_set
        tstate.sanctions_cache_epoch = target_epoch
        return s_set


def _reverse_bfs_2hop(
    adj: dict[str, dict[str, int]] | dict[str, set[str]],
    sanctioned: frozenset[str],
    account_id: str,
    counterparty_id: str,
) -> int:
    """从 {account_id, counterparty_id} 反向执行深度 2 广度优先搜索，计算到受制裁集合 S 的最短传染跳数。"""
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    frontier1: set[str] = set()
    for start in (account_id, counterparty_id):
        nbrs = adj.get(start)
        if not nbrs:
            continue
        for nxt in nbrs:
            if nxt in sanctioned:
                return 2
            if nxt != account_id and nxt != counterparty_id:
                frontier1.add(nxt)

    for mid in frontier1:
        nbrs = adj.get(mid)
        if not nbrs:
            continue
        for nxt in nbrs:
            if nxt in sanctioned:
                return 3

    return 0


class TenantContagionGraph:
    """单租户 24 小时增量资金关联无向图（单调窗口 O(1) 均摊淘汰 + 反向 2 跳 BFS）。"""

    __slots__ = ("edges", "adj", "max_ts")

    def __init__(self) -> None:
        self.edges: deque[tuple[int, str, str]] = deque()
        self.adj: dict[str, dict[str, int]] = {}
        self.max_ts: int = -1

    def _inc_edge(self, u: str, v: str) -> None:
        nu = self.adj.get(u)
        if nu is None:
            self.adj[u] = {v: 1}
        else:
            nu[v] = nu.get(v, 0) + 1
        nv = self.adj.get(v)
        if nv is None:
            self.adj[v] = {u: 1}
        else:
            nv[u] = nv.get(u, 0) + 1

    def _dec_edge(self, u: str, v: str) -> None:
        nu = self.adj.get(u)
        if nu is not None:
            c = nu.get(v, 0)
            if c <= 1:
                nu.pop(v, None)
                if not nu:
                    self.adj.pop(u, None)
            else:
                nu[v] = c - 1
        nv = self.adj.get(v)
        if nv is not None:
            c = nv.get(u, 0)
            if c <= 1:
                nv.pop(u, None)
                if not nv:
                    self.adj.pop(v, None)
            else:
                nv[u] = c - 1

    def prune_for_ts(self, ts: int) -> None:
        win_start = ts - SLIDING_WINDOW_SECONDS
        edges = self.edges
        while edges and edges[0][0] < win_start:
            _, u, v = edges.popleft()
            self._dec_edge(u, v)

    def add_edge_monotonic(self, ts: int, u: str, v: str) -> None:
        self.prune_for_ts(ts)
        self.edges.append((ts, u, v))
        self._inc_edge(u, v)
        if ts > self.max_ts:
            self.max_ts = ts

    def insert_edge_out_of_order(self, ts: int, u: str, v: str) -> None:
        if self.max_ts < 0:
            self.add_edge_monotonic(ts, u, v)
            return
        if ts < self.max_ts - SLIDING_WINDOW_SECONDS:
            return
        lst = list(self.edges)
        lst.append((ts, u, v))
        lst.sort(key=lambda x: x[0])
        self.edges = deque(lst)
        self._inc_edge(u, v)

    def compute_hop_monotonic(
        self,
        sanctioned: frozenset[str],
        account_id: str,
        counterparty_id: str,
        ts: int,
    ) -> int:
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1
        self.prune_for_ts(ts)
        return _reverse_bfs_2hop(self.adj, sanctioned, account_id, counterparty_id)


def compute_hop_out_of_order(
    conn: sqlite3.Connection,
    tenant_id: str,
    sanctioned: frozenset[str],
    account_id: str,
    counterparty_id: str,
    ts: int,
    staged_edges: list[tuple[int, str, str]],
) -> int:
    """乱序时间戳精确回退路径：利用 (tenant_id, ts) 复合索引查询 [ts-86400, ts] 活跃边并执行反向 2 跳 BFS。"""
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1
    win_start = ts - SLIDING_WINDOW_SECONDS
    rows = conn.execute(
        "SELECT account_id, counterparty_id FROM transactions "
        "WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
        (tenant_id, win_start, ts),
    ).fetchall()
    adj: dict[str, set[str]] = {}
    for r in rows:
        u = str(r["account_id"])
        v = str(r["counterparty_id"])
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)
    for e_ts, u, v in staged_edges:
        if win_start <= e_ts <= ts:
            adj.setdefault(u, set()).add(v)
            adj.setdefault(v, set()).add(u)
    return _reverse_bfs_2hop(adj, sanctioned, account_id, counterparty_id)


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    sanctioned = get_active_sanctions(db_path, tenant_id)
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1
    with borrow_connection(db_path) as conn:
        return compute_hop_out_of_order(conn, tenant_id, sanctioned, account_id, counterparty_id, ts, [])


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
        raise ValueError("entity_id is required")
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0
    src_str = str(list_source or "CUSTOM").strip()[:64]

    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.meta_lock:
        with write_transaction(db_path) as conn:
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, ent, src_str, act_val, now_ts),
            )
        tstate.sanction_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": src_str,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
