# -*- coding: utf-8 -*-
"""时间过滤的局部双端 BFS 三跳传染图与实时黑名单管理。"""
from __future__ import annotations

from collections import deque
import time
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import open_connection
from .runtime import bounded_text, tenant_write_lock


class TemporalContagionGraph:
    """一次建边，多笔复用；查询只访问端点两跳邻域而非逐制裁源扫全图。"""

    def __init__(self, rows: Iterable[Any]) -> None:
        self.adjacency: dict[str, list[tuple[int, str]]] = {}
        for row in rows:
            ts = int(row["ts"])
            account = str(row["account_id"])
            counterparty = str(row["counterparty_id"])
            self.adjacency.setdefault(account, []).append((ts, counterparty))
            self.adjacency.setdefault(counterparty, []).append((ts, account))

    def add_edge(self, account: str, counterparty: str, ts: int) -> None:
        self.adjacency.setdefault(account, []).append((ts, counterparty))
        self.adjacency.setdefault(counterparty, []).append((ts, account))

    def hop(self, account: str, counterparty: str, ts: int, sanctioned: set[str]) -> int:
        if not sanctioned:
            return 0
        if account in sanctioned or counterparty in sanctioned:
            return 1
        window_start = ts - SLIDING_WINDOW_SECONDS
        queue: deque[tuple[str, int]] = deque([(account, 0), (counterparty, 0)])
        visited = {account: 0, counterparty: 0}
        while queue:
            current, distance = queue.popleft()
            if distance >= 2:
                continue
            for edge_ts, neighbor in self.adjacency.get(current, ()):
                if not window_start <= edge_ts <= ts:
                    continue
                next_distance = distance + 1
                if next_distance < visited.get(neighbor, 99):
                    if neighbor in sanctioned:
                        return min(3, next_distance + 1)
                    visited[neighbor] = next_distance
                    queue.append((neighbor, next_distance))
        return 0


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    conn = open_connection(db_path)
    try:
        sanctioned = {
            str(row["entity_id"]) for row in conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            )
        }
        rows = conn.execute(
            "SELECT account_id, counterparty_id, ts FROM transactions WHERE tenant_id = ? AND ts BETWEEN ? AND ?",
            (tenant_id, ts - SLIDING_WINDOW_SECONDS, ts),
        ).fetchall()
    finally:
        conn.close()
    return TemporalContagionGraph(rows).hop(account, counterparty, ts, sanctioned)


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    require_admin(caller)
    entity_id = bounded_text(entity_id, "entity_id", 256)
    list_source = bounded_text(list_source or "CUSTOM", "list_source", 64)
    if not isinstance(active, bool):
        raise ValueError("active must be boolean")
    now_ts = int(caller.request_ts or int(time.time()))
    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, entity_id, list_source, int(active), now_ts),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    return {
        "tenant_id": caller.tenant_id, "entity_id": entity_id,
        "list_source": list_source, "active": active, "updated_at": now_ts,
    }
