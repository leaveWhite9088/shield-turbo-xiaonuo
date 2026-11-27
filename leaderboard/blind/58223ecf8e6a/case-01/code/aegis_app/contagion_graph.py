# -*- coding: utf-8 -*-
"""时间窗增量资金图与多源 BFS 三跳制裁传染追踪。"""
from __future__ import annotations

from collections import Counter, deque
import time
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import open_connection
from .runtime import RUNTIME
from .security import bounded_text, strict_bool


class TemporalContagionGraph:
    """边计数支持重复交易和精确过期；同一批次乱序时由上层整体重建。"""

    __slots__ = ("tenant_id", "sanctioned", "records", "adjacency")

    def __init__(self, tenant_id: str, sanctioned: Iterable[str]) -> None:
        self.tenant_id = tenant_id
        self.sanctioned = frozenset(sanctioned)
        self.records: deque[tuple[int, str, str]] = deque()
        self.adjacency: dict[str, Counter[str]] = {}

    def _link(self, left: str, right: str) -> None:
        self.adjacency.setdefault(left, Counter())[right] += 1
        self.adjacency.setdefault(right, Counter())[left] += 1

    def _unlink(self, left: str, right: str) -> None:
        for node, other in ((left, right), (right, left)):
            neighbors = self.adjacency.get(node)
            if not neighbors:
                continue
            neighbors[other] -= 1
            if neighbors[other] <= 0:
                del neighbors[other]
            if not neighbors:
                self.adjacency.pop(node, None)

    def add(self, record: Any) -> None:
        ts, left, right = int(record["ts"]), str(record["account_id"]), str(record["counterparty_id"])
        self.records.append((ts, left, right))
        self._link(left, right)

    def expire(self, start_ts: int) -> None:
        while self.records and self.records[0][0] < start_ts:
            _, left, right = self.records.popleft()
            self._unlink(left, right)

    def hop_for(self, account_id: str, counterparty_id: str) -> int:
        if not self.sanctioned:
            return 0
        if account_id in self.sanctioned or counterparty_id in self.sanctioned:
            return 1
        # 当前交易自身边按原契约临时加入，计算后精确撤销，不污染下一笔。
        self._link(account_id, counterparty_id)
        try:
            distances: dict[str, int] = {}
            queue: deque[str] = deque()
            for source in self.sanctioned:
                if source in self.adjacency:
                    distances[source] = 0
                    queue.append(source)
            while queue:
                current = queue.popleft()
                distance = distances[current]
                if distance >= 2:
                    continue
                for neighbor in self.adjacency.get(current, ()):
                    if neighbor in distances:
                        continue
                    next_distance = distance + 1
                    if neighbor == account_id or neighbor == counterparty_id:
                        hop = next_distance + 1
                        return hop if 1 <= hop <= 3 else 0
                    distances[neighbor] = next_distance
                    queue.append(neighbor)
            return 0
        finally:
            self._unlink(account_id, counterparty_id)


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    conn = open_connection(db_path)
    try:
        sanctioned_rows = conn.execute(
            "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        rows = conn.execute(
            "SELECT account_id, counterparty_id, ts FROM transactions "
            "WHERE tenant_id = ? AND ts >= ? AND ts <= ? ORDER BY ts ASC, tx_id ASC",
            (tenant_id, ts - SLIDING_WINDOW_SECONDS, ts),
        ).fetchall()
    finally:
        conn.close()
    graph = TemporalContagionGraph(tenant_id, (row["entity_id"] for row in sanctioned_rows))
    for row in rows:
        graph.add(row)
    return graph.hop_for(account_id, counterparty_id)


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    require_admin(caller)
    entity = bounded_text(entity_id, "entity_id", max_length=128)
    source = bounded_text(list_source or "CUSTOM", "list_source", max_length=64)
    active_value = strict_bool(active, "active")
    now_ts = caller.request_ts or int(time.time())
    with RUNTIME.tenant_write(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(tenant_id, entity_id) DO UPDATE SET "
                "list_source = excluded.list_source, active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, entity, source, int(active_value), now_ts),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    return {
        "tenant_id": caller.tenant_id,
        "entity_id": entity,
        "list_source": source,
        "active": active_value,
        "updated_at": now_ts,
    }
