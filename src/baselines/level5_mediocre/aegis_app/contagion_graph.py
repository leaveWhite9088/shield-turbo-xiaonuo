# -*- coding: utf-8 -*-
"""三跳制裁传染图追踪（5级平庸样本：每笔交易仍独立拉取窗口全量边重建邻接表并执行列表 BFS）。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import open_connection


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    conn = open_connection(db_path)
    try:
        s_rows = conn.execute(
            "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        sanctioned = {r["entity_id"] for r in s_rows}
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1

        win_start = ts - SLIDING_WINDOW_SECONDS
        tx_rows = conn.execute(
            "SELECT account_id, counterparty_id FROM transactions WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
            (tenant_id, win_start, ts),
        ).fetchall()
    finally:
        conn.close()

    adj: dict[str, list[str]] = {}
    for r in tx_rows:
        u = r["account_id"]
        v = r["counterparty_id"]
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)

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


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent:
        raise ValueError("entity_id is required")
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

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
