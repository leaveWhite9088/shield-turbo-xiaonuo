# -*- coding: utf-8 -*-
"""高性能三跳制裁传染图引擎：纪元缓存黑名单集合 + 从制裁源出发的两层有界多源前沿扩展。"""
from __future__ import annotations

import threading
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    normalize_db_key,
    register_cache_reset_hook,
)

_SANC_LOCK = threading.Lock()
# (db_key, tenant_id) -> (sanction_epoch, frozenset[entity_id])
_SANCTION_SET_CACHE: dict[tuple[str, str], tuple[int, frozenset[str]]] = {}


def _clear_sanction_cache(db_key: str) -> None:
    with _SANC_LOCK:
        for k in [k for k in _SANCTION_SET_CACHE if k[0] == db_key]:
            _SANCTION_SET_CACHE.pop(k, None)


register_cache_reset_hook(_clear_sanction_cache)


def get_active_sanctioned_entities(db_path: str, tenant_id: str) -> frozenset[str]:
    db_key = normalize_db_key(db_path)
    eps = get_tenant_epochs(db_path, tenant_id)
    tk = (db_key, tenant_id)
    with _SANC_LOCK:
        cached = _SANCTION_SET_CACHE.get(tk)
        if cached is not None and cached[0] == eps.sanction:
            return cached[1]

    conn = get_thread_connection(db_path)
    rows = conn.execute(
        "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
        (tenant_id,),
    ).fetchall()
    entities = frozenset(str(r["entity_id"]) for r in rows)

    with _SANC_LOCK:
        live_eps = get_tenant_epochs(db_path, tenant_id)
        if live_eps.sanction == eps.sanction:
            _SANCTION_SET_CACHE[tk] = (eps.sanction, entities)
    return entities


def eval_3hop_from_window_adj(
    sanctioned: frozenset[str],
    adj_by_node: dict[str, list[tuple[int, str]]],
    account_id: str,
    counterparty_id: str,
    win_start: int,
    ts: int,
) -> int:
    """利用带时间戳的邻接边表，从黑名单源集合执行最多两层精确前沿扩展，O(deg(S)) 判定 1..3 跳传染。"""
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    layer1: set[str] = set()
    for src in sanctioned:
        edges = adj_by_node.get(src)
        if not edges:
            continue
        for e_ts, nb in edges:
            if win_start <= e_ts <= ts and nb not in sanctioned:
                if nb == account_id or nb == counterparty_id:
                    return 2
                layer1.add(nb)

    if not layer1:
        return 0

    for u in layer1:
        edges = adj_by_node.get(u)
        if not edges:
            continue
        for e_ts, nb in edges:
            if win_start <= e_ts <= ts:
                if nb == account_id or nb == counterparty_id:
                    return 3

    return 0


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    sanctioned = get_active_sanctioned_entities(db_path, tenant_id)
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    win_start = ts - SLIDING_WINDOW_SECONDS
    conn = get_thread_connection(db_path)
    rows = conn.execute(
        "SELECT ts, account_id, counterparty_id FROM transactions "
        "WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
        (tenant_id, win_start, ts),
    ).fetchall()

    adj: dict[str, list[tuple[int, str]]] = {}
    for r in rows:
        r_ts = int(r[0])
        u = str(r[1])
        v = str(r[2])
        adj.setdefault(u, []).append((r_ts, v))
        adj.setdefault(v, []).append((r_ts, u))

    return eval_3hop_from_window_adj(sanctioned, adj, account_id, counterparty_id, win_start, ts)


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
    src = str(list_source or "CUSTOM").strip()
    if not ent or len(ent) > 128 or len(src) > 64:
        raise ValueError("Invalid entity_id or list_source")

    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0
    lock = get_striped_lock(db_path, caller.tenant_id, "sanction")
    with lock:
        conn = get_thread_connection(db_path)
        conn.execute(
            "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
            "active = excluded.active, updated_at = excluded.updated_at",
            (caller.tenant_id, ent, src, act_val, now_ts),
        )
        conn.commit()
        bump_tenant_epoch(db_path, caller.tenant_id, "sanction")

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": src,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
