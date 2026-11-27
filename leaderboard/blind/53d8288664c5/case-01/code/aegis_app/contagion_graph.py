# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph）与名单管理模块。

图连通与传染跳数定义：
- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条双向资金关联边；
- 当前正在评估的交易自身的边 (tx.account_id, tx.counterparty_id) 同步计入当前图；
- 设活跃受制裁实体集合为 S（sanctioned_entities 表中 active=1 的 entity_id）：
  * 若 tx.account_id in S 或 tx.counterparty_id in S（即本次交易两端直接命中制裁名单），则传染跳数 hop = 1；
  * 否则计算 tx.account_id 与 tx.counterparty_id 到集合 S 中任意实体的最短无向边路径长度 d_min：
    传染跳数 hop = d_min + 1；
  * 若 hop > 3 或不可达，记为 0（无三跳内制裁传染）。

性能与安全重构（跳数语义 100% 零失真）：
- 活跃制裁名单按 sanctions 纪元缓存（manage_sanctioned_entity 提交后立即 bump）；
- 边集不再全表扫描后内存过滤，改为 idx_tx_tenant_ts 复合索引上的区间扫描
  [ts - 86400, ts]，复杂度从 O(全租户交易数) 降至 O(log N + 活跃窗口边数)；
- 逐源 BFS 合并为一次多源 BFS：min over src(dist(src, endpoint)) 与
  dist_multi-source(endpoint) 严格等价，同时保留深度 2 截断与 visited 免疫
  自环/重边放大。
"""
from __future__ import annotations

from collections import deque
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import open_connection
from .epoch_cache import CACHE_MISS, EpochScopedCache, bump_epoch, epoch_token

_sanctioned_cache = EpochScopedCache("sanctioned_entities", 256)


def _load_sanctioned_set(db_path: str, tenant_id: str) -> frozenset[str]:
    """按 sanctions 纪元缓存租户当前活跃受制裁实体集合。"""
    db_key = str(db_path)
    token = epoch_token(db_path, "sanctions")
    hit = _sanctioned_cache.get(db_key, token, tenant_id)
    if hit is not CACHE_MISS:
        return hit

    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    sanctioned = frozenset(str(r["entity_id"]) for r in rows)
    _sanctioned_cache.put(db_key, token, tenant_id, sanctioned)
    return sanctioned


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    sanctioned = _load_sanctioned_set(db_path, tenant_id)
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    win_start = ts - SLIDING_WINDOW_SECONDS
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT account_id, counterparty_id FROM transactions "
            "WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
            (tenant_id, win_start, ts),
        ).fetchall()
    finally:
        conn.close()

    adj: dict[str, list[str]] = {}
    for r in rows:
        u = str(r["account_id"])
        v = str(r["counterparty_id"])
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)

    # 当前交易自身的边同步计入图。
    adj.setdefault(account_id, []).append(counterparty_id)
    adj.setdefault(counterparty_id, []).append(account_id)

    # 多源 BFS：从全部活跃受制裁实体同步扩展至深度 2，
    # dist[endpoint] 即为 endpoint 到制裁集合的最短边距离（与逐源 BFS 取最小严格等价）。
    dist: dict[str, int] = {}
    queue: deque[str] = deque()
    for src in sanctioned:
        if src in adj and src not in dist:
            dist[src] = 0
            queue.append(src)

    while queue:
        curr = queue.popleft()
        d = dist[curr]
        if d >= 2:
            continue
        for nxt in adj.get(curr, ()):
            if nxt not in dist:
                dist[nxt] = d + 1
                queue.append(nxt)

    best_hop = 0
    for endpoint in (account_id, counterparty_id):
        if endpoint in dist:
            hop = dist[endpoint] + 1
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
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单。"""
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

    # 名单变更提交后立即提升 sanctions 纪元，传染追踪缓存零脏读地即时生效。
    bump_epoch(db_path, "sanctions")

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
