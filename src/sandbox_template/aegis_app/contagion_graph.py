# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph）与名单管理模块。

图连通与传染跳数定义：
- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条双向资金关联边；
- 当前正在评估的交易自身的边 (tx.account_id, tx.counterparty_id) 同步计入当前图；
- 设活跃受制裁实体集合为 S（sanctioned_entities 表中 active=1 的 entity_id）：
  * 若 tx.account_id in S 或 tx.counterparty_id in S（即本次交易两端直接命中制裁名单），则传染跳数 hop = 1；
  * 否则计算 tx.account_id 与 tx.counterparty_id 到集合 S 中任意实体的最短无向边路径长度 d_min：
    传染跳数 hop = d_min + 1（例如 tx.counterparty_id 曾与受制裁实体直接交易过，即 d_min = 1，则本次交易 hop = 2；
    若隔一层中间跳板账户，d_min = 2，则本次交易 hop = 3）；
  * 若 hop > 3 或不可达，记为 0（无三跳内制裁传染）。
"""
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
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
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
            "SELECT account_id, counterparty_id, ts FROM transactions WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    adj: dict[str, list[str]] = {}
    for r in tx_rows:
        r_ts = int(r["ts"])
        if win_start <= r_ts <= ts:
            u = r["account_id"]
            v = r["counterparty_id"]
            adj.setdefault(u, []).append(v)
            adj.setdefault(v, []).append(u)

    adj.setdefault(account_id, []).append(counterparty_id)
    adj.setdefault(counterparty_id, []).append(account_id)

    # 从每个受制裁源点执行广度优先搜索，计算到达 account_id 或 counterparty_id 的最小边距离
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

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
