# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎。

裁决优先级规则（从高到低）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。

性能重构（裁决语义 100% 零失真）：
- 用户档案与组织树走静态纪元缓存（内存图上溯，带 visited 环路免疫）；
- 每条 (tenant, user, doc) 裁决结论按 acl 纪元缓存，upsert_doc_acl_rule
  提交后立即 bump 纪元，热路径检索重复裁决全部命中内存；
- 单次裁决仅一条数据库连接、至多一条参数化规则查询。
"""
from __future__ import annotations

import time
from typing import Any

from .db import open_connection
from .epoch_cache import CACHE_MISS, EpochScopedCache, bump_epoch, epoch_token, load_tenant_static

_verdict_cache = EpochScopedCache("acl_wall_verdicts", 8192)


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    if not start_node_id:
        return []
    org_map = load_tenant_static(db_path, tenant_id)["org"]
    lineage: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        node = org_map.get(curr)
        curr = node[0] if node else None
    return lineage


def _resolve_org_verdict(
    org_map: dict[str, tuple[str | None, str]],
    org_node_id: str | None,
    acl_rows: list[Any],
) -> bool:
    """沿组织链由近及远采用最近一个有规则节点的裁决（同节点 DENY 优先）。"""
    org_effects_by_node: dict[str, set[str]] = {}
    for r in acl_rows:
        if r["subject_type"] == "ORG_NODE":
            org_effects_by_node.setdefault(str(r["subject_id"]), set()).add(str(r["effect"]).upper())

    curr = org_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        effs = org_effects_by_node.get(curr)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False
        node = org_map.get(curr)
        curr = node[0] if node else None
    return False


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    db_key = str(db_path)
    token = epoch_token(db_path, "acl", "org", "users")
    key = (tenant_id, user_id, doc_id)
    hit = _verdict_cache.get(db_key, token, key)
    if hit is not CACHE_MISS:
        return hit

    static = load_tenant_static(db_path, tenant_id)
    u_info = static["users"].get(user_id)
    if not u_info or u_info[0] != 1:
        _verdict_cache.put(db_key, token, key, True)
        return True

    conn = open_connection(db_path)
    try:
        acl_rows = conn.execute(
            "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
            (tenant_id, doc_id),
        ).fetchall()
    finally:
        conn.close()

    if not acl_rows:
        verdict = False
    else:
        user_effects = {
            str(r["effect"]).upper()
            for r in acl_rows
            if r["subject_type"] == "USER" and r["subject_id"] == user_id
        }
        if "ALLOW" in user_effects:
            verdict = False
        elif "DENY" in user_effects:
            verdict = True
        else:
            verdict = _resolve_org_verdict(static["org"], u_info[1], acl_rows)

    _verdict_cache.put(db_key, token, key, verdict)
    return verdict


def upsert_doc_acl_rule(
    db_path: str,
    tenant_id: str,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
) -> dict[str, Any]:
    """配置或停用文档利益冲突隔离墙规则（支持 USER / ORG_NODE 与 DENY / ALLOW）。"""
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    conn = open_connection(db_path)
    try:
        doc_row = conn.execute(
            "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchone()
        if not doc_row:
            raise LookupError(f"Document not found in tenant: {doc_id}")

        if active:
            conn.execute(
                "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?)",
                (tenant_id, doc_id, norm_type, subject_id, norm_effect, now_ts),
            )
        else:
            conn.execute(
                "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                (now_ts, tenant_id, doc_id, norm_type, subject_id, norm_effect),
            )
        conn.commit()
    finally:
        conn.close()

    bump_epoch(db_path, "acl")

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
