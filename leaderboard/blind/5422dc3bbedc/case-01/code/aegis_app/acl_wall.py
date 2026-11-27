# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎。

裁决优先级规则（从高到低）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。

性能契约：规则表按 acl 纪元缓存（与文档倒排索引纪元完全解耦——修改单条 doc-acl
规则绝不触发索引重建），组织树静态缓存，裁决为纯内存 O(lineage) 运算。
"""
from __future__ import annotations

import time
from typing import Any

from .db import open_connection
from .index_cache import TenantState, get_state


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链（带环路防护）。"""
    state = get_state(db_path)
    tree = state.tenant(tenant_id).org_tree(db_path)
    lineage: list[str] = []
    curr = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        node = tree.get(curr)
        curr = node[0] if node else None
    return lineage


def evaluate_doc_wall_cached(
    db_path: str,
    wall_rules: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]],
    tstate: TenantState,
    user_id: str,
    user_org_node: str,
    doc_id: str,
) -> bool:
    """基于预取规则与组织树的纯内存三级裁决（输出与原版逐位一致）。"""
    user_map, org_map = wall_rules.get(doc_id, ({}, {}))

    user_effects = user_map.get(user_id)
    if user_effects:
        if "ALLOW" in user_effects:
            return False
        if "DENY" in user_effects:
            return True

    curr = user_org_node
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        effs = org_map.get(curr)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False
        node = tstate.org_tree(db_path).get(curr)
        curr = node[0] if node else None
    return False


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    user_row = tstate.users(db_path).get(user_id)
    if not user_row or not user_row["active"]:
        return True

    wall_rules = tstate.wall_rules(db_path)
    return evaluate_doc_wall_cached(
        db_path, wall_rules, tstate, user_id, user_row["org_node_id"], doc_id
    )


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
    subject_id = str(subject_id or "").strip()
    if not subject_id or len(subject_id) > 128:
        raise ValueError("subject_id must be a non-empty identifier")

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

    # 仅递增 acl 纪元——文档倒排索引与其他纪元缓存不受任何影响
    get_state(db_path).tenant(tenant_id).bump_acl()

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
