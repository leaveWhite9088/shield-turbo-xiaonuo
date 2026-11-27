# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎。

裁决优先级规则（从高到低）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。

性能改造：组织树、用户台账与隔离墙规则均以「租户级只读快照 + 双失效条件」
缓存，裁决过程退化为纯内存运算（O(组织层级深度)），不再逐层开库查表。
"""
from __future__ import annotations

import time
from typing import Any

from .db import open_connection, write_transaction
from .state import DOMAIN_ACL
from .tenant_cache import load_acl_rules, load_org_snapshot


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    nodes = load_org_snapshot(db_path, tenant_id)["nodes"]
    lineage: list[str] = []
    visited: set[str] = set()
    curr = start_node_id
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        node = nodes.get(curr)
        curr = node["parent"] if node else None
    return lineage


def is_user_blocked_by_wall_rules(
    org_snapshot: dict[str, Any],
    acl_rules: dict[str, list[tuple[str, str, str]]],
    user_id: str,
    doc_id: str,
) -> bool:
    """纯内存裁决：输入已加载的组织/规则快照，输出是否被隔离墙阻断。

    供检索等批量场景复用，避免逐文档重复触发快照装载与数据库查询。
    """
    user = org_snapshot["users"].get(user_id)
    if not user or not user["active"]:
        return True

    doc_rules = acl_rules.get(doc_id)
    if not doc_rules:
        return False

    user_effects = {
        effect
        for subject_type, subject_id, effect in doc_rules
        if subject_type == "USER" and subject_id == user_id
    }
    if "ALLOW" in user_effects:
        return False
    if "DENY" in user_effects:
        return True

    org_effects_by_node: dict[str, set[str]] = {}
    for subject_type, subject_id, effect in doc_rules:
        if subject_type == "ORG_NODE":
            org_effects_by_node.setdefault(subject_id, set()).add(effect)

    nodes = org_snapshot["nodes"]
    curr = user["org_node_id"]
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        effects = org_effects_by_node.get(curr)
        if effects:
            if "DENY" in effects:
                return True
            if "ALLOW" in effects:
                return False
        node = nodes.get(curr)
        curr = node["parent"] if node else None

    return False


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    return is_user_blocked_by_wall_rules(
        load_org_snapshot(db_path, tenant_id),
        load_acl_rules(db_path, tenant_id),
        user_id,
        doc_id,
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

    now_ts = int(time.time())
    conn = open_connection(db_path)
    try:
        with write_transaction(conn):
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
    finally:
        conn.close()

    # 隔离墙纪元推进：仅失效 acl 域缓存，文档倒排索引不受任何牵连。
    from .state import get_runtime_state

    get_runtime_state(db_path).bump(tenant_id, DOMAIN_ACL)

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
