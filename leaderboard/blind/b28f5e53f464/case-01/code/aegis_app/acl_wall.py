# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎（独立 ACL 纪元隔离缓存版）。

裁决优先级规则（从高到低）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。
"""
from __future__ import annotations

import time
from typing import Any

from .runtime import GatewayRuntime, get_runtime


def get_org_lineage(
    db_path: str,
    tenant_id: str,
    start_node_id: str,
    *,
    runtime: GatewayRuntime | None = None,
) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    rt = runtime or get_runtime(db_path)
    perm_state = rt.get_perm_state(tenant_id)
    return perm_state.get_org_lineage(start_node_id)


def is_doc_blocked_by_wall(
    db_path: str,
    tenant_id: str,
    user_id: str,
    doc_id: str,
    *,
    runtime: GatewayRuntime | None = None,
) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    rt = runtime or get_runtime(db_path)
    perm_state = rt.get_perm_state(tenant_id)
    u_info = perm_state.users.get(user_id)
    if not u_info or u_info[3] != 1:
        return True

    acl_state = rt.get_acl_state(tenant_id)
    pair = acl_state.rules_by_doc.get(doc_id)
    if pair is None:
        return False

    user_map, org_map = pair
    user_effects = user_map.get(user_id)
    if user_effects:
        if "ALLOW" in user_effects:
            return False
        if "DENY" in user_effects:
            return True

    if not org_map:
        return False

    org_node_id = u_info[1]
    for node_id in perm_state.get_org_lineage(org_node_id):
        effs = org_map.get(node_id)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False

    return False


def upsert_doc_acl_rule(
    db_path: str,
    tenant_id: str,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """配置或停用文档利益冲突隔离墙规则（仅更新独立 ACL 纪元，绝不清空文档倒排索引）。"""
    clean_doc_id = str(doc_id or "").strip()
    clean_subject_id = str(subject_id or "").strip()
    norm_type = str(subject_type or "").strip().upper()
    norm_effect = str(effect or "DENY").strip().upper()
    if not clean_doc_id or not clean_subject_id:
        raise ValueError("doc_id and subject_id are required")
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    rt = runtime or get_runtime(db_path)
    acl_state = rt.get_acl_state(tenant_id)

    with rt.acl_lock(tenant_id):
        with rt.write_tx() as conn:
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, clean_doc_id),
            ).fetchone()
            if not doc_row:
                raise LookupError(f"Document not found in tenant: {clean_doc_id}")

            if active:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, clean_doc_id, norm_type, clean_subject_id, norm_effect, now_ts),
                )
            else:
                conn.execute(
                    "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                    (now_ts, tenant_id, clean_doc_id, norm_type, clean_subject_id, norm_effect),
                )
        acl_state.apply_rule_change(clean_doc_id, norm_type, clean_subject_id, norm_effect, bool(active))

    return {
        "tenant_id": tenant_id,
        "doc_id": clean_doc_id,
        "subject_type": norm_type,
        "subject_id": clean_subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
