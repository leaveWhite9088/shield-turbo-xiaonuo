# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎（独立 ACL 纪元缓存版）。

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

from .state import GatewayState, get_gateway_state


class _TenantAclCache:
    __slots__ = ("epoch", "org_parents", "rules_by_doc")

    def __init__(self, epoch: int, org_parents: dict[str, str | None], rules_by_doc: dict[str, list[tuple[str, str, str]]]) -> None:
        self.epoch = epoch
        self.org_parents = org_parents
        self.rules_by_doc = rules_by_doc


def _get_acl_cache(gw_state: GatewayState, tenant_id: str) -> _TenantAclCache:
    t_state = gw_state.tenant(tenant_id)
    cache = t_state.acl_cache
    if cache is not None and cache.epoch == t_state.acl_epoch:
        return cache
    with t_state.acl_lock:
        cache = t_state.acl_cache
        if cache is not None and cache.epoch == t_state.acl_epoch:
            return cache
        epoch = t_state.acl_epoch
        with gw_state.pool.borrow() as conn:
            org_rows = conn.execute(
                "SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            acl_rows = conn.execute(
                "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
                "WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
        org_parents = {r["node_id"]: r["parent_node_id"] for r in org_rows}
        rules_by_doc: dict[str, list[tuple[str, str, str]]] = {}
        for r in acl_rows:
            rules_by_doc.setdefault(r["doc_id"], []).append(
                (r["subject_type"], r["subject_id"], str(r["effect"]).upper())
            )
        cache = _TenantAclCache(epoch, org_parents, rules_by_doc)
        t_state.acl_cache = cache
        return cache


def get_org_lineage_from_map(org_parents: dict[str, str | None], start_node_id: str) -> list[str]:
    lineage: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        curr = org_parents.get(curr)
    return lineage


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    gw_state = get_gateway_state(db_path)
    cache = _get_acl_cache(gw_state, tenant_id)
    return get_org_lineage_from_map(cache.org_parents, start_node_id)


def evaluate_wall_rules(
    rules: list[tuple[str, str, str]] | None,
    user_id: str,
    lineage: list[str],
) -> bool:
    if not rules:
        return False
    user_allow = False
    user_deny = False
    org_effects_by_node: dict[str, set[str]] = {}
    for stype, sid, eff in rules:
        if stype == "USER" and sid == user_id:
            if eff == "ALLOW":
                user_allow = True
            elif eff == "DENY":
                user_deny = True
        elif stype == "ORG_NODE":
            org_effects_by_node.setdefault(sid, set()).add(eff)

    if user_allow:
        return False
    if user_deny:
        return True

    for node_id in lineage:
        effs = org_effects_by_node.get(node_id)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False
    return False


def is_doc_blocked_by_wall(
    db_path: str,
    tenant_id: str,
    user_id: str,
    doc_id: str,
    *,
    org_node_id: str | None = None,
) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    gw_state = get_gateway_state(db_path)
    cache = _get_acl_cache(gw_state, tenant_id)
    rules = cache.rules_by_doc.get(doc_id)
    if not rules:
        return False

    if org_node_id is None:
        with gw_state.pool.borrow() as conn:
            u_row = conn.execute(
                "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
                (tenant_id, user_id),
            ).fetchone()
            if not u_row:
                return True
            org_node_id = u_row["org_node_id"]

    lineage = get_org_lineage_from_map(cache.org_parents, org_node_id)
    return evaluate_wall_rules(rules, user_id, lineage)


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
    """配置或停用文档利益冲突隔离墙规则（仅递增 acl_epoch，不污染文档倒排索引）。"""
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(tenant_id)
    with t_state.acl_lock:
        with gw_state.pool.borrow() as conn:
            conn.execute("BEGIN IMMEDIATE")
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            ).fetchone()
            if not doc_row:
                conn.rollback()
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
        t_state.acl_epoch += 1

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
