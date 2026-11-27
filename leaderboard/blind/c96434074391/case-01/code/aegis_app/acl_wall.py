# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎与独立纪元缓存。

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

from .db import DatabaseRuntime, get_db_runtime
from .delegation import get_tenant_auth_state
from .middleware import strict_bool


class DocAclEntry:
    """单篇文档的紧凑利益冲突墙规则集合。"""

    __slots__ = ("user_allow", "user_deny", "org_allow", "org_deny")

    def __init__(self) -> None:
        self.user_allow: set[str] = set()
        self.user_deny: set[str] = set()
        self.org_allow: set[str] = set()
        self.org_deny: set[str] = set()

    def is_empty(self) -> bool:
        return not (self.user_allow or self.user_deny or self.org_allow or self.org_deny)


class TenantAclState:
    """与文档倒排索引完全正交解耦的租户隔离墙状态（独立 acl_epoch）。"""

    __slots__ = ("tenant_id", "acl_epoch", "rules_by_doc")

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.acl_epoch = 1
        self.rules_by_doc: dict[str, DocAclEntry] = {}


def _load_tenant_acl_state(rt: DatabaseRuntime, tenant_id: str) -> TenantAclState:
    state = TenantAclState(tenant_id)
    with rt.read_conn() as conn:
        rows = conn.execute(
            "SELECT doc_id, subject_type, subject_id, effect "
            "FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
    for r in rows:
        doc_id = str(r["doc_id"])
        s_type = str(r["subject_type"]).upper()
        s_id = str(r["subject_id"])
        eff = str(r["effect"]).upper()
        entry = state.rules_by_doc.get(doc_id)
        if entry is None:
            entry = DocAclEntry()
            state.rules_by_doc[doc_id] = entry
        if s_type == "USER":
            if eff == "ALLOW":
                entry.user_allow.add(s_id)
            elif eff == "DENY":
                entry.user_deny.add(s_id)
        elif s_type == "ORG_NODE":
            if eff == "ALLOW":
                entry.org_allow.add(s_id)
            elif eff == "DENY":
                entry.org_deny.add(s_id)
    return state


def get_tenant_acl_state(rt: DatabaseRuntime, tenant_id: str) -> TenantAclState:
    cached = rt.acl_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.tenant_meta_lock(tenant_id):
        cached = rt.acl_cache.get(tenant_id)
        if cached is not None:
            return cached
        loaded = _load_tenant_acl_state(rt, tenant_id)
        rt.acl_cache.set(tenant_id, loaded)
        return loaded


def is_doc_blocked_in_memory(
    acl_state: TenantAclState,
    user_id: str,
    org_lineage: tuple[str, ...],
    doc_id: str,
) -> bool:
    """在内存隔离墙快照上执行 O(depth) 三级优先级裁决。"""
    entry = acl_state.rules_by_doc.get(doc_id)
    if entry is None:
        return False
    if user_id in entry.user_allow:
        return False
    if user_id in entry.user_deny:
        return True
    for node_id in org_lineage:
        if node_id in entry.org_deny:
            return True
        if node_id in entry.org_allow:
            return False
    return False


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    rt = get_db_runtime(db_path)
    auth_state = get_tenant_auth_state(rt, tenant_id)
    if auth_state is not None and start_node_id in auth_state.org_lineage:
        return list(auth_state.org_lineage[start_node_id])

    lineage: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    with rt.read_conn() as conn:
        while curr and curr not in visited:
            visited.add(curr)
            lineage.append(curr)
            row = conn.execute(
                "SELECT parent_node_id FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                (tenant_id, curr),
            ).fetchone()
            curr = row["parent_node_id"] if row else None
    return lineage


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    rt = get_db_runtime(db_path)
    auth_state = get_tenant_auth_state(rt, tenant_id)
    if auth_state is None:
        return True
    u_rec = auth_state.users.get(user_id)
    if u_rec is None or not u_rec.active:
        return True
    lineage = auth_state.org_lineage.get(u_rec.org_node_id, (u_rec.org_node_id,))
    acl_state = get_tenant_acl_state(rt, tenant_id)
    return is_doc_blocked_in_memory(acl_state, user_id, lineage, doc_id)


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
    """配置或停用文档利益冲突隔离墙规则（仅局部更新 acl_epoch，绝不清空文档倒排索引）。"""
    act_bool = strict_bool(active, "active")
    norm_doc = str(doc_id or "").strip()
    norm_subj = str(subject_id or "").strip()
    norm_type = str(subject_type or "").strip().upper()
    norm_effect = str(effect or "DENY").strip().upper()

    if not norm_doc or len(norm_doc) > 128 or not norm_subj or len(norm_subj) > 128:
        raise ValueError("Valid doc_id and subject_id are required")
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(tenant_id):
        with rt.write_tx() as conn:
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, norm_doc),
            ).fetchone()
            if not doc_row:
                raise LookupError(f"Document not found in tenant: {norm_doc}")

            if act_bool:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, norm_doc, norm_type, norm_subj, norm_effect, now_ts),
                )
            else:
                conn.execute(
                    "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                    (now_ts, tenant_id, norm_doc, norm_type, norm_subj, norm_effect),
                )

        acl_state = rt.acl_cache.get(tenant_id)
        if acl_state is not None:
            entry = acl_state.rules_by_doc.get(norm_doc)
            if act_bool:
                if entry is None:
                    entry = DocAclEntry()
                    acl_state.rules_by_doc[norm_doc] = entry
                if norm_type == "USER":
                    if norm_effect == "ALLOW":
                        entry.user_allow.add(norm_subj)
                    else:
                        entry.user_deny.add(norm_subj)
                else:
                    if norm_effect == "ALLOW":
                        entry.org_allow.add(norm_subj)
                    else:
                        entry.org_deny.add(norm_subj)
            elif entry is not None:
                if norm_type == "USER":
                    if norm_effect == "ALLOW":
                        entry.user_allow.discard(norm_subj)
                    else:
                        entry.user_deny.discard(norm_subj)
                else:
                    if norm_effect == "ALLOW":
                        entry.org_allow.discard(norm_subj)
                    else:
                        entry.org_deny.discard(norm_subj)
                if entry.is_empty():
                    acl_state.rules_by_doc.pop(norm_doc, None)
            acl_state.acl_epoch += 1

    return {
        "tenant_id": tenant_id,
        "doc_id": norm_doc,
        "subject_type": norm_type,
        "subject_id": norm_subj,
        "effect": norm_effect,
        "active": act_bool,
    }
