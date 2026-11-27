# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎（独立 acl_epoch 缓存解耦版）。"""
from __future__ import annotations

import time
from typing import Any

from .db import borrow_connection, get_db_hub, write_transaction
from .delegation import get_perm_snapshot
from .middleware import strict_bool


class DocAclEntry:
    """单篇文档的隔离墙规则紧凑结构（2=DENY，1=ALLOW，同一组织节点 DENY 优先）。"""

    __slots__ = ("user_allow", "user_deny", "org_effects")

    def __init__(
        self,
        user_allow: frozenset[str],
        user_deny: frozenset[str],
        org_effects: dict[str, int],
    ) -> None:
        self.user_allow = user_allow
        self.user_deny = user_deny
        self.org_effects = org_effects


class TenantAclSnapshot:
    """与 acl_epoch 绑定的租户隔离墙内存快照（修改隔离墙绝不触发文档倒排索引重建）。"""

    __slots__ = ("epoch", "by_doc")

    def __init__(self, epoch: int, by_doc: dict[str, DocAclEntry]) -> None:
        self.epoch = epoch
        self.by_doc = by_doc

    def is_blocked(self, user_id: str, org_lineage: tuple[str, ...], doc_id: str) -> bool:
        entry = self.by_doc.get(doc_id)
        if entry is None:
            return False
        if user_id in entry.user_allow:
            return False
        if user_id in entry.user_deny:
            return True
        org_eff = entry.org_effects
        if org_eff:
            for node_id in org_lineage:
                code = org_eff.get(node_id, 0)
                if code != 0:
                    return code == 2
        return False


def get_acl_snapshot(db_path: str, tenant_id: str) -> TenantAclSnapshot:
    hub = get_db_hub(db_path)
    target_ep = hub.get_epochs(tenant_id).acl_epoch
    cached: TenantAclSnapshot | None = hub.acl_snapshots.get(tenant_id)
    if cached is not None and cached.epoch == target_ep:
        return cached

    with hub.tenant_meta_lock(tenant_id):
        target_ep = hub.get_epochs(tenant_id).acl_epoch
        cached = hub.acl_snapshots.get(tenant_id)
        if cached is not None and cached.epoch == target_ep:
            return cached

        with borrow_connection(db_path) as conn:
            rows = conn.execute(
                "SELECT doc_id, subject_type, subject_id, effect "
                "FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()

        raw_doc: dict[str, tuple[set[str], set[str], dict[str, int]]] = {}
        for r in rows:
            did = str(r["doc_id"])
            stype = str(r["subject_type"]).upper()
            sid = str(r["subject_id"])
            eff = str(r["effect"]).upper()
            bucket = raw_doc.get(did)
            if bucket is None:
                bucket = (set(), set(), {})
                raw_doc[did] = bucket
            u_allow, u_deny, org_map = bucket
            if stype == "USER":
                if eff == "ALLOW":
                    u_allow.add(sid)
                elif eff == "DENY":
                    u_deny.add(sid)
            elif stype == "ORG_NODE":
                if eff == "DENY":
                    org_map[sid] = 2
                elif eff == "ALLOW" and org_map.get(sid, 0) != 2:
                    org_map[sid] = 1

        by_doc = {
            did: DocAclEntry(frozenset(ua), frozenset(ud), om)
            for did, (ua, ud, om) in raw_doc.items()
        }
        snap = TenantAclSnapshot(epoch=target_ep, by_doc=by_doc)
        hub.acl_snapshots.set(tenant_id, snap)
        return snap


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    if not start_node_id:
        return []
    perm_snap = get_perm_snapshot(db_path, tenant_id)
    chain = perm_snap.org_lineage.get(start_node_id)
    if chain is not None:
        return list(chain)
    return [start_node_id]


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    perm_snap = get_perm_snapshot(db_path, tenant_id)
    u_rec = perm_snap.users.get(user_id)
    if u_rec is None or not u_rec.active:
        return True
    acl_snap = get_acl_snapshot(db_path, tenant_id)
    lineage = perm_snap.org_lineage.get(u_rec.org_node_id, (u_rec.org_node_id,))
    return acl_snap.is_blocked(user_id, lineage, doc_id)


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
    """配置或停用文档利益冲突隔离墙规则（仅递增 acl_epoch，与 doc_epoch 严格解耦）。"""
    clean_doc_id = str(doc_id or "").strip()
    clean_subject_id = str(subject_id or "").strip()
    norm_type = str(subject_type or "").strip().upper()
    norm_effect = str(effect or "DENY").strip().upper()
    is_active = strict_bool(active, "active")

    if not clean_doc_id or len(clean_doc_id) > 128:
        raise ValueError("Valid doc_id is required")
    if not clean_subject_id or len(clean_subject_id) > 128:
        raise ValueError("Valid subject_id is required")
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    hub = get_db_hub(db_path)
    with hub.tenant_meta_lock(tenant_id):
        with write_transaction(db_path) as conn:
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, clean_doc_id),
            ).fetchone()
            if not doc_row:
                raise LookupError(f"Document not found in tenant: {clean_doc_id}")

            if is_active:
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
        hub.bump_acl_epoch(tenant_id)

    return {
        "tenant_id": tenant_id,
        "doc_id": clean_doc_id,
        "subject_type": norm_type,
        "subject_id": clean_subject_id,
        "effect": norm_effect,
        "active": is_active,
    }
