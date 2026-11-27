# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎（独立 acl_epoch 驱动，与文档倒排索引完全解耦）。

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

from .db import (
    bump_acl_epoch,
    get_tenant_acl_lock,
    get_tenant_epochs,
    normalize_db_key,
    open_connection,
    register_reset_callback,
)
from .delegation import get_tenant_auth_snapshot
from .middleware import strict_bool


class _TenantAclSnapshot:
    """租户利益冲突隔离墙内存快照（由 acl_epoch 独立驱动，绝不触发文档倒排索引重建）。"""

    __slots__ = ("acl_epoch", "auth_epoch", "doc_rules", "verdict_cache")

    def __init__(self, acl_epoch: int, auth_epoch: int) -> None:
        self.acl_epoch = acl_epoch
        self.auth_epoch = auth_epoch
        # doc_id -> (user_id -> set[effect], org_node_id -> set[effect])
        self.doc_rules: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]] = {}
        self.verdict_cache: dict[tuple[str, str], bool] = {}


_MAX_ACL_SNAPSHOTS = 256
_MAX_VERDICT_CACHE_PER_TENANT = 4096
_ACL_SNAPSHOTS: dict[tuple[str, str], _TenantAclSnapshot] = {}


def _reset_acl_snapshots(db_key: str) -> None:
    for k in [k for k in _ACL_SNAPSHOTS if k[0] == db_key]:
        _ACL_SNAPSHOTS.pop(k, None)


register_reset_callback(_reset_acl_snapshots)


def _load_tenant_acl_snapshot(
    db_path: str,
    tenant_id: str,
    acl_epoch: int,
    auth_epoch: int,
) -> _TenantAclSnapshot:
    snap = _TenantAclSnapshot(acl_epoch, auth_epoch)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT doc_id, subject_type, subject_id, effect "
            "FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    for r in rows:
        did = str(r["doc_id"])
        stype = str(r["subject_type"]).upper()
        sid = str(r["subject_id"])
        eff = str(r["effect"]).upper()
        entry = snap.doc_rules.get(did)
        if entry is None:
            entry = ({}, {})
            snap.doc_rules[did] = entry
        if stype == "USER":
            entry[0].setdefault(sid, set()).add(eff)
        elif stype == "ORG_NODE":
            entry[1].setdefault(sid, set()).add(eff)
    return snap


def _get_tenant_acl_snapshot(db_path: str, tenant_id: str) -> _TenantAclSnapshot:
    db_key = normalize_db_key(db_path)
    epochs = get_tenant_epochs(db_path, tenant_id)
    cur_acl_ep = epochs.acl_epoch
    cur_auth_ep = epochs.auth_epoch
    cache_key = (db_key, tenant_id)
    snap = _ACL_SNAPSHOTS.get(cache_key)
    if snap is not None and snap.acl_epoch == cur_acl_ep:
        if snap.auth_epoch != cur_auth_ep:
            with get_tenant_acl_lock(db_path, tenant_id):
                if snap.auth_epoch != cur_auth_ep:
                    snap.auth_epoch = cur_auth_ep
                    snap.verdict_cache.clear()
        return snap

    with get_tenant_acl_lock(db_path, tenant_id):
        epochs = get_tenant_epochs(db_path, tenant_id)
        cur_acl_ep = epochs.acl_epoch
        cur_auth_ep = epochs.auth_epoch
        snap = _ACL_SNAPSHOTS.get(cache_key)
        if snap is not None and snap.acl_epoch == cur_acl_ep:
            if snap.auth_epoch != cur_auth_ep:
                snap.auth_epoch = cur_auth_ep
                snap.verdict_cache.clear()
            return snap
        snap = _load_tenant_acl_snapshot(db_path, tenant_id, cur_acl_ep, cur_auth_ep)
        if len(_ACL_SNAPSHOTS) >= _MAX_ACL_SNAPSHOTS and cache_key not in _ACL_SNAPSHOTS:
            _ACL_SNAPSHOTS.pop(next(iter(_ACL_SNAPSHOTS)), None)
        _ACL_SNAPSHOTS[cache_key] = snap
        return snap


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    auth_snap = get_tenant_auth_snapshot(db_path, tenant_id)
    if start_node_id in auth_snap.org_lineage:
        return list(auth_snap.org_lineage[start_node_id])
    lineage: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        info = auth_snap.org_nodes.get(curr)
        curr = info[0] if info else None
    return lineage


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    auth_snap = get_tenant_auth_snapshot(db_path, tenant_id)
    u_entry = auth_snap.users.get(user_id)
    if u_entry is None or not u_entry.active:
        return True

    acl_snap = _get_tenant_acl_snapshot(db_path, tenant_id)
    rules = acl_snap.doc_rules.get(doc_id)
    if not rules:
        return False

    v_key = (user_id, doc_id)
    cached = acl_snap.verdict_cache.get(v_key)
    if cached is not None:
        return cached

    user_rules, org_rules = rules
    user_effects = user_rules.get(user_id)
    verdict = False
    if user_effects:
        if "ALLOW" in user_effects:
            verdict = False
        elif "DENY" in user_effects:
            verdict = True
    else:
        lineage = auth_snap.org_lineage.get(u_entry.org_node_id, ())
        for node_id in lineage:
            effs = org_rules.get(node_id)
            if effs:
                if "DENY" in effs:
                    verdict = True
                    break
                if "ALLOW" in effs:
                    verdict = False
                    break

    if len(acl_snap.verdict_cache) >= _MAX_VERDICT_CACHE_PER_TENANT and v_key not in acl_snap.verdict_cache:
        acl_snap.verdict_cache.pop(next(iter(acl_snap.verdict_cache)), None)
    acl_snap.verdict_cache[v_key] = verdict
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
    """配置或停用文档利益冲突隔离墙规则（仅递增 acl_epoch，绝不清空或重建文档倒排索引）。"""
    norm_doc_id = str(doc_id or "").strip()
    norm_subject_id = str(subject_id or "").strip()
    norm_type = str(subject_type or "").strip().upper()
    norm_effect = str(effect or "DENY").strip().upper()
    is_active = strict_bool(active, "active")

    if not norm_doc_id or not norm_subject_id:
        raise ValueError("doc_id and subject_id are required")
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    with get_tenant_acl_lock(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, norm_doc_id),
            ).fetchone()
            if not doc_row:
                raise LookupError(f"Document not found in tenant: {norm_doc_id}")

            if is_active:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, norm_doc_id, norm_type, norm_subject_id, norm_effect, now_ts),
                )
            else:
                conn.execute(
                    "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                    (now_ts, tenant_id, norm_doc_id, norm_type, norm_subject_id, norm_effect),
                )
            conn.commit()
        finally:
            conn.close()
        bump_acl_epoch(db_path, tenant_id)

    return {
        "tenant_id": tenant_id,
        "doc_id": norm_doc_id,
        "subject_type": norm_type,
        "subject_id": norm_subject_id,
        "effect": norm_effect,
        "active": bool(is_active),
    }
