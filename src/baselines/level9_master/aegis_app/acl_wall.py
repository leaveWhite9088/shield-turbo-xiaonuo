# -*- coding: utf-8 -*-
"""高性能三级利益冲突隔离墙引擎：独立 ACL 纪元解耦缓存，避免隔离墙更新连带重建文档倒排表。"""
from __future__ import annotations

import threading
import time
from typing import Any

from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    normalize_db_key,
    register_cache_reset_hook,
)

_WALL_CACHE_LOCK = threading.Lock()
# (db_key, tenant_id) -> (acl_epoch, dict[doc_id, list[tuple[subject_type, subject_id, effect]]])
_TENANT_ACL_RULES_CACHE: dict[
    tuple[str, str],
    tuple[int, dict[str, list[tuple[str, str, str]]]],
] = {}
# (db_key, tenant_id, perm_epoch, acl_epoch, user_id) -> frozenset[denied_doc_id]
_USER_DENIED_DOCS_CACHE: dict[tuple[str, str, int, int, str], frozenset[str]] = {}


def _clear_wall_caches(db_key: str) -> None:
    with _WALL_CACHE_LOCK:
        for k in [k for k in _TENANT_ACL_RULES_CACHE if k[0] == db_key]:
            _TENANT_ACL_RULES_CACHE.pop(k, None)
        for k in [k for k in _USER_DENIED_DOCS_CACHE if k[0] == db_key]:
            _USER_DENIED_DOCS_CACHE.pop(k, None)


register_cache_reset_hook(_clear_wall_caches)


def _load_tenant_acl_map(
    db_path: str,
    tenant_id: str,
    acl_epoch: int,
) -> dict[str, list[tuple[str, str, str]]]:
    db_key = normalize_db_key(db_path)
    tk = (db_key, tenant_id)
    with _WALL_CACHE_LOCK:
        cached = _TENANT_ACL_RULES_CACHE.get(tk)
        if cached is not None and cached[0] == acl_epoch:
            return cached[1]

    conn = get_thread_connection(db_path)
    rows = conn.execute(
        "SELECT doc_id, subject_type, subject_id, effect "
        "FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
        (tenant_id,),
    ).fetchall()

    rules_by_doc: dict[str, list[tuple[str, str, str]]] = {}
    for r in rows:
        rules_by_doc.setdefault(str(r["doc_id"]), []).append(
            (str(r["subject_type"]).upper(), str(r["subject_id"]), str(r["effect"]).upper())
        )

    with _WALL_CACHE_LOCK:
        live_eps = get_tenant_epochs(db_path, tenant_id)
        if live_eps.acl == acl_epoch:
            _TENANT_ACL_RULES_CACHE[tk] = (acl_epoch, rules_by_doc)
    return rules_by_doc


def _is_doc_denied_by_rules(
    rules: list[tuple[str, str, str]],
    user_id: str,
    lineage: tuple[str, ...],
) -> bool:
    """严格执行三级优先级：USER ALLOW > USER DENY > 最近祖先 ORG_NODE（同节点 DENY > ALLOW）。"""
    user_allow = False
    user_deny = False
    org_effects: dict[str, set[str]] = {}

    for stype, sid, eff in rules:
        if stype == "USER" and sid == user_id:
            if eff == "ALLOW":
                user_allow = True
            elif eff == "DENY":
                user_deny = True
        elif stype == "ORG_NODE":
            org_effects.setdefault(sid, set()).add(eff)

    if user_allow:
        return False
    if user_deny:
        return True

    for node_id in lineage:
        effs = org_effects.get(node_id)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False
    return False


def get_user_denied_docs(
    db_path: str,
    tenant_id: str,
    user_id: str,
    lineage: tuple[str, ...],
    perm_epoch: int,
    acl_epoch: int,
) -> frozenset[str]:
    """返回该操作员在当前权限纪元与隔离墙纪元下被禁止访问的文档集合。"""
    db_key = normalize_db_key(db_path)
    ck = (db_key, tenant_id, perm_epoch, acl_epoch, user_id)
    with _WALL_CACHE_LOCK:
        cached = _USER_DENIED_DOCS_CACHE.get(ck)
        if cached is not None:
            return cached

    rules_by_doc = _load_tenant_acl_map(db_path, tenant_id, acl_epoch)
    if not rules_by_doc:
        denied = frozenset()
    else:
        denied = frozenset(
            doc_id
            for doc_id, rlist in rules_by_doc.items()
            if _is_doc_denied_by_rules(rlist, user_id, lineage)
        )

    with _WALL_CACHE_LOCK:
        live_eps = get_tenant_epochs(db_path, tenant_id)
        if live_eps.perm == perm_epoch and live_eps.acl == acl_epoch:
            if len(_USER_DENIED_DOCS_CACHE) > 1024:
                _USER_DENIED_DOCS_CACHE.clear()
            _USER_DENIED_DOCS_CACHE[ck] = denied
    return denied


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    conn = get_thread_connection(db_path)
    rows = conn.execute(
        "SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    parent_map = {str(r["node_id"]): r["parent_node_id"] for r in rows}
    lineage: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        curr = parent_map.get(curr)
    return lineage


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    eps = get_tenant_epochs(db_path, tenant_id)
    conn = get_thread_connection(db_path)
    u_row = conn.execute(
        "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
        (tenant_id, user_id),
    ).fetchone()
    if not u_row:
        return True
    lineage = tuple(get_org_lineage(db_path, tenant_id, str(u_row["org_node_id"])))
    denied = get_user_denied_docs(db_path, tenant_id, user_id, lineage, eps.perm, eps.acl)
    return doc_id in denied


def upsert_doc_acl_rule(
    db_path: str,
    tenant_id: str,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
    now_ts: int | None = None,
) -> dict[str, Any]:
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")
    if not doc_id or len(doc_id) > 128 or not subject_id or len(subject_id) > 128:
        raise ValueError("Invalid doc_id or subject_id")

    ts_val = int(now_ts if now_ts is not None else time.time())
    lock = get_striped_lock(db_path, tenant_id, "acl")
    with lock:
        conn = get_thread_connection(db_path)
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
                (tenant_id, doc_id, norm_type, subject_id, norm_effect, ts_val),
            )
        else:
            conn.execute(
                "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                (ts_val, tenant_id, doc_id, norm_type, subject_id, norm_effect),
            )
        conn.commit()
        # 仅递增独立 acl 纪元，完全不触碰租户文档倒排索引
        bump_tenant_epoch(db_path, tenant_id, "acl")

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
