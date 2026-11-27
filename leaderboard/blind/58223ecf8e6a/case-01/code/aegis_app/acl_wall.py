# -*- coding: utf-8 -*-
"""三级 Chinese Wall 裁决；ACL 纪元与文档索引完全解耦。"""
from __future__ import annotations

import time
from typing import Any, Iterable

from .db import open_connection
from .runtime import RUNTIME, db_key
from .security import bounded_text


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    key = (db_key(db_path), tenant_id, start_node_id)
    epoch = RUNTIME.epoch(db_path, tenant_id, "auth")
    cached = RUNTIME.org_lineage.get(key, epoch)
    if cached is not None:
        return list(cached)
    lineage: list[str] = []
    current = start_node_id
    visited: set[str] = set()
    conn = open_connection(db_path)
    try:
        while current and current not in visited and len(lineage) < 64:
            visited.add(current)
            lineage.append(current)
            row = conn.execute(
                "SELECT parent_node_id FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                (tenant_id, current),
            ).fetchone()
            current = str(row["parent_node_id"]) if row and row["parent_node_id"] else ""
    finally:
        conn.close()
    RUNTIME.org_lineage.put(key, epoch, tuple(lineage))
    return lineage


def _tenant_acl_rows(db_path: str, tenant_id: str) -> tuple[tuple[str, str, str, str], ...]:
    key = (db_key(db_path), tenant_id, "acl")
    epoch = RUNTIME.epoch(db_path, tenant_id, "acl")
    cached = RUNTIME.acl_rules.get(key, epoch)
    if cached is not None:
        return cached
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND active = 1 ORDER BY rule_id ASC LIMIT 50000",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()
    result = tuple(
        (str(row["doc_id"]), str(row["subject_type"]), str(row["subject_id"]), str(row["effect"]).upper())
        for row in rows
    )
    RUNTIME.acl_rules.put(key, epoch, result)
    return result


def acl_rows_by_doc(db_path: str, tenant_id: str) -> dict[str, tuple[tuple[str, str, str, str], ...]]:
    grouped: dict[str, list[tuple[str, str, str, str]]] = {}
    for doc_id, subject_type, subject_id, effect in _tenant_acl_rows(db_path, tenant_id):
        grouped.setdefault(doc_id, []).append((doc_id, subject_type, subject_id, effect))
    return {doc_id: tuple(rows) for doc_id, rows in grouped.items()}


def decide_wall(
    *,
    user_id: str,
    lineage: Iterable[str],
    acl_rows: Iterable[tuple[str, str, str, str]],
) -> bool:
    """USER ALLOW > USER DENY > 最近组织节点（同节点 DENY 优先）> 默认放行。"""
    rows = tuple(acl_rows)
    if not rows:
        return False
    user_effects = {
        row[3] for row in rows if row[1] == "USER" and row[2] == user_id
    }
    if "ALLOW" in user_effects:
        return False
    if "DENY" in user_effects:
        return True
    org_effects: dict[str, set[str]] = {}
    for row in rows:
        if row[1] == "ORG_NODE":
            org_effects.setdefault(row[2], set()).add(row[3])
    for node_id in lineage:
        effects = org_effects.get(node_id)
        if effects:
            if "DENY" in effects:
                return True
            if "ALLOW" in effects:
                return False
    return False


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    conn = open_connection(db_path)
    try:
        user = conn.execute(
            "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        ).fetchone()
    finally:
        conn.close()
    if not user:
        return True
    rows = [row for row in _tenant_acl_rows(db_path, tenant_id) if row[0] == doc_id]
    return decide_wall(
        user_id=user_id,
        lineage=get_org_lineage(db_path, tenant_id, str(user["org_node_id"])),
        acl_rows=rows,
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
    norm_type = bounded_text(subject_type, "subject_type", max_length=16).upper()
    norm_effect = bounded_text(effect or "DENY", "effect", max_length=8).upper()
    subject_id = bounded_text(subject_id, "subject_id", max_length=128)
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")
    now_ts = int(time.time())
    with RUNTIME.tenant_write(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            doc = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            ).fetchone()
            if not doc:
                raise LookupError("Document not found in tenant")
            table = "users" if norm_type == "USER" else "org_nodes"
            id_col = "user_id" if norm_type == "USER" else "node_id"
            subject = conn.execute(
                f"SELECT {id_col} FROM {table} WHERE tenant_id = ? AND {id_col} = ?",
                (tenant_id, subject_id),
            ).fetchone()
            if not subject:
                raise LookupError("ACL subject not found in tenant")
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
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        RUNTIME.bump(db_path, tenant_id, "acl")
    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
