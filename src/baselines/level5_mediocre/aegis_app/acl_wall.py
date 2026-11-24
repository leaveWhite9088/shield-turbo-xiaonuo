# -*- coding: utf-8 -*-
"""三级利益冲突隔离墙（5级平庸样本：逐篇文档重复打开连接回溯组织树，规则更新未清空检索缓存）。"""
from __future__ import annotations

import time
from typing import Any

from .db import open_connection


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    lineage: list[str] = []
    curr = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        conn = open_connection(db_path)
        try:
            row = conn.execute(
                "SELECT parent_node_id FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                (tenant_id, curr),
            ).fetchone()
            curr = row["parent_node_id"] if row else None
        finally:
            conn.close()
    return lineage


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    conn = open_connection(db_path)
    try:
        u_row = conn.execute(
            "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        ).fetchone()
        if not u_row:
            return True

        acl_rows = conn.execute(
            "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
            (tenant_id, doc_id),
        ).fetchall()
    finally:
        conn.close()

    if not acl_rows:
        return False

    user_effects = {
        str(r["effect"]).upper()
        for r in acl_rows
        if r["subject_type"] == "USER" and r["subject_id"] == user_id
    }
    if "ALLOW" in user_effects:
        return False
    if "DENY" in user_effects:
        return True

    lineage = get_org_lineage(db_path, tenant_id, u_row["org_node_id"])
    org_effects_by_node: dict[str, set[str]] = {}
    for r in acl_rows:
        if r["subject_type"] == "ORG_NODE":
            org_effects_by_node.setdefault(r["subject_id"], set()).add(str(r["effect"]).upper())

    for node_id in lineage:
        effs = org_effects_by_node.get(node_id)
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
) -> dict[str, Any]:
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

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
