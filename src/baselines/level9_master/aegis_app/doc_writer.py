# -*- coding: utf-8 -*-
"""高性能合规文档流式写入服务：原子事务校验 + 联动内存倒排表执行 O(L) 单篇增量差量同步。"""
from __future__ import annotations

import re
import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS, MAX_DOC_BODY_CHARS
from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_thread_connection,
    require_strict_int,
)
from .search_service import sync_single_doc_in_index

SAFE_DOC_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _require_editor_clearance(caller: CallerContext, doc_clearance: int) -> None:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("SENIOR_AUDITOR or COMPLIANCE_ADMIN role required to write documents")
    if doc_clearance > caller.max_clearance:
        raise PermissionError("Cannot create or modify document above caller clearance level")


def upsert_compliance_document(
    db_path: str,
    caller: CallerContext,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Document payload must be an object")

    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    raw_cl = payload.get("clearance_level", 2)
    raw_rw = payload.get("risk_weight", 10)
    clearance_level = require_strict_int(raw_cl, "clearance_level", min_val=1, max_val=4)
    risk_weight = require_strict_int(raw_rw, "risk_weight", min_val=0, max_val=200)

    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()

    raw_upd = payload.get("updated_at")
    if raw_upd is not None:
        updated_at = require_strict_int(raw_upd, "updated_at", min_val=1, max_val=9_999_999_999)
    else:
        updated_at = int(caller.request_ts or int(time.time()))

    citations = payload.get("citations") if payload.get("citations") is not None else []
    if not isinstance(citations, list) or len(citations) > 50:
        raise ValueError("citations must be a list of at most 50 items")

    if not doc_id or not SAFE_DOC_ID_RE.match(doc_id):
        raise ValueError("Invalid doc_id format")
    if not title or len(title) > 512 or not body or len(body) > MAX_DOC_BODY_CHARS:
        raise ValueError("Invalid title or body length")
    if len(category) > 64 or len(regulation_code) > 64 or not SAFE_TAG_RE.match(custom_tag):
        raise ValueError("Invalid category, regulation_code, or custom_tag")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")

    _require_editor_clearance(caller, clearance_level)

    lock = get_striped_lock(db_path, caller.tenant_id, "doc_write")
    with lock:
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            existing = conn.execute(
                "SELECT tenant_id, clearance_level, quarantined FROM compliance_docs WHERE doc_id = ?",
                (doc_id,),
            ).fetchone()
            if existing:
                if existing["tenant_id"] != caller.tenant_id:
                    conn.rollback()
                    raise PermissionError("Document ID belongs to another tenant")
                if int(existing["clearance_level"]) > caller.max_clearance:
                    conn.rollback()
                    raise PermissionError("Existing document exceeds caller clearance")
                keep_q = int(existing["quarantined"])
                conn.execute(
                    "UPDATE compliance_docs SET category = ?, regulation_code = ?, clearance_level = ?, "
                    "risk_weight = ?, custom_tag = ?, title = ?, body = ?, status = 'ACTIVE', quarantined = ?, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ?",
                    (
                        category,
                        regulation_code,
                        clearance_level,
                        risk_weight,
                        custom_tag,
                        title,
                        body,
                        keep_q,
                        updated_at,
                        caller.tenant_id,
                        doc_id,
                    ),
                )
                mode = "updated"
            else:
                conn.execute(
                    "INSERT INTO compliance_docs("
                    "doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
                    "custom_tag, title, body, status, quarantined, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?)",
                    (
                        doc_id,
                        caller.tenant_id,
                        category,
                        regulation_code,
                        clearance_level,
                        risk_weight,
                        custom_tag,
                        title,
                        body,
                        updated_at,
                    ),
                )
                mode = "created"

            if citations:
                cite_rows = []
                for c_ref in citations:
                    c_str = str(c_ref).strip()
                    if len(c_str) > 128:
                        raise ValueError("Citation reference too long")
                    cite_rows.append((caller.tenant_id, doc_id, c_str, updated_at))
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    cite_rows,
                )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

        new_ep = bump_tenant_epoch(db_path, caller.tenant_id, "doc")
        sync_single_doc_in_index(db_path, caller.tenant_id, doc_id, new_ep)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "operation": mode,
        "updated_at": updated_at,
    }


def retire_compliance_document(
    db_path: str,
    caller: CallerContext,
    doc_id: str,
) -> dict[str, Any]:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    if not isinstance(doc_id, str) or not SAFE_DOC_ID_RE.match(doc_id):
        raise ValueError("Invalid doc_id")

    now_ts = int(caller.request_ts or int(time.time()))
    lock = get_striped_lock(db_path, caller.tenant_id, "doc_write")
    with lock:
        conn = get_thread_connection(db_path)
        cur = conn.execute(
            "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
            (now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            if conn.in_transaction:
                conn.rollback()
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
        new_ep = bump_tenant_epoch(db_path, caller.tenant_id, "doc")
        sync_single_doc_in_index(db_path, caller.tenant_id, doc_id, new_ep)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
