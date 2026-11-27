# -*- coding: utf-8 -*-
"""企业合规文档单篇增量写入、引用联动与退役服务。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .db import open_connection
from .doc_indexer import get_document_index
from .runtime import bounded_text, strict_int


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
    doc_id = bounded_text(payload.get("doc_id") or "", "doc_id", 128)
    category = bounded_text(payload.get("category") or "AML", "category", 64).upper()
    regulation_code = bounded_text(payload.get("regulation_code") or "", "regulation_code", 128, allow_empty=True)
    raw_clearance = payload.get("clearance_level", 2)
    clearance_level = strict_int(2 if raw_clearance in (None, "") else raw_clearance, "clearance_level")
    raw_risk = payload.get("risk_weight", 10)
    risk_weight = strict_int(10 if raw_risk in (None, "") else raw_risk, "risk_weight")
    custom_tag = bounded_text(payload.get("custom_tag") or "tag_default", "custom_tag", 128)
    title = bounded_text(payload.get("title") or "", "title", 4096)
    body = bounded_text(payload.get("body") or "", "body", 524_288)
    raw_updated = payload.get("updated_at", caller.request_ts or int(time.time()))
    updated_at = strict_int(raw_updated or caller.request_ts, "updated_at", minimum=0)
    citations = payload.get("citations") or []
    if not isinstance(citations, list) or len(citations) > 512:
        raise ValueError("citations must be a list of at most 512 references")
    clean_citations = [bounded_text(ref, "citation", 256) for ref in citations]

    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if risk_weight < 0 or risk_weight > 200:
        raise ValueError("risk_weight must be between 0 and 200")
    _require_editor_clearance(caller, clearance_level)

    index = get_document_index(db_path, caller.tenant_id)
    with index.lock:
        index.ensure_loaded()
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT tenant_id, clearance_level, quarantined FROM compliance_docs WHERE doc_id = ?",
                (doc_id,),
            ).fetchone()
            if existing:
                if existing["tenant_id"] != caller.tenant_id:
                    raise PermissionError("Document is not accessible in this tenant")
                if int(existing["clearance_level"]) > caller.max_clearance:
                    raise PermissionError("Existing document exceeds caller clearance")
                keep_q = int(existing["quarantined"])
                conn.execute(
                    "UPDATE compliance_docs SET category = ?, regulation_code = ?, clearance_level = ?, "
                    "risk_weight = ?, custom_tag = ?, title = ?, body = ?, status = 'ACTIVE', quarantined = ?, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ?",
                    (category, regulation_code, clearance_level, risk_weight, custom_tag, title, body,
                     keep_q, updated_at, caller.tenant_id, doc_id),
                )
                mode = "updated"
            else:
                keep_q = 0
                conn.execute(
                    "INSERT INTO compliance_docs(doc_id, tenant_id, category, regulation_code, clearance_level, "
                    "risk_weight, custom_tag, title, body, status, quarantined, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?)",
                    (doc_id, caller.tenant_id, category, regulation_code, clearance_level, risk_weight,
                     custom_tag, title, body, updated_at),
                )
                mode = "created"
            if clean_citations:
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, ref, updated_at) for ref in clean_citations],
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        index_row = {
            "doc_id": doc_id, "category": category, "regulation_code": regulation_code,
            "clearance_level": clearance_level, "risk_weight": risk_weight,
            "custom_tag": custom_tag, "title": title, "body": body,
            "status": "ACTIVE", "quarantined": keep_q, "updated_at": updated_at,
        }
        index.apply_upsert(index_row, clean_citations)

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
    doc_id = bounded_text(doc_id, "doc_id", 128)
    now_ts = int(caller.request_ts or int(time.time()))
    index = get_document_index(db_path, caller.tenant_id)
    with index.lock:
        index.ensure_loaded()
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError("Document not found")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        index.apply_state(doc_id, status="RETIRED", updated_at=now_ts)
    return {"tenant_id": caller.tenant_id, "doc_id": doc_id, "status": "RETIRED", "updated_at": now_ts}
