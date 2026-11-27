# -*- coding: utf-8 -*-
"""文档 Upsert/Retire：SQLite 与单篇增量索引在租户写临界区内同步提交。"""
from __future__ import annotations

from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .db import open_connection
from .doc_indexer import get_tenant_doc_index
from .runtime import RUNTIME
from .security import bounded_text, strict_int


def _require_editor_clearance(caller: CallerContext, clearance: int) -> None:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("SENIOR_AUDITOR or COMPLIANCE_ADMIN role required to write documents")
    if clearance > caller.max_clearance:
        raise PermissionError("Cannot create or modify document above caller clearance level")


def upsert_compliance_document(
    db_path: str,
    caller: CallerContext,
    payload: dict[str, Any],
) -> dict[str, Any]:
    doc_id = bounded_text(payload.get("doc_id"), "doc_id", max_length=128)
    category = bounded_text(payload.get("category") or "AML", "category", max_length=32).upper()
    regulation_code = bounded_text(payload.get("regulation_code") or "", "regulation_code", max_length=64, allow_empty=True)
    clearance = strict_int(payload.get("clearance_level", 2), "clearance_level", minimum=1, maximum=4)
    risk_weight = strict_int(payload.get("risk_weight", 10), "risk_weight", minimum=0, maximum=200)
    custom_tag = bounded_text(payload.get("custom_tag") or "tag_default", "custom_tag", max_length=128)
    title = bounded_text(payload.get("title"), "title", max_length=4096)
    body = bounded_text(payload.get("body"), "body", max_length=1_048_576)
    updated_at = strict_int(payload.get("updated_at", caller.request_ts), "updated_at")
    raw_citations = payload.get("citations", [])
    if raw_citations is None:
        raw_citations = []
    if not isinstance(raw_citations, list) or len(raw_citations) > 128:
        raise ValueError("citations must be a list with at most 128 entries")
    citations = [bounded_text(ref, "citation", max_length=256, allow_empty=True) for ref in raw_citations]
    if clearance not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    _require_editor_clearance(caller, clearance)

    index = get_tenant_doc_index(db_path, caller.tenant_id)
    with index.lock:
        index.ensure_loaded()
        with RUNTIME.tenant_write(db_path, caller.tenant_id):
            conn = open_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT tenant_id, clearance_level, quarantined FROM compliance_docs WHERE doc_id = ?",
                    (doc_id,),
                ).fetchone()
                if existing and existing["tenant_id"] != caller.tenant_id:
                    raise PermissionError("Document ID belongs to another tenant")
                if existing and int(existing["clearance_level"]) > caller.max_clearance:
                    raise PermissionError("Existing document exceeds caller clearance")
                quarantined = int(existing["quarantined"]) if existing else 0
                values = (
                    doc_id, caller.tenant_id, category, regulation_code, clearance, risk_weight,
                    custom_tag, title, body, "ACTIVE", quarantined, updated_at,
                )
                if existing:
                    conn.execute(
                        "UPDATE compliance_docs SET category = ?, regulation_code = ?, clearance_level = ?, "
                        "risk_weight = ?, custom_tag = ?, title = ?, body = ?, status = 'ACTIVE', "
                        "quarantined = ?, updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                        (category, regulation_code, clearance, risk_weight, custom_tag, title, body,
                         quarantined, updated_at, caller.tenant_id, doc_id),
                    )
                    mode = "updated"
                else:
                    conn.execute(
                        "INSERT INTO compliance_docs(doc_id, tenant_id, category, regulation_code, clearance_level, "
                        "risk_weight, custom_tag, title, body, status, quarantined, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", values,
                    )
                    mode = "created"
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, reference, updated_at) for reference in citations],
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            row = {
                "doc_id": doc_id, "category": category, "regulation_code": regulation_code,
                "clearance_level": clearance, "risk_weight": risk_weight, "custom_tag": custom_tag,
                "title": title, "body": body, "status": "ACTIVE", "quarantined": quarantined,
                "updated_at": updated_at,
            }
            index.upsert(row, citations)
    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "operation": mode,
        "updated_at": updated_at,
    }


def retire_compliance_document(db_path: str, caller: CallerContext, doc_id: str) -> dict[str, Any]:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    doc_id = bounded_text(doc_id, "doc_id", max_length=128)
    now_ts = caller.request_ts
    index = get_tenant_doc_index(db_path, caller.tenant_id)
    with index.lock:
        index.ensure_loaded()
        with RUNTIME.tenant_write(db_path, caller.tenant_id):
            conn = open_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ?",
                    (now_ts, caller.tenant_id, doc_id),
                )
                if cursor.rowcount == 0:
                    raise LookupError("Document not found in tenant")
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            index.set_state(doc_id, status="RETIRED", updated_at=now_ts)
    return {"tenant_id": caller.tenant_id, "doc_id": doc_id, "status": "RETIRED", "updated_at": now_ts}
