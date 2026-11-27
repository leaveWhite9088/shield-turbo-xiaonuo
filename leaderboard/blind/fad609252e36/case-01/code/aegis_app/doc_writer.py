# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（单篇增量索引更新与反向引用传播）及退役归档服务。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS, MAX_CITATION_REF_LEN, MAX_DOC_CITATIONS
from .db import bump_doc_epoch, get_tenant_doc_lock, open_connection
from .doc_indexer import get_loaded_tenant_doc_index
from .middleware import strict_int


def _require_editor_clearance(caller: CallerContext, doc_clearance: int) -> None:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("SENIOR_AUDITOR or COMPLIANCE_ADMIN role required to write documents")
    if doc_clearance > caller.max_clearance:
        raise PermissionError("Cannot create or modify document above caller clearance level")


def _validate_citations(citations: Any) -> list[str]:
    if citations is None:
        return []
    if not isinstance(citations, list):
        raise ValueError("citations must be a list of strings")
    if len(citations) > MAX_DOC_CITATIONS:
        raise ValueError(f"citations count exceeds maximum limit ({MAX_DOC_CITATIONS})")
    cleaned: list[str] = []
    for item in citations:
        if not isinstance(item, str):
            raise ValueError("Each citation reference must be a string")
        ref = item.strip()
        if not ref or len(ref) > MAX_CITATION_REF_LEN:
            raise ValueError("Invalid citation reference length")
        cleaned.append(ref)
    return cleaned


def upsert_compliance_document(
    db_path: str,
    caller: CallerContext,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """实时新增或修订本租户下的合规文档，并在内存中执行单篇增量倒排与双向引用联动更新。"""
    if not isinstance(payload, dict):
        raise ValueError("Document payload must be an object")

    raw_doc_id = payload.get("doc_id")
    raw_title = payload.get("title")
    raw_body = payload.get("body")
    if not isinstance(raw_doc_id, str) or not isinstance(raw_title, str) or not isinstance(raw_body, str):
        raise ValueError("doc_id, title, and body must be strings")

    doc_id = raw_doc_id.strip()
    title = raw_title.strip()
    body = raw_body.strip()
    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if len(doc_id) > 128 or len(title) > 512 or len(body) > 200000:
        raise ValueError("Document field length exceeds safety budget")

    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    if len(category) > 64 or len(regulation_code) > 64 or len(custom_tag) > 64:
        raise ValueError("Metadata field length exceeds limit")

    if "clearance_level" in payload and payload["clearance_level"] is not None:
        clearance_level = strict_int(payload["clearance_level"], "clearance_level", min_val=1, max_val=4)
    else:
        clearance_level = 2

    if "risk_weight" in payload and payload["risk_weight"] is not None:
        risk_weight = strict_int(payload["risk_weight"], "risk_weight", min_val=0, max_val=200)
    else:
        risk_weight = 10

    if "updated_at" in payload and payload["updated_at"] is not None:
        updated_at = strict_int(payload["updated_at"], "updated_at", min_val=1)
    else:
        updated_at = int(caller.request_ts or int(time.time()))

    citations = _validate_citations(payload.get("citations"))

    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")

    _require_editor_clearance(caller, clearance_level)

    with get_tenant_doc_lock(db_path, caller.tenant_id):
        idx = get_loaded_tenant_doc_index(db_path, caller.tenant_id)
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT tenant_id, clearance_level, quarantined FROM compliance_docs WHERE doc_id = ?",
                (doc_id,),
            ).fetchone()
            if existing:
                if existing["tenant_id"] != caller.tenant_id:
                    raise PermissionError("Document ID belongs to another tenant")
                if int(existing["clearance_level"]) > caller.max_clearance:
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
                keep_q = 0
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
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, c_ref, updated_at) for c_ref in citations],
                )
            conn.commit()
        finally:
            conn.close()

        new_epoch = bump_doc_epoch(db_path, caller.tenant_id)
        if idx is not None:
            idx.upsert_single_doc(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                body=body,
                status="ACTIVE",
                quarantined=bool(keep_q),
                updated_at=updated_at,
                new_citations=citations,
                new_epoch=new_epoch,
            )

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
    """将指定合规文档置为 RETIRED 退役状态，并沿 reverse_dependents 增量剥离被引用计数。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    clean_id = str(doc_id or "").strip()
    if not clean_id:
        raise ValueError("doc_id is required")

    now_ts = int(caller.request_ts or int(time.time()))
    with get_tenant_doc_lock(db_path, caller.tenant_id):
        idx = get_loaded_tenant_doc_index(db_path, caller.tenant_id)
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, clean_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {clean_id}")
            conn.commit()
        finally:
            conn.close()

        new_epoch = bump_doc_epoch(db_path, caller.tenant_id)
        if idx is not None:
            idx.update_doc_state(
                clean_id,
                status="RETIRED",
                updated_at=now_ts,
                new_epoch=new_epoch,
            )

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": clean_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
