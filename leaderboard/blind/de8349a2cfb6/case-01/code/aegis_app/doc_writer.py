# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import (
    CLEARANCE_LEVELS,
    MAX_CITATIONS_PER_DOC,
    MAX_DOC_BODY_CHARS,
    parse_strict_int,
)
from .db import bump_domain_epoch, open_connection
from .doc_indexer import get_tenant_doc_index


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
    """实时新增或修订本租户下的合规文档，并同步登记可选引用记录（增量更新内存索引）。"""
    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    clearance_level = parse_strict_int(payload.get("clearance_level", 2), "clearance_level", min_val=1, max_val=4)
    risk_weight = parse_strict_int(payload.get("risk_weight", 10), "risk_weight", min_val=0, max_val=200)
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    raw_updated = payload.get("updated_at")
    if raw_updated is not None:
        updated_at = parse_strict_int(raw_updated, "updated_at", min_val=1)
    else:
        updated_at = int(caller.request_ts or int(time.time()))
    citations = payload.get("citations") or []

    if not doc_id or len(doc_id) > 128 or not title or len(title) > 512 or not body:
        raise ValueError("doc_id, title, and body are required")
    if len(body) > MAX_DOC_BODY_CHARS:
        raise ValueError("Document body exceeds maximum allowed size")
    if len(category) > 64 or len(regulation_code) > 64 or len(custom_tag) > 128:
        raise ValueError("Document metadata field too long")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if not isinstance(citations, list) or len(citations) > MAX_CITATIONS_PER_DOC:
        raise ValueError(f"citations must be a list with at most {MAX_CITATIONS_PER_DOC} items")

    clean_citations: list[str] = []
    for c_ref in citations:
        if not isinstance(c_ref, str):
            raise ValueError("citation reference must be a string")
        s_ref = c_ref.strip()
        if len(s_ref) > 128:
            raise ValueError("citation reference exceeds maximum length")
        if s_ref:
            clean_citations.append(s_ref)

    _require_editor_clearance(caller, clearance_level)

    # 先确保内存索引已初始化，避免在事务中途首次建索引
    doc_index = get_tenant_doc_index(db_path, caller.tenant_id)

    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
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

        if clean_citations:
            conn.executemany(
                "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                [(caller.tenant_id, doc_id, s_ref, updated_at) for s_ref in clean_citations],
            )
        conn.commit()
    finally:
        conn.close()

    doc_index.apply_upsert(
        doc_id=doc_id,
        category=category,
        regulation_code=regulation_code,
        clearance_level=clearance_level,
        risk_weight=risk_weight,
        custom_tag=custom_tag,
        title=title,
        body=body,
        status="ACTIVE",
        quarantined=keep_q,
        updated_at=updated_at,
        added_citations=clean_citations,
    )
    bump_domain_epoch(db_path, caller.tenant_id, "doc")

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
    """将指定合规文档置为 RETIRED 退役状态，不再参与常规在线检索（增量传播内部引用计数）。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    if not doc_id:
        raise ValueError("doc_id is required")
    now_ts = int(caller.request_ts or int(time.time()))
    doc_index = get_tenant_doc_index(db_path, caller.tenant_id)
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
            (now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            conn.rollback()
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
    finally:
        conn.close()

    doc_index.apply_status_change(doc_id, status="RETIRED", updated_at=now_ts)
    bump_domain_epoch(db_path, caller.tenant_id, "doc")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
