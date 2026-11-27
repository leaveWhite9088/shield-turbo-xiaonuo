# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。

增量索引联动：单篇写入只重新分词该文档（O(该文档词数)），
并沿 ``reverse_dependents`` 反向引用图把有效引用计数变化传播给受影响的文档，
绝不因一次写入而重建整租户倒排索引。
"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .db import open_connection, write_transaction
from .tenant_cache import peek_doc_index, refresh_doc_index_signature


def _require_editor_clearance(caller: CallerContext, doc_clearance: int) -> None:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("SENIOR_AUDITOR or COMPLIANCE_ADMIN role required to write documents")
    if doc_clearance > caller.max_clearance:
        raise PermissionError("Cannot create or modify document above caller clearance level")


def _sync_index_after_upsert(
    db_path: str,
    tenant_id: str,
    *,
    doc_id: str,
    category: str,
    regulation_code: str,
    clearance_level: int,
    risk_weight: int,
    custom_tag: str,
    title: str,
    body: str,
    status: str,
    quarantined: bool,
    updated_at: int,
    citations: list[Any],
) -> None:
    index = peek_doc_index(db_path, tenant_id)
    if index is None or not index.usable:
        return
    index.upsert_doc(
        doc_id=doc_id,
        category=category,
        regulation_code=regulation_code,
        clearance_level=clearance_level,
        risk_weight=risk_weight,
        custom_tag=custom_tag,
        title=title,
        body=body,
        status=status,
        quarantined=quarantined,
        updated_at=updated_at,
    )
    if citations:
        index.add_citations(doc_id, [str(c) for c in citations])
    refresh_doc_index_signature(db_path, tenant_id, index)


def upsert_compliance_document(
    db_path: str,
    caller: CallerContext,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """实时新增或修订本租户下的合规文档，并同步登记可选引用记录。"""
    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    clearance_level = int(payload.get("clearance_level") or 2)
    risk_weight = int(payload.get("risk_weight") or 10)
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    updated_at = int(payload.get("updated_at") or caller.request_ts or int(time.time()))
    citations = payload.get("citations") or []

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if len(doc_id) > 128 or len(title) > 512 or len(body) > 2_000_000:
        raise ValueError("Document field length exceeds the allowed limit")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if risk_weight < 0 or risk_weight > 200:
        raise ValueError("risk_weight must be between 0 and 200")
    if isinstance(citations, list) and len(citations) > 500:
        raise ValueError("citations exceeds the maximum count of 500")

    _require_editor_clearance(caller, clearance_level)

    conn = open_connection(db_path)
    try:
        with write_transaction(conn):
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

            if isinstance(citations, list) and citations:
                for c_ref in citations:
                    conn.execute(
                        "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                        (caller.tenant_id, doc_id, str(c_ref), updated_at),
                    )
    finally:
        conn.close()

    _sync_index_after_upsert(
        db_path,
        caller.tenant_id,
        doc_id=doc_id,
        category=category,
        regulation_code=regulation_code,
        clearance_level=clearance_level,
        risk_weight=risk_weight,
        custom_tag=custom_tag,
        title=title,
        body=body,
        status="ACTIVE",
        quarantined=False,
        updated_at=updated_at,
        citations=citations if isinstance(citations, list) else [],
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
    """将指定合规文档置为 RETIRED 退役状态，不再参与常规在线检索。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        with write_transaction(conn):
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {doc_id}")
    finally:
        conn.close()

    # 退役即刻生效：索引状态翻转 + 反向引用图 O(deg) 联动（被引用方引用计数立即失效）。
    from .search_service import _sync_doc_index_status

    _sync_doc_index_status(db_path, caller.tenant_id, doc_id, status="RETIRED")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
