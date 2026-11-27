# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、单篇增量索引更新（Upsert）与退役归档（Retire）服务。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .doc_store import get_or_load_doc_index
from .state import get_gateway_state
from .validation import parse_strict_int

MAX_CITATIONS_PER_UPSERT = 200
MAX_CITATION_REF_LEN = 128


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
    """实时新增或修订本租户下的合规文档，并增量更新倒排索引与双向引用图。"""
    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    clearance_level = parse_strict_int(
        payload.get("clearance_level", 2) if payload.get("clearance_level") is not None else 2,
        "clearance_level",
    )
    risk_weight = parse_strict_int(
        payload.get("risk_weight", 10) if payload.get("risk_weight") is not None else 10,
        "risk_weight",
        min_val=0,
        max_val=200,
    )
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    raw_upd = payload.get("updated_at")
    updated_at = (
        parse_strict_int(raw_upd, "updated_at", min_val=1)
        if raw_upd is not None
        else int(caller.request_ts or int(time.time()))
    )
    citations = payload.get("citations") or []

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if not isinstance(citations, list):
        raise ValueError("citations must be a list")
    if len(citations) > MAX_CITATIONS_PER_UPSERT:
        raise ValueError(f"citations exceeds maximum budget ({MAX_CITATIONS_PER_UPSERT})")

    cleaned_citations: list[str] = []
    for c_ref in citations:
        s_ref = str(c_ref or "").strip()
        if len(s_ref) > MAX_CITATION_REF_LEN:
            raise ValueError("citation reference exceeds maximum length")
        if s_ref:
            cleaned_citations.append(s_ref)

    _require_editor_clearance(caller, clearance_level)

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    with t_state.doc_lock:
        idx = get_or_load_doc_index(gw_state, t_state)
        with gw_state.pool.borrow() as conn:
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

            if cleaned_citations:
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, s_ref, updated_at) for s_ref in cleaned_citations],
                )
            conn.commit()

        idx.apply_upsert(
            doc_id=doc_id,
            category=category,
            regulation_code=regulation_code,
            clearance_level=clearance_level,
            risk_weight=risk_weight,
            custom_tag=custom_tag,
            title=title,
            body=body,
            quarantined=keep_q,
            updated_at=updated_at,
            new_citations=cleaned_citations,
        )
        t_state.doc_epoch += 1

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
    """将指定合规文档置为 RETIRED 退役状态，并增量更新倒排索引与被引用方分值。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    now_ts = int(caller.request_ts or int(time.time()))

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    with t_state.doc_lock:
        idx = get_or_load_doc_index(gw_state, t_state)
        with gw_state.pool.borrow() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, doc_id),
            )
            if cur.rowcount == 0:
                conn.rollback()
                raise LookupError(f"Document not found in tenant: {doc_id}")
            conn.commit()

        idx.apply_status_change(doc_id, status="RETIRED", updated_at=now_ts)
        t_state.doc_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
