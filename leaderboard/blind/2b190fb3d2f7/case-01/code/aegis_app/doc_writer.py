# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务（增量索引同步）。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .db import write_transaction
from .runtime_state import get_runtime, parse_strict_int

_MAX_DOC_ID_LEN = 128
_MAX_TITLE_LEN = 500
_MAX_BODY_LEN = 100_000
_MAX_CITATIONS_PER_UPSERT = 100
_MAX_CITATION_REF_LEN = 128


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
    """实时新增或修订本租户下的合规文档，并增量同步倒排索引与双向引用传播图。"""
    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    raw_cl = payload.get("clearance_level", 2)
    clearance_level = parse_strict_int(
        2 if raw_cl is None else raw_cl,
        field_name="clearance_level",
        min_val=1,
        max_val=4,
    )
    raw_rw = payload.get("risk_weight", 10)
    risk_weight = parse_strict_int(
        10 if raw_rw is None else raw_rw,
        field_name="risk_weight",
        min_val=0,
        max_val=200,
    )
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()

    raw_upd = payload.get("updated_at")
    if raw_upd is None:
        updated_at = int(caller.request_ts or int(time.time()))
    else:
        updated_at = parse_strict_int(raw_upd, field_name="updated_at", min_val=0)

    raw_citations = payload.get("citations")
    cleaned_citations: list[str] = []
    if raw_citations is not None:
        if not isinstance(raw_citations, list):
            raise ValueError("citations must be a list")
        if len(raw_citations) > _MAX_CITATIONS_PER_UPSERT:
            raise ValueError(f"citations exceeds maximum allowed count ({_MAX_CITATIONS_PER_UPSERT})")
        for c_ref in raw_citations:
            if not isinstance(c_ref, str):
                raise ValueError("Each citation reference must be a string")
            s_ref = c_ref.strip()
            if len(s_ref) > _MAX_CITATION_REF_LEN:
                raise ValueError("Citation reference exceeds maximum length")
            if s_ref:
                cleaned_citations.append(s_ref)

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if len(doc_id) > _MAX_DOC_ID_LEN or len(title) > _MAX_TITLE_LEN or len(body) > _MAX_BODY_LEN:
        raise ValueError("Document field length exceeds maximum allowed limit")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")

    _require_editor_clearance(caller, clearance_level)

    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.doc_lock:
        with write_transaction(db_path) as conn:
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

            if cleaned_citations:
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, ref, updated_at) for ref in cleaned_citations],
                )

        tstate.doc_epoch += 1
        if tstate.doc_index is not None:
            tstate.doc_index.apply_upsert(
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
                new_citations=cleaned_citations,
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
    """将指定合规文档置为 RETIRED 退役状态，并增量更新倒排索引与引用计数。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    did = str(doc_id or "").strip()
    if not did:
        raise ValueError("doc_id is required")
    now_ts = int(caller.request_ts or int(time.time()))

    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.doc_lock:
        with write_transaction(db_path) as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, did),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {did}")

        tstate.doc_epoch += 1
        if tstate.doc_index is not None:
            tstate.doc_index.apply_retire(did)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": did,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
