# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、单篇增量修订（Upsert）与退役归档（Retire）服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall
from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .runtime import GatewayRuntime, get_runtime
from .validation import strict_int

MAX_CITATIONS_PER_UPSERT = 256
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
    *,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """实时新增或修订本租户下的合规文档，并执行单篇增量倒排索引与双向引用计数联动。"""
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object")

    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()

    raw_clearance = payload.get("clearance_level")
    clearance_level = strict_int(
        2 if raw_clearance is None else raw_clearance,
        "clearance_level",
        min_val=1,
        max_val=4,
    )
    raw_risk_w = payload.get("risk_weight")
    risk_weight = strict_int(
        10 if raw_risk_w is None else raw_risk_w,
        "risk_weight",
        min_val=0,
        max_val=200,
    )
    raw_updated = payload.get("updated_at")
    updated_at = (
        strict_int(raw_updated, "updated_at", min_val=0)
        if raw_updated is not None
        else int(caller.request_ts or int(time.time()))
    )

    raw_citations = payload.get("citations")
    clean_citations: list[str] = []
    if raw_citations is not None:
        if not isinstance(raw_citations, list):
            raise ValueError("citations must be a list")
        if len(raw_citations) > MAX_CITATIONS_PER_UPSERT:
            raise ValueError("citations count exceeds maximum limit")
        for c_ref in raw_citations:
            if not isinstance(c_ref, str):
                raise ValueError("Each citation reference must be a string")
            c_str = c_ref.strip()
            if len(c_str) > MAX_CITATION_REF_LEN:
                raise ValueError("Citation reference exceeds maximum length")
            if c_str:
                clean_citations.append(c_str)

    if not doc_id or len(doc_id) > 128 or not title or not body:
        raise ValueError("Valid doc_id, title, and body are required")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")

    _require_editor_clearance(caller, clearance_level)

    rt = runtime or get_runtime(db_path)
    with rt.doc_lock(caller.tenant_id):
        doc_index = rt.get_doc_index(caller.tenant_id)
        with rt.write_tx() as conn:
            existing = conn.execute(
                "SELECT tenant_id, clearance_level, quarantined FROM compliance_docs WHERE doc_id = ?",
                (doc_id,),
            ).fetchone()
            if existing:
                if existing["tenant_id"] != caller.tenant_id:
                    raise PermissionError("Document ID belongs to another tenant")
                if int(existing["clearance_level"]) > caller.max_clearance:
                    raise PermissionError("Existing document exceeds caller clearance")
                if is_doc_blocked_by_wall(
                    db_path, caller.tenant_id, caller.user_id, doc_id, runtime=rt
                ):
                    raise PermissionError("Document access blocked by Chinese Wall")
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

            if clean_citations:
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, c_ref, updated_at) for c_ref in clean_citations],
                )

        doc_index.apply_upsert(
            doc_id=doc_id,
            category=category,
            regulation_code=regulation_code,
            clearance_level=clearance_level,
            risk_weight=risk_weight,
            custom_tag=custom_tag,
            title=title,
            body=body,
            updated_at=updated_at,
            new_citations=clean_citations,
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
    *,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """将指定合规文档置为 RETIRED 退役状态，并同步更新反向引用方有效引用数。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    clean_doc_id = str(doc_id or "").strip()
    if not clean_doc_id:
        raise ValueError("doc_id is required")

    now_ts = int(caller.request_ts or int(time.time()))
    rt = runtime or get_runtime(db_path)

    with rt.doc_lock(caller.tenant_id):
        doc_index = rt.get_doc_index(caller.tenant_id)
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, clean_doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {clean_doc_id}")

        doc_index.apply_status_change(
            clean_doc_id,
            status="RETIRED",
            updated_at=now_ts,
        )

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": clean_doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
