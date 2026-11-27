# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .doc_indexer import TenantDocIndex
from .middleware import parse_strict_int
from .runtime import get_runtime

MAX_CITATIONS_PER_UPSERT = 64
MAX_CITATION_REF_LEN = 128
MAX_DOC_ID_LEN = 128
MAX_TITLE_LEN = 512
MAX_BODY_LEN = 262144  # 256 KiB


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
    """实时新增或修订本租户下的合规文档，并同步单篇增量更新内存倒排索引与反向引用图。"""
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object")

    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    clearance_level = parse_strict_int(
        payload.get("clearance_level"),
        "clearance_level",
        default=2,
        min_val=1,
        max_val=4,
    )
    risk_weight = parse_strict_int(
        payload.get("risk_weight"),
        "risk_weight",
        default=10,
        min_val=0,
        max_val=200,
    )
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    default_ts = int(caller.request_ts or int(time.time()))
    updated_at = parse_strict_int(
        payload.get("updated_at"),
        "updated_at",
        default=default_ts,
        min_val=0,
    )

    raw_citations = payload.get("citations")
    cleaned_citations: list[str] = []
    if raw_citations is not None:
        if not isinstance(raw_citations, list):
            raise ValueError("citations must be a list of strings")
        if len(raw_citations) > MAX_CITATIONS_PER_UPSERT:
            raise ValueError(f"citations count exceeds limit ({MAX_CITATIONS_PER_UPSERT})")
        for c_ref in raw_citations:
            if not isinstance(c_ref, str):
                raise ValueError("Each citation reference must be a string")
            c_str = c_ref.strip()
            if len(c_str) > MAX_CITATION_REF_LEN:
                raise ValueError("Citation reference exceeds maximum length")
            if c_str:
                cleaned_citations.append(c_str)

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if (
        len(doc_id) > MAX_DOC_ID_LEN
        or len(title) > MAX_TITLE_LEN
        or len(body) > MAX_BODY_LEN
        or len(category) > 64
        or len(regulation_code) > 64
        or len(custom_tag) > 128
    ):
        raise ValueError("Document field exceeds maximum length limit")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")

    _require_editor_clearance(caller, clearance_level)

    rt = get_runtime(db_path)
    with rt.doc_lock(caller.tenant_id):
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
                    [(caller.tenant_id, doc_id, c_ref, updated_at) for c_ref in cleaned_citations],
                )

        # 单篇增量同步内存倒排索引与反向引用图，递增 doc_epoch（不影响 acl/perm 纪元）
        doc_idx: TenantDocIndex | None = rt.doc_indices.get(caller.tenant_id)
        if doc_idx is not None:
            doc_idx.apply_upsert(
                rt,
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
        rt.epochs(caller.tenant_id).doc_epoch += 1

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
    """将指定合规文档置为 RETIRED 退役状态，单篇增量摘除倒排表并 O(deg) 联动引用计数。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    norm_doc_id = str(doc_id or "").strip()
    if not norm_doc_id:
        raise ValueError("doc_id is required")
    now_ts = int(caller.request_ts or int(time.time()))

    rt = get_runtime(db_path)
    with rt.doc_lock(caller.tenant_id):
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, norm_doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {norm_doc_id}")

        doc_idx: TenantDocIndex | None = rt.doc_indices.get(caller.tenant_id)
        if doc_idx is not None:
            doc_idx.apply_status_change(rt, doc_id=norm_doc_id, now_valid=False, updated_at=now_ts)
        rt.epochs(caller.tenant_id).doc_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": norm_doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
