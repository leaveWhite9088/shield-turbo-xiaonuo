# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。

性能契约：单篇 upsert/retire 只做单篇增量索引更新（倒排位置表 + 引用反向依赖
脏标记），绝不重建整租户倒排索引；正文长度施加硬预算以约束常驻索引内存。
"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import (
    CLEARANCE_LEVELS,
    MAX_DOC_BODY_BYTES,
    MAX_DOC_CITATIONS,
    MAX_DOC_TITLE_LEN,
    MAX_REF_LEN,
)
from .db import coerce_strict_int, open_connection
from .index_cache import get_state


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
    """实时新增或修订本租户下的合规文档，并同步登记可选引用记录。"""
    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    clearance_level = coerce_strict_int(payload.get("clearance_level"), 2, field="clearance_level")
    risk_weight = coerce_strict_int(payload.get("risk_weight"), 10, field="risk_weight")
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    updated_at = coerce_strict_int(
        payload.get("updated_at"), caller.request_ts or int(time.time()), field="updated_at"
    )
    citations = payload.get("citations") or []

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if len(doc_id) > 128 or len(title) > MAX_DOC_TITLE_LEN:
        raise ValueError("doc_id or title exceeds length limit")
    if len(category) > 64 or len(regulation_code) > 64 or len(custom_tag) > 128:
        raise ValueError("category, regulation_code, or custom_tag exceeds length limit")
    if len(body.encode("utf-8", "ignore")) > MAX_DOC_BODY_BYTES:
        raise ValueError(f"document body exceeds {MAX_DOC_BODY_BYTES} bytes")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if risk_weight < 0 or risk_weight > 200:
        raise ValueError("risk_weight must be between 0 and 200")
    if not isinstance(citations, list) or len(citations) > MAX_DOC_CITATIONS:
        raise ValueError(f"citations must be a list of at most {MAX_DOC_CITATIONS} references")
    normalized_refs = []
    for c_ref in citations:
        ref = str(c_ref).strip()
        if not ref or len(ref) > MAX_REF_LEN:
            raise ValueError("each citation reference must be a non-empty short string")
        normalized_refs.append(ref)

    _require_editor_clearance(caller, clearance_level)

    conn = open_connection(db_path)
    try:
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

        if normalized_refs:
            conn.executemany(
                "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                [(caller.tenant_id, doc_id, ref, updated_at) for ref in normalized_refs],
            )
        conn.commit()
    finally:
        conn.close()

    # 单篇增量索引联动：新条目/引用立即对后续检索生效
    state = get_state(db_path)
    tstate = state.tenant(caller.tenant_id)
    tstate.ensure_docs(db_path)
    tstate.apply_upsert(
        {
            "doc_id": doc_id,
            "category": category,
            "regulation_code": regulation_code,
            "clearance_level": clearance_level,
            "risk_weight": risk_weight,
            "custom_tag": custom_tag,
            "title": title,
            "body": body,
            "status": "ACTIVE",
            "quarantined": int(existing["quarantined"]) if existing else 0,
            "updated_at": updated_at,
        },
        normalized_refs,
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
        cur = conn.execute(
            "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
            (now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
    finally:
        conn.close()

    # 单篇增量：退役状态翻转 + 反向依赖引用计数脏标记
    get_state(db_path).tenant(caller.tenant_id).apply_status(doc_id, "RETIRED")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
