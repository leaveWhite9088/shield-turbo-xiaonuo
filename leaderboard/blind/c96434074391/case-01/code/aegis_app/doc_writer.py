# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall
from .auth import CallerContext
from .config import (
    CLEARANCE_LEVELS,
    MAX_CITATION_REF_LEN,
    MAX_DOC_BODY_LEN,
    MAX_DOC_CITATIONS,
    MAX_DOC_TITLE_LEN,
)
from .db import get_db_runtime
from .doc_indexer import get_tenant_doc_index
from .middleware import strict_int


def _require_editor_clearance(caller: CallerContext, doc_clearance: int) -> None:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("SENIOR_AUDITOR or COMPLIANCE_ADMIN role required to write documents")
    if doc_clearance > caller.max_clearance:
        raise PermissionError("Cannot create or modify document above caller clearance level")


def _require_clean_str(val: Any, field_name: str, *, max_len: int, allow_empty: bool = False) -> str:
    if val is None:
        if allow_empty:
            return ""
        raise ValueError(f"{field_name} is required")
    if not isinstance(val, str):
        raise ValueError(f"{field_name} must be a string")
    s = val.strip()
    if not allow_empty and not s:
        raise ValueError(f"{field_name} cannot be empty")
    if len(s) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length ({max_len})")
    return s


def upsert_compliance_document(
    db_path: str,
    caller: CallerContext,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """实时新增或修订本租户下的合规文档，并单篇增量更新内存倒排与双向引用图。"""
    if not isinstance(payload, dict):
        raise ValueError("Document payload must be an object")

    doc_id = _require_clean_str(payload.get("doc_id"), "doc_id", max_len=128)
    raw_cat = payload.get("category")
    category = _require_clean_str(raw_cat if raw_cat is not None else "AML", "category", max_len=64).upper()
    raw_reg = payload.get("regulation_code")
    regulation_code = _require_clean_str(
        raw_reg if raw_reg is not None else "",
        "regulation_code",
        max_len=64,
        allow_empty=True,
    )

    raw_cl = payload.get("clearance_level")
    clearance_level = strict_int(raw_cl if raw_cl is not None else 2, "clearance_level", min_val=1, max_val=4)
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")

    raw_rw = payload.get("risk_weight")
    risk_weight = strict_int(raw_rw if raw_rw is not None else 10, "risk_weight", min_val=0, max_val=200)

    raw_tag = payload.get("custom_tag")
    custom_tag = _require_clean_str(
        raw_tag if raw_tag is not None else "tag_default",
        "custom_tag",
        max_len=128,
    )
    title = _require_clean_str(payload.get("title"), "title", max_len=MAX_DOC_TITLE_LEN)
    body = _require_clean_str(payload.get("body"), "body", max_len=MAX_DOC_BODY_LEN)

    raw_upd = payload.get("updated_at")
    updated_at = (
        strict_int(raw_upd, "updated_at", min_val=0)
        if raw_upd is not None
        else int(caller.request_ts or int(time.time()))
    )

    raw_citations = payload.get("citations")
    cleaned_citations: list[str] = []
    if raw_citations is not None:
        if not isinstance(raw_citations, list):
            raise ValueError("citations must be a list of strings")
        if len(raw_citations) > MAX_DOC_CITATIONS:
            raise ValueError(f"citations count exceeds limit ({MAX_DOC_CITATIONS})")
        seen_in_req: set[str] = set()
        for item in raw_citations:
            if not isinstance(item, str):
                raise ValueError("Each citation reference must be a string")
            c_str = item.strip()
            if len(c_str) > MAX_CITATION_REF_LEN:
                raise ValueError("Citation reference exceeds maximum length")
            if c_str and c_str != doc_id and c_str not in seen_in_req:
                seen_in_req.add(c_str)
                cleaned_citations.append(c_str)

    _require_editor_clearance(caller, clearance_level)

    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(caller.tenant_id):
        doc_index = get_tenant_doc_index(rt, caller.tenant_id)
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
                if is_doc_blocked_by_wall(db_path, caller.tenant_id, caller.user_id, doc_id):
                    raise PermissionError("Document modification blocked by conflict-of-interest wall")
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
                existing_node = doc_index.docs.get(doc_id)
                already_refs = existing_node.raw_citations if existing_node is not None else set()
                to_insert = [
                    (caller.tenant_id, doc_id, c_ref, updated_at)
                    for c_ref in cleaned_citations
                    if c_ref not in already_refs
                ]
                if to_insert:
                    conn.executemany(
                        "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                        to_insert,
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
            quarantined=bool(keep_q),
            updated_at=updated_at,
            citations=cleaned_citations,
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
    """将指定合规文档置为 RETIRED 退役状态，并沿反向引用图 O(deg) 剥离有效引用计数。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    norm_doc = _require_clean_str(doc_id, "doc_id", max_len=128)
    now_ts = int(caller.request_ts or int(time.time()))

    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(caller.tenant_id):
        doc_index = get_tenant_doc_index(rt, caller.tenant_id)
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, norm_doc),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {norm_doc}")
        doc_index.apply_retire(norm_doc, now_ts)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": norm_doc,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
