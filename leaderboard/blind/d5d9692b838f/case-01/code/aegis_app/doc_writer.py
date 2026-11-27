# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、单篇增量索引联动（Upsert）与退役归档（Retire）服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall
from .auth import CallerContext
from .config import (
    CLEARANCE_LEVELS,
    MAX_CITATIONS_PER_DOC,
    MAX_DOC_BODY_CHARS,
    MAX_SAFE_TS,
)
from .db import get_db_hub, write_transaction
from .doc_indexer import TenantDocIndex
from .middleware import strict_int


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
    """实时新增或修订本租户下的合规文档，并在内存倒排与反向引用图中执行 O(deg) 单篇增量更新。"""
    if not isinstance(payload, dict):
        raise ValueError("Document payload must be an object")

    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()

    raw_cl = payload.get("clearance_level")
    clearance_level = (
        2 if raw_cl is None else strict_int(raw_cl, "clearance_level")
    )
    raw_rw = payload.get("risk_weight")
    risk_weight = (
        10 if raw_rw is None else strict_int(raw_rw, "risk_weight")
    )
    raw_upd = payload.get("updated_at")
    updated_at = (
        int(caller.request_ts or int(time.time()))
        if raw_upd is None
        else strict_int(raw_upd, "updated_at", min_val=1, max_val=MAX_SAFE_TS)
    )

    raw_citations = payload.get("citations")
    if raw_citations is None:
        citations_list: list[str] = []
    elif isinstance(raw_citations, list):
        if len(raw_citations) > MAX_CITATIONS_PER_DOC:
            raise ValueError("citations list exceeds maximum allowed budget")
        citations_list = []
        seen_batch_refs: set[str] = set()
        for item in raw_citations:
            if isinstance(item, (dict, list, bool)):
                raise ValueError("Invalid citation reference type")
            c_str = str(item or "").strip()
            if len(c_str) > 256:
                raise ValueError("Citation reference exceeds maximum length")
            if c_str and c_str not in seen_batch_refs:
                seen_batch_refs.add(c_str)
                citations_list.append(c_str)
    else:
        raise ValueError("citations must be a list")

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if (
        len(doc_id) > 128
        or len(category) > 64
        or len(regulation_code) > 128
        or len(custom_tag) > 128
        or len(title) > 1024
        or len(body) > MAX_DOC_BODY_CHARS
    ):
        raise ValueError("Document field exceeds maximum allowed length")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if risk_weight < 0 or risk_weight > 200:
        raise ValueError("risk_weight must be between 0 and 200")

    _require_editor_clearance(caller, clearance_level)

    hub = get_db_hub(db_path)
    with hub.tenant_doc_lock(caller.tenant_id):
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
                if is_doc_blocked_by_wall(db_path, caller.tenant_id, caller.user_id, doc_id):
                    raise PermissionError("Document blocked by conflict-of-interest wall")
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

            if citations_list:
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, c_ref, updated_at) for c_ref in citations_list],
                )

        new_ep = hub.bump_doc_epoch(caller.tenant_id)
        cached_idx: TenantDocIndex | None = hub.doc_indices.get(caller.tenant_id)
        if cached_idx is not None and cached_idx.epoch == new_ep - 1:
            cached_idx.apply_upsert(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                body=body,
                status="ACTIVE",
                quarantined=(keep_q != 0),
                updated_at=updated_at,
                new_citations=citations_list,
                new_epoch=new_ep,
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
    """将指定合规文档置为 RETIRED 退役状态，并同步单篇增量摘除索引与内部引用有效性。"""
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
    clean_doc_id = str(doc_id or "").strip()
    if not clean_doc_id or len(clean_doc_id) > 128:
        raise ValueError("Valid doc_id is required")

    now_ts = int(caller.request_ts or int(time.time()))
    hub = get_db_hub(db_path)
    with hub.tenant_doc_lock(caller.tenant_id):
        with write_transaction(db_path) as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, clean_doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {clean_doc_id}")

        new_ep = hub.bump_doc_epoch(caller.tenant_id)
        cached_idx: TenantDocIndex | None = hub.doc_indices.get(caller.tenant_id)
        if cached_idx is not None and cached_idx.epoch == new_ep - 1:
            cached_idx.apply_retire(clean_doc_id, now_ts, new_ep)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": clean_doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
