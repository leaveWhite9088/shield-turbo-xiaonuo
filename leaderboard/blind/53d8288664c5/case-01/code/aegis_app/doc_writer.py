# -*- coding: utf-8 -*-
"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。

本模块职责（写入语义与原版 100% 一致）：
- 严格字段类型 / 长度 / 引用预算守卫：bool / 非整数混淆、超长字段、畸形引用
  洪水一律毫秒级 400 熔断；
- upsert / retire 提交后立即提升 docs 与 citations 业务纪元，令检索侧增量
  倒排、有效引用计数与隔离墙缓存零脏读即时联动失效（引用源文档状态翻转对
  被引用方 citation_count 的传导由读取侧纪元缓存感知）。
"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS
from .db import open_connection
from .epoch_cache import bump_epoch

_MAX_DOC_ID_LEN = 256
_MAX_TITLE_LEN = 1024
_MAX_CATEGORY_LEN = 128
_MAX_REG_CODE_LEN = 256
_MAX_TAG_LEN = 256
_MAX_CITATIONS = 200
_MAX_CITATION_REF_LEN = 256


def _coerce_doc_int(raw: Any, fallback: int, label: str) -> int:
    """严格整数字段守卫：None/0/空值回退默认（与原版 `or` 语义一致），bool / 非整数拒绝。"""
    if not raw:
        return fallback
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError(f"{label} must be an integer")
    return raw


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
    clearance_level = _coerce_doc_int(payload.get("clearance_level"), 2, "clearance_level")
    risk_weight = _coerce_doc_int(payload.get("risk_weight"), 10, "risk_weight")
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    updated_at = _coerce_doc_int(
        payload.get("updated_at"),
        int(caller.request_ts or int(time.time())),
        "updated_at",
    )
    citations = payload.get("citations") or []

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    if (
        len(doc_id) > _MAX_DOC_ID_LEN
        or len(title) > _MAX_TITLE_LEN
        or len(category) > _MAX_CATEGORY_LEN
        or len(regulation_code) > _MAX_REG_CODE_LEN
        or len(custom_tag) > _MAX_TAG_LEN
    ):
        raise ValueError("Document field length exceeds allowed limit")
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if risk_weight < 0 or risk_weight > 200:
        raise ValueError("risk_weight must be between 0 and 200")

    # 引用预算与长度守卫：畸形引用洪水在打开连接前即被 400 拒绝。
    normalized_citations: list[str] = []
    if isinstance(citations, list) and citations:
        if len(citations) > _MAX_CITATIONS:
            raise ValueError(f"citations list exceeds maximum allowed size ({_MAX_CITATIONS})")
        for c_ref in citations:
            ref_str = str(c_ref)
            if len(ref_str) > _MAX_CITATION_REF_LEN:
                raise ValueError("Citation reference exceeds allowed length")
            normalized_citations.append(ref_str)

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

        if normalized_citations:
            for ref_str in normalized_citations:
                conn.execute(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    (caller.tenant_id, doc_id, ref_str, updated_at),
                )
        conn.commit()
    finally:
        conn.close()

    # 文档与引用写入提交后立即提升 docs / citations 纪元，
    # 检索侧增量倒排、引用计数与隔离墙缓存零脏读即时联动。
    bump_epoch(db_path, "docs", "citations")

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

    # 退役状态翻转即时生效：docs 纪元提升后，该文档不再可被检索，
    # 也不再作为其他文档的有效内部引用源。
    bump_epoch(db_path, "docs")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
