# -*- coding: utf-8 -*-
"""企业合规文档实时入库、正文修订（Upsert）与退役归档（Retire）服务。

写入路径的一致性设计（全局锁偏序：SQL ``BEGIN IMMEDIATE`` → 内存索引提交 → COMMIT）：

1. 业务校验（角色、密级、字段）在任何锁与事务之前完成，非法请求不占锁；
2. 事务内先落库（含引用明细**整体替换**语义的重建），再在锁内做 O(词数 + 出度) 增量索引，
   最后更新请求世代戳并提交；异常路径回滚且内存索引按“重新装载该文档”自愈；
3. 内部引用 ``doc_`` 侧信道防御：来自其它租户的 ``doc_`` 引用只按“不存在”登记，绝不暴露其状态。
"""
from __future__ import annotations

import time
from typing import Any

from .auth import CallerContext
from .config import CLEARANCE_LEVELS, MAX_CITATIONS, MAX_ID_CHARS, MAX_TEXT_BODY_CHARS
from .db import GatewayDB
from .guards import guard_text, strict_int


def _require_editor_clearance(caller: CallerContext, doc_clearance: int) -> None:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise PermissionError("SENIOR_AUDITOR or COMPLIANCE_ADMIN role required to write documents")
    if doc_clearance > caller.max_clearance:
        raise PermissionError("Cannot create or modify document above caller clearance level")


def _work_db(caller: CallerContext, db_path: str) -> tuple[GatewayDB, bool]:
    if caller.db is not None and caller.db.path == db_path:
        return caller.db, False
    return GatewayDB(db_path), True


def upsert_compliance_document(
    db_path: str,
    caller: CallerContext,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """实时新增或修订本租户下的合规文档，并同步登记可选引用记录。"""
    if not isinstance(payload, dict):
        raise ValueError("Request JSON payload must be an object")
    doc_id = str(payload.get("doc_id") or "").strip()
    category = str(payload.get("category") or "AML").strip().upper()
    regulation_code = str(payload.get("regulation_code") or "").strip()
    clearance_level = strict_int(payload.get("clearance_level") or 2, name="clearance_level")
    risk_weight = strict_int(payload.get("risk_weight") or 10, name="risk_weight")
    custom_tag = str(payload.get("custom_tag") or "tag_default").strip()
    title = str(payload.get("title") or "").strip()
    body = str(payload.get("body") or "").strip()
    updated_at = strict_int(payload.get("updated_at") or caller.request_ts or int(time.time()),
                            name="updated_at")
    citations = payload.get("citations") or []

    if not doc_id or not title or not body:
        raise ValueError("doc_id, title, and body are required")
    guard_text(doc_id, name="doc_id", max_chars=MAX_ID_CHARS)
    guard_text(category, name="category", max_chars=MAX_ID_CHARS)
    guard_text(regulation_code, name="regulation_code", max_chars=MAX_ID_CHARS)
    guard_text(custom_tag, name="custom_tag", max_chars=MAX_ID_CHARS)
    guard_text(title, name="title", max_chars=MAX_TEXT_BODY_CHARS)
    guard_text(body, name="body", max_chars=MAX_TEXT_BODY_CHARS)
    if clearance_level not in CLEARANCE_LEVELS.values():
        raise ValueError("clearance_level must be in 1..4")
    if risk_weight < 0 or risk_weight > 200:
        raise ValueError("risk_weight must be between 0 and 200")
    if not isinstance(citations, list):
        raise ValueError("citations must be a list of reference ids")
    if len(citations) > MAX_CITATIONS:
        raise ValueError(f"citations exceeds limit of {MAX_CITATIONS}")
    for c_ref in citations:
        if not isinstance(c_ref, str):
            raise ValueError("citations must be a list of reference ids")
        guard_text(c_ref, name="citation", max_chars=MAX_ID_CHARS)

    _require_editor_clearance(caller, clearance_level)

    db, own = _work_db(caller, db_path)
    shared = caller.shared if not own else None
    try:
        refs = [str(c_ref) for c_ref in citations]

        def _tx(conn):
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
                        category, regulation_code, clearance_level, risk_weight, custom_tag, title,
                        body, keep_q, updated_at, caller.tenant_id, doc_id,
                    ),
                )
                mode = "updated"
                conn.execute(
                    "DELETE FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
                    (caller.tenant_id, doc_id),
                )
            else:
                conn.execute(
                    "INSERT INTO compliance_docs("
                    "doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
                    "custom_tag, title, body, status, quarantined, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?)",
                    (
                        doc_id, caller.tenant_id, category, regulation_code, clearance_level,
                        risk_weight, custom_tag, title, body, updated_at,
                    ),
                )
                mode = "created"
                keep_q = 0
            if refs:
                conn.executemany(
                    "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                    [(caller.tenant_id, doc_id, ref, updated_at) for ref in refs],
                )
            return mode, True, bool(keep_q == 0)

        mode, was_live, live = db.write(_tx)

        if shared is not None:
            index = shared.index
            index.view(caller.tenant_id)
            # 引用明细为整体替换语义：先整体解绑（含被引用方计数回退），再按新记录重挂
            index.put_document(
                caller.tenant_id,
                {
                    "doc_id": doc_id,
                    "category": category,
                    "regulation_code": regulation_code,
                    "clearance": clearance_level,
                    "risk_weight": risk_weight,
                    "custom_tag": custom_tag,
                    "title": title,
                    "body": body,
                    "updated_at": updated_at,
                    "status": "ACTIVE" if live else "RETIRED",
                    "quarantined": 0,
                    "ext_cites": 0,
                },
            )
            if refs:
                index.add_citations(caller.tenant_id, [(doc_id, ref) for ref in refs])
            with shared.lock:
                shared.stamp = int(caller.request_ts)
            shared.epoch.touch("doc")
    finally:
        if own:
            db.close_thread()

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
    db, own = _work_db(caller, db_path)
    shared = caller.shared if not own else None
    try:
        def _tx(conn):
            cur = conn.execute(
                "UPDATE compliance_docs SET status = 'RETIRED', updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (now_ts, caller.tenant_id, doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {doc_id}")

        db.write(_tx)
        if shared is not None:
            shared.index.change_status(caller.tenant_id, doc_id, status="RETIRED")
            with shared.lock:
                shared.stamp = now_ts
            shared.epoch.bump("doc")
    finally:
        if own:
            db.close_thread()

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "status": "RETIRED",
        "updated_at": now_ts,
    }
