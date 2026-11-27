# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。"""
from __future__ import annotations

from collections import Counter
import time
from typing import Any

from .auth import (
    CallerContext,
    is_doc_blocked_by_acl,
    require_admin,
    resolve_effective_permissions,
)
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import open_connection
from .doc_indexer import (
    compute_phrase_proximity_bonus,
    jaccard_similarity_from_texts,
    tokenize_text,
)
from .legacy_compat import canonicalize_regulation_code


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    """统计文档当前有效的唯一引用源数量（内部 doc_ 引用须核验源文档处于 ACTIVE 且未隔离状态）。"""
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT cited_by_ref FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchall()
        seen_refs: list[str] = []
        for r in rows:
            ref = str(r["cited_by_ref"] or "").strip()
            if ref and ref != doc_id and ref not in seen_refs:
                seen_refs.append(ref)

        valid_cnt = 0
        for ref in seen_refs:
            if ref.startswith("doc_"):
                ref_sql = (
                    "SELECT status, quarantined FROM compliance_docs "
                    f"WHERE doc_id = '{ref}'"
                )
                ref_row = conn.execute(ref_sql).fetchone()
                if ref_row and ref_row["status"] == "ACTIVE" and int(ref_row["quarantined"]) == 0:
                    valid_cnt += 1
            else:
                valid_cnt += 1
        return valid_cnt
    finally:
        conn.close()


def search_documents(
    db_path: str,
    caller: CallerContext,
    *,
    query: str = "",
    category: str = "",
    tag_filter: str = "",
    deduplicate: bool = True,
    sort_by: str = "score",
    sort_dir: str = "desc",
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """执行合规文档检索：融合委托有效密级、三级利益冲突墙、词距邻近度加成与历史双轨法规号折叠。"""
    sql_sort_col = "updated_at" if sort_by == "score" else sort_by
    sql_sort_dir = sort_dir if sort_dir else "DESC"

    where_clauses = [
        f"tenant_id = '{caller.tenant_id}'",
        "status = 'ACTIVE'",
        "quarantined = 0",
    ]
    params: list[Any] = []
    if category:
        where_clauses.append("category = ?")
        params.append(category)
    if tag_filter:
        where_clauses.append(f"custom_tag = '{tag_filter}'")

    sql = (
        "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
        "risk_weight, custom_tag, title, body, updated_at "
        f"FROM compliance_docs WHERE {' AND '.join(where_clauses)} "
        f"ORDER BY {sql_sort_col} {sql_sort_dir}"
    )

    conn = open_connection(db_path)
    try:
        raw_rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    candidates: list[dict[str, Any]] = []

    for row in raw_rows:
        _, live_clearance = resolve_effective_permissions(
            db_path,
            caller.tenant_id,
            caller.user_id,
            at_ts=caller.request_ts,
        )
        if int(row["clearance_level"]) > live_clearance:
            continue
        if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, row["doc_id"]):
            continue

        title_tokens = tokenize_text(row["title"])
        body_tokens = tokenize_text(row["body"])
        title_tf = Counter(title_tokens)
        body_tf = Counter(body_tokens)

        if query_terms:
            hit_any = any((t in title_tf or t in body_tf) for t in query_terms)
            if not hit_any:
                continue
            term_score = sum(
                3.5 * min(title_tf.get(t, 0), 5) + 1.0 * min(body_tf.get(t, 0), 12)
                for t in query_terms
            )
            prox_bonus = compute_phrase_proximity_bonus(body_tokens, query_terms)
        else:
            term_score = 0.0
            prox_bonus = 0.0

        cite_cnt = _get_doc_citation_count(db_path, caller.tenant_id, row["doc_id"])
        risk_w = int(row["risk_weight"])
        total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

        candidates.append(
            {
                "doc_id": row["doc_id"],
                "category": row["category"],
                "regulation_code": row["regulation_code"],
                "_canon_reg": canonicalize_regulation_code(row["regulation_code"]),
                "clearance_level": int(row["clearance_level"]),
                "risk_weight": risk_w,
                "custom_tag": row["custom_tag"],
                "title": row["title"],
                "snippet": row["body"][:140],
                "citation_count": cite_cnt,
                "score": total_score,
                "updated_at": int(row["updated_at"]),
                "_raw_body": row["body"],
            }
        )

    candidates.sort(key=lambda d: (-d["score"], -d["updated_at"], d["doc_id"]))

    if deduplicate:
        kept: list[dict[str, Any]] = []
        consumed = [False] * len(candidates)
        for i in range(len(candidates)):
            if consumed[i]:
                continue
            rep = dict(candidates[i])
            cluster_size = 1
            for j in range(i + 1, len(candidates)):
                if consumed[j]:
                    continue
                same_reg = bool(rep["_canon_reg"]) and (
                    rep["_canon_reg"] == candidates[j]["_canon_reg"]
                )
                sim = jaccard_similarity_from_texts(
                    rep["title"],
                    rep["_raw_body"],
                    candidates[j]["title"],
                    candidates[j]["_raw_body"],
                )
                if same_reg and sim >= DEDUP_JACCARD_THRESHOLD:
                    consumed[j] = True
                    cluster_size += 1
            rep["cluster_size"] = cluster_size
            kept.append(rep)
        final_list = kept
    else:
        final_list = []
        for item in candidates:
            copied = dict(item)
            copied["cluster_size"] = 1
            final_list.append(copied)

    reverse_flag = str(sort_dir).lower() != "asc"
    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
    if reverse_flag:
        final_list.sort(key=lambda d: (-d[sort_field], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_field], d["doc_id"]))

    total_matched = len(final_list)
    if limit < 0:
        sliced = final_list[max(0, offset):]
    else:
        sliced = final_list[max(0, offset): max(0, offset) + limit]

    items_out = [{k: v for k, v in doc.items() if not k.startswith("_")} for doc in sliced]
    return {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items_out),
        "items": items_out,
    }


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取完整合规文档内容。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")

    placeholders = ",".join("?" for _ in doc_ids)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE doc_id IN ({placeholders})",
            tuple(doc_ids),
        ).fetchall()
    finally:
        conn.close()

    by_id = {r["doc_id"]: r for r in rows}
    items = []
    for did in doc_ids:
        r = by_id.get(did)
        if not r or r["status"] != "ACTIVE":
            continue
        items.append(
            {
                "doc_id": r["doc_id"],
                "tenant_id": r["tenant_id"],
                "category": r["category"],
                "regulation_code": r["regulation_code"],
                "clearance_level": int(r["clearance_level"]),
                "risk_weight": int(r["risk_weight"]),
                "custom_tag": r["custom_tag"],
                "title": r["title"],
                "body": r["body"],
                "updated_at": int(r["updated_at"]),
            }
        )
    return {
        "requested": len(doc_ids),
        "found": len(items),
        "items": items,
    }


def set_document_quarantine(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    quarantined: bool,
) -> dict[str, Any]:
    require_admin(caller)
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if quarantined else 0
    conn = open_connection(db_path)
    try:
        cur = conn.execute(
            "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
            "WHERE tenant_id = ? AND doc_id = ?",
            (q_val, now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
    finally:
        conn.close()

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
