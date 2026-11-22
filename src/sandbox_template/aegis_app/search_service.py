# -*- coding: utf-8 -*-
"""企业合规文档检索、相关性打分、利益冲突墙校验与近似修订簇折叠服务。"""
from __future__ import annotations

from collections import Counter
import re
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

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    # 逐字符归一化空白与标点后切分词项
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()
    return [tok for tok in TOKEN_RE.findall(cleaned) if len(tok) >= 2]


def _get_doc_citation_count(db_path: str, doc_id: str) -> int:
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT citation_id, cited_by_ref FROM doc_citations WHERE doc_id = ?",
            (doc_id,),
        ).fetchall()
        return len([dict(r) for r in rows])
    finally:
        conn.close()


def _jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    tokens_a = tokenize_text(title_a) + tokenize_text(body_a)
    tokens_b = tokenize_text(title_b) + tokenize_text(body_b)
    uniq_a: list[str] = []
    for t in tokens_a:
        if t not in uniq_a:
            uniq_a.append(t)
    uniq_b: list[str] = []
    for t in tokens_b:
        if t not in uniq_b:
            uniq_b.append(t)
    if not uniq_a and not uniq_b:
        return 1.0
    inter_cnt = sum(1 for t in uniq_a if t in uniq_b)
    union_cnt = len(uniq_a) + sum(1 for t in uniq_b if t not in uniq_a)
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt


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
    """执行多关键词合规文档检索，按调用者实时密级与利益冲突墙过滤，并折叠近似修订版。"""
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
        # 实时核验操作员最高密级与部门利益冲突隔离墙（Chinese Wall）
        _, live_clearance = resolve_effective_permissions(db_path, caller.tenant_id, caller.user_id)
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
        else:
            term_score = 0.0

        cite_cnt = _get_doc_citation_count(db_path, row["doc_id"])
        risk_w = int(row["risk_weight"])
        total_score = round(term_score + 0.25 * cite_cnt + 0.1 * risk_w, 4)

        candidates.append(
            {
                "doc_id": row["doc_id"],
                "category": row["category"],
                "regulation_code": row["regulation_code"],
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
                same_reg = bool(rep["regulation_code"]) and (
                    rep["regulation_code"] == candidates[j]["regulation_code"]
                )
                sim = _jaccard_similarity_from_texts(
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
    """由合规管理员将指定合规文档置为隔离下架或解除隔离状态。"""
    require_admin(caller)
    now_ts = int(time.time())
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
