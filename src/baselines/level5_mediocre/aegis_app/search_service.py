# -*- coding: utf-8 -*-
"""合规文档检索服务（5级平庸样本：保留 O(N^2) 去重，无界粗糙缓存漏绑权限纪元/委托时效，batch_get 漏纵向与隔离墙校验）。"""
from __future__ import annotations

from collections import Counter
import copy
import time
from typing import Any

from .auth import CallerContext, is_doc_blocked_by_acl, require_admin
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import open_connection
from .doc_indexer import compute_phrase_proximity_bonus, tokenize_text
from .legacy_compat import canonicalize_regulation_code

# 5级平庸缓存：无容量上限，未绑定角色撤回/借调过期/利益冲突墙更新，且任意文档写入即整库清空
_NAIVE_SEARCH_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}


def clear_naive_search_cache() -> None:
    _NAIVE_SEARCH_CACHE.clear()


def _jaccard_sets(set_a: set[str], set_b: set[str]) -> float:
    if not set_a and not set_b:
        return 1.0
    union_len = len(set_a | set_b)
    if union_len == 0:
        return 0.0
    return len(set_a & set_b) / union_len


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
    if sort_by not in ("score", "updated_at", "risk_weight"):
        raise ValueError("Unsupported sort_by field")
    if str(sort_dir).lower() not in ("asc", "desc"):
        raise ValueError("Unsupported sort_dir")

    cache_key = (
        db_path,
        caller.tenant_id,
        caller.user_id,
        query,
        category,
        tag_filter,
        deduplicate,
        sort_by,
        str(sort_dir).lower(),
        limit,
        offset,
    )
    if cache_key in _NAIVE_SEARCH_CACHE:
        return copy.deepcopy(_NAIVE_SEARCH_CACHE[cache_key])

    where_clauses = [
        "tenant_id = ?",
        "status = 'ACTIVE'",
        "quarantined = 0",
    ]
    params: list[Any] = [caller.tenant_id]
    if category:
        where_clauses.append("category = ?")
        params.append(category)
    if tag_filter:
        where_clauses.append("custom_tag = ?")
        params.append(tag_filter)

    sql = (
        "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
        "risk_weight, custom_tag, title, body, updated_at "
        f"FROM compliance_docs WHERE {' AND '.join(where_clauses)}"
    )

    conn = open_connection(db_path)
    try:
        raw_rows = conn.execute(sql, tuple(params)).fetchall()
        cite_rows = conn.execute(
            "SELECT doc_id, COUNT(*) AS cnt FROM doc_citations WHERE tenant_id = ? GROUP BY doc_id",
            (caller.tenant_id,),
        ).fetchall()
        cite_map = {r["doc_id"]: int(r["cnt"]) for r in cite_rows}
    finally:
        conn.close()

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    candidates: list[dict[str, Any]] = []

    for row in raw_rows:
        if int(row["clearance_level"]) > caller.max_clearance:
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

        cite_cnt = cite_map.get(row["doc_id"], 0)
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
                "_tok_set": set(title_tokens + body_tokens),
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
                sim = _jaccard_sets(rep["_tok_set"], candidates[j]["_tok_set"])
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
    if reverse_flag:
        final_list.sort(key=lambda d: (-d[sort_by], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_by], d["doc_id"]))

    total_matched = len(final_list)
    if limit < 0:
        sliced = final_list[max(0, offset):]
    else:
        sliced = final_list[max(0, offset): max(0, offset) + limit]

    items_out = [{k: v for k, v in doc.items() if not k.startswith("_")} for doc in sliced]
    resp = {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items_out),
        "items": items_out,
    }
    _NAIVE_SEARCH_CACHE[cache_key] = copy.deepcopy(resp)
    return resp


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """仅补了 tenant_id 过滤，遗漏了纵向 clearance_level、quarantined 与利益冲突隔离墙拦截。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")

    placeholders = ",".join("?" for _ in doc_ids)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *doc_ids),
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

    clear_naive_search_cache()
    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
