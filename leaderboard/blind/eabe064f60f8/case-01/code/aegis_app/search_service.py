# -*- coding: utf-8 -*-
"""企业合规文档检索、相关性打分、利益冲突墙校验与近似修订簇折叠服务。"""
from __future__ import annotations

from collections import Counter
import re
import time
from typing import Any

from .auth import (
    CallerContext,
    get_denied_doc_ids,
    get_tenant_acl_snapshot,
    require_admin,
    resolve_effective_permissions,
)
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import get_thread_connection
from .runtime import IndexedDoc, TenantDocIndex, get_db_runtime

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")

ALLOWED_SORT_BY = frozenset({"score", "updated_at", "risk_weight"})
ALLOWED_SORT_DIR = frozenset({"asc", "desc"})

MAX_SEARCH_LIMIT = 200
MAX_SEARCH_OFFSET = 10000
MAX_QUERY_LENGTH = 512
MAX_QUERY_TERMS = 32
MAX_FILTER_LENGTH = 128
MAX_BATCH_GET_IDS = 200
MAX_WILDCARD_CHARS = 8


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def _build_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    """单次批量加载并预分词租户全部可用文档，构建内存倒排索引与属性索引。"""
    tr = get_db_runtime(db_path).tenant(tenant_id)
    cached = tr.get_cached_doc_index()
    if cached is not None:
        return cached

    with tr.lock:
        expected_epoch = tr.doc_epoch

    conn = get_thread_connection(db_path)
    cite_rows = conn.execute(
        "SELECT doc_id, COUNT(*) AS cnt FROM doc_citations WHERE tenant_id = ? GROUP BY doc_id",
        (tenant_id,),
    ).fetchall()
    cite_map: dict[str, int] = {str(r["doc_id"]): int(r["cnt"]) for r in cite_rows}

    doc_rows = conn.execute(
        "SELECT doc_id, category, regulation_code, clearance_level, "
        "risk_weight, custom_tag, title, body, updated_at "
        "FROM compliance_docs "
        "WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
        (tenant_id,),
    ).fetchall()

    docs: list[IndexedDoc] = []
    inverted_sets: dict[str, list[int]] = {}
    cat_sets: dict[str, set[int]] = {}
    tag_sets: dict[str, set[int]] = {}

    for idx, row in enumerate(doc_rows):
        doc_id = str(row["doc_id"])
        cat = str(row["category"])
        reg_code = str(row["regulation_code"])
        clearance = int(row["clearance_level"])
        risk_w = int(row["risk_weight"])
        tag = str(row["custom_tag"])
        title = str(row["title"])
        body = str(row["body"])
        upd_at = int(row["updated_at"])

        title_tf = Counter(tokenize_text(title))
        body_tf = Counter(tokenize_text(body))
        title_capped = {k: (5 if v > 5 else v) for k, v in title_tf.items()}
        body_capped = {k: (12 if v > 12 else v) for k, v in body_tf.items()}
        token_set = frozenset(title_capped.keys()) | frozenset(body_capped.keys())

        cite_cnt = cite_map.get(doc_id, 0)
        base_score = 0.25 * cite_cnt + 0.1 * risk_w

        docs.append(
            IndexedDoc(
                idx=idx,
                doc_id=doc_id,
                category=cat,
                regulation_code=reg_code,
                clearance_level=clearance,
                risk_weight=risk_w,
                custom_tag=tag,
                title=title,
                snippet=body[:140],
                citation_count=cite_cnt,
                base_score=base_score,
                updated_at=upd_at,
                title_tf_capped=title_capped,
                body_tf_capped=body_capped,
                token_set=token_set,
                token_set_len=len(token_set),
            )
        )

        for tok in token_set:
            inverted_sets.setdefault(tok, []).append(idx)
        cat_sets.setdefault(cat, set()).add(idx)
        tag_sets.setdefault(tag, set()).add(idx)

    index = TenantDocIndex(
        epoch=expected_epoch,
        docs=docs,
        inverted=inverted_sets,
        by_category={k: frozenset(v) for k, v in cat_sets.items()},
        by_tag={k: frozenset(v) for k, v in tag_sets.items()},
    )
    tr.put_cached_doc_index(index)
    return index


def _validate_search_inputs(
    *,
    query: str,
    category: str,
    tag_filter: str,
    sort_by: str,
    sort_dir: str,
    limit: int,
    offset: int,
) -> tuple[str, str, list[str]]:
    if not isinstance(query, str) or len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"query exceeds maximum length of {MAX_QUERY_LENGTH}")
    wildcard_cnt = sum(1 for ch in query if ch in "%*?")
    if wildcard_cnt > MAX_WILDCARD_CHARS:
        raise ValueError("Excessive wildcard characters in search query")

    if not isinstance(category, str) or len(category) > MAX_FILTER_LENGTH:
        raise ValueError("Invalid category filter")
    if not isinstance(tag_filter, str) or len(tag_filter) > MAX_FILTER_LENGTH:
        raise ValueError("Invalid tag_filter")

    norm_sort_by = (sort_by or "score").strip()
    if norm_sort_by not in ALLOWED_SORT_BY:
        raise ValueError(f"Unsupported sort_by field: {norm_sort_by}")

    norm_sort_dir = (sort_dir or "desc").strip().lower()
    if norm_sort_dir not in ALLOWED_SORT_DIR:
        raise ValueError(f"Unsupported sort_dir direction: {norm_sort_dir}")

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0 or limit > MAX_SEARCH_LIMIT:
        raise ValueError(f"limit must be an integer between 0 and {MAX_SEARCH_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > MAX_SEARCH_OFFSET:
        raise ValueError(f"offset must be an integer between 0 and {MAX_SEARCH_OFFSET}")

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > MAX_QUERY_TERMS:
        raise ValueError(f"query contains too many unique terms (max {MAX_QUERY_TERMS})")

    return norm_sort_by, norm_sort_dir, query_terms


def _deduplicate_scored_docs(
    scored: list[tuple[IndexedDoc, float]],
) -> list[tuple[IndexedDoc, float, int]]:
    """按 regulation_code 分桶 + 集合大小下界剪枝的精确 Jaccard 近似修订簇折叠。

    数学等价性保证：不同 regulation_code 间绝不合并，同组内按 (-score, -updated_at, doc_id)
    顺序贪心聚簇，与全量 O(N^2) 扫描产生 100% 相同的代表文档与 cluster_size。
    """
    reg_buckets: dict[str, list[int]] = {}
    for pos, (doc, _) in enumerate(scored):
        if doc.regulation_code:
            reg_buckets.setdefault(doc.regulation_code, []).append(pos)

    cluster_sizes: dict[int, int] = {}
    consumed_pos: set[int] = set()

    for positions in reg_buckets.values():
        n = len(positions)
        if n == 1:
            cluster_sizes[positions[0]] = 1
            continue
        local_consumed = [False] * n
        for i in range(n):
            if local_consumed[i]:
                continue
            pos_i = positions[i]
            doc_a = scored[pos_i][0]
            set_a = doc_a.token_set
            len_a = doc_a.token_set_len
            c_size = 1
            for j in range(i + 1, n):
                if local_consumed[j]:
                    continue
                pos_j = positions[j]
                doc_b = scored[pos_j][0]
                len_b = doc_b.token_set_len
                if len_a == 0 and len_b == 0:
                    sim = 1.0
                else:
                    min_l = len_a if len_a < len_b else len_b
                    max_l = len_b if len_a < len_b else len_a
                    if max_l == 0 or min_l < DEDUP_JACCARD_THRESHOLD * max_l:
                        continue
                    inter = len(set_a & doc_b.token_set)
                    union = len_a + len_b - inter
                    sim = (inter / union) if union > 0 else 0.0
                if sim >= DEDUP_JACCARD_THRESHOLD:
                    local_consumed[j] = True
                    consumed_pos.add(pos_j)
                    c_size += 1
            cluster_sizes[pos_i] = c_size

    out: list[tuple[IndexedDoc, float, int]] = []
    for pos, (doc, sc) in enumerate(scored):
        if pos in consumed_pos:
            continue
        out.append((doc, sc, cluster_sizes.get(pos, 1)))
    return out


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
    norm_sort_by, norm_sort_dir, query_terms = _validate_search_inputs(
        query=query,
        category=category,
        tag_filter=tag_filter,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=limit,
        offset=offset,
    )

    tr = get_db_runtime(db_path).tenant(caller.tenant_id)
    epochs_before = tr.get_search_epochs()
    _, live_clearance = resolve_effective_permissions(db_path, caller.tenant_id, caller.user_id)

    cache_key = (
        epochs_before[0],
        epochs_before[1],
        epochs_before[2],
        caller.user_id,
        live_clearance,
        query,
        category,
        tag_filter,
        bool(deduplicate),
        norm_sort_by,
        norm_sort_dir,
        limit,
        offset,
    )
    cached_resp = tr.get_search_lru(cache_key)
    if cached_resp is not None:
        return {
            "tenant_id": cached_resp["tenant_id"],
            "total_matched": cached_resp["total_matched"],
            "returned_count": cached_resp["returned_count"],
            "items": [dict(it) for it in cached_resp["items"]],
        }

    doc_index = _build_tenant_doc_index(db_path, caller.tenant_id)
    acl_snap = get_tenant_acl_snapshot(db_path, caller.tenant_id)
    denied_docs = get_denied_doc_ids(
        db_path,
        caller.tenant_id,
        caller.user_id,
        caller.org_node_id,
        acl_snap=acl_snap,
    )

    docs = doc_index.docs
    candidate_indices: set[int] | None = None

    if query_terms:
        q_set: set[int] = set()
        inv = doc_index.inverted
        for term in query_terms:
            postings = inv.get(term)
            if postings:
                q_set.update(postings)
        candidate_indices = q_set

    if category:
        cat_set = doc_index.by_category.get(category)
        if not cat_set:
            candidate_indices = set()
        elif candidate_indices is None:
            candidate_indices = set(cat_set)
        else:
            candidate_indices &= cat_set

    if tag_filter:
        tag_set = doc_index.by_tag.get(tag_filter)
        if not tag_set:
            candidate_indices = set()
        elif candidate_indices is None:
            candidate_indices = set(tag_set)
        else:
            candidate_indices &= tag_set

    iter_indices = range(len(docs)) if candidate_indices is None else candidate_indices

    scored: list[tuple[IndexedDoc, float]] = []
    has_query = bool(query_terms)

    for idx in iter_indices:
        doc = docs[idx]
        if doc.clearance_level > live_clearance:
            continue
        if denied_docs and doc.doc_id in denied_docs:
            continue
        if has_query:
            t_tf = doc.title_tf_capped
            b_tf = doc.body_tf_capped
            term_score = 0.0
            for t in query_terms:
                tc = t_tf.get(t, 0)
                bc = b_tf.get(t, 0)
                if tc:
                    term_score += 3.5 * tc
                if bc:
                    term_score += bc
        else:
            term_score = 0.0
        total_score = round(term_score + doc.base_score, 4)
        scored.append((doc, total_score))

    scored.sort(key=lambda pair: (-pair[1], -pair[0].updated_at, pair[0].doc_id))

    if deduplicate:
        final_tuples = _deduplicate_scored_docs(scored)
    else:
        final_tuples = [(doc, sc, 1) for doc, sc in scored]

    reverse_flag = norm_sort_dir != "asc"
    if norm_sort_by == "score":
        if reverse_flag:
            final_tuples.sort(key=lambda item: (-item[1], item[0].doc_id))
        else:
            final_tuples.sort(key=lambda item: (item[1], item[0].doc_id))
    elif norm_sort_by == "updated_at":
        if reverse_flag:
            final_tuples.sort(key=lambda item: (-item[0].updated_at, item[0].doc_id))
        else:
            final_tuples.sort(key=lambda item: (item[0].updated_at, item[0].doc_id))
    else:  # risk_weight
        if reverse_flag:
            final_tuples.sort(key=lambda item: (-item[0].risk_weight, item[0].doc_id))
        else:
            final_tuples.sort(key=lambda item: (item[0].risk_weight, item[0].doc_id))

    total_matched = len(final_tuples)
    sliced = final_tuples[offset : offset + limit]

    items_out = [
        {
            "doc_id": doc.doc_id,
            "category": doc.category,
            "regulation_code": doc.regulation_code,
            "clearance_level": doc.clearance_level,
            "risk_weight": doc.risk_weight,
            "custom_tag": doc.custom_tag,
            "title": doc.title,
            "snippet": doc.snippet,
            "citation_count": doc.citation_count,
            "score": sc,
            "updated_at": doc.updated_at,
            "cluster_size": c_size,
        }
        for doc, sc, c_size in sliced
    ]

    result = {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items_out),
        "items": items_out,
    }
    tr.put_search_lru(cache_key, epochs_before, result)
    return result


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取完整合规文档内容（严格校验租户隔离、密级、隔离状态与利益冲突墙）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_IDS:
        raise ValueError(f"doc_ids exceeds maximum batch size of {MAX_BATCH_GET_IDS}")

    cleaned_ids: list[str] = []
    for raw_id in doc_ids:
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise ValueError("Each doc_id must be a non-empty string")
        cleaned_ids.append(raw_id.strip())

    _, live_clearance = resolve_effective_permissions(db_path, caller.tenant_id, caller.user_id)
    denied_docs = get_denied_doc_ids(db_path, caller.tenant_id, caller.user_id, caller.org_node_id)

    unique_ids = list(dict.fromkeys(cleaned_ids))
    placeholders = ",".join("?" for _ in unique_ids)
    conn = get_thread_connection(db_path)
    rows = conn.execute(
        f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
        f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
        f"FROM compliance_docs "
        f"WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 "
        f"AND clearance_level <= ? AND doc_id IN ({placeholders})",
        (caller.tenant_id, live_clearance, *unique_ids),
    ).fetchall()

    by_id = {str(r["doc_id"]): r for r in rows}
    items = []
    for did in cleaned_ids:
        if did in denied_docs:
            continue
        r = by_id.get(did)
        if not r:
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
        "requested": len(cleaned_ids),
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
    """由合规管理员将指定合规文档置为隔离下架或解除隔离状态，提交后立即递增 doc_epoch 失效缓存。"""
    require_admin(caller)
    if not doc_id:
        raise ValueError("doc_id is required")

    now_ts = int(time.time())
    q_val = 1 if quarantined else 0
    conn = get_thread_connection(db_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
            "WHERE tenant_id = ? AND doc_id = ?",
            (q_val, now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            conn.execute("ROLLBACK")
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    get_db_runtime(db_path).tenant(caller.tenant_id).bump_doc_epoch()

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
