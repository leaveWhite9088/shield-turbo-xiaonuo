# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级/隔离墙管控编排服务。"""
from __future__ import annotations

import time
from typing import Any

from .auth import (
    CallerContext,
    is_doc_blocked_by_acl,
    require_admin,
    resolve_effective_permissions,
)
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT, MAX_BATCH_GET_DOCS
from .db import bump_doc_epoch, get_tenant_doc_lock, open_connection
from .doc_indexer import (
    compute_proximity_bonus_from_positions,
    get_loaded_tenant_doc_index,
    get_or_load_tenant_doc_index,
    jaccard_similarity_from_token_sets,
    tokenize_text,
)
from .middleware import strict_bool, strict_int

_ALLOWED_SORT_BY = frozenset({"score", "updated_at", "risk_weight"})
_ALLOWED_SORT_DIR = frozenset({"asc", "desc"})


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    """统计文档当前有效的唯一引用源数量（内部 doc_ 引用严格限制在本租户、ACTIVE 且未隔离状态，阻断跨租户侧信道与二阶注入）。"""
    idx = get_or_load_tenant_doc_index(db_path, tenant_id)
    node = idx.docs.get(doc_id)
    if node is not None:
        return node.valid_citation_count
    return 0


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
    norm_sort_by = str(sort_by or "score").strip()
    norm_sort_dir = str(sort_dir or "desc").strip().lower()
    if norm_sort_by not in _ALLOWED_SORT_BY:
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    if norm_sort_dir not in _ALLOWED_SORT_DIR:
        raise ValueError(f"Unsupported sort_dir value: {sort_dir}")

    lim_val = strict_int(limit, "limit", min_val=-1, max_val=1000)
    off_val = strict_int(offset, "offset", min_val=0, max_val=1000000)
    cat_filter = str(category or "").strip()
    tag_flt = str(tag_filter or "").strip()

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )

    idx = get_or_load_tenant_doc_index(db_path, caller.tenant_id)
    query_terms = list(dict.fromkeys(tokenize_text(str(query or ""))))

    if query_terms:
        candidate_ids: set[str] = set()
        inv = idx.inverted_index
        for t in query_terms:
            postings = inv.get(t)
            if postings:
                candidate_ids.update(postings)
    else:
        candidate_ids = idx.active_doc_ids

    candidates: list[dict[str, Any]] = []
    docs_map = idx.docs
    for doc_id in candidate_ids:
        node = docs_map.get(doc_id)
        if node is None or not node.is_active_source:
            continue
        if cat_filter and node.category != cat_filter:
            continue
        if tag_flt and node.custom_tag != tag_flt:
            continue
        if node.clearance_level > live_clearance:
            continue
        if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, doc_id):
            continue

        if query_terms:
            t_tf = node.title_tf
            b_pos = node.body_positions
            term_score = 0.0
            for t in query_terms:
                tc = t_tf.get(t, 0)
                bc_pos = b_pos.get(t)
                bc = len(bc_pos) if bc_pos is not None else 0
                term_score += 3.5 * (tc if tc < 5 else 5) + 1.0 * (bc if bc < 12 else 12)
            prox_bonus = compute_proximity_bonus_from_positions(b_pos, query_terms)
        else:
            term_score = 0.0
            prox_bonus = 0.0

        cite_cnt = node.valid_citation_count
        risk_w = node.risk_weight
        total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

        candidates.append(
            {
                "doc_id": node.doc_id,
                "category": node.category,
                "regulation_code": node.regulation_code,
                "_canon_reg": node.canon_reg,
                "_dedup_tokens": node.dedup_tokens,
                "clearance_level": node.clearance_level,
                "risk_weight": risk_w,
                "custom_tag": node.custom_tag,
                "title": node.title,
                "snippet": node.snippet,
                "citation_count": cite_cnt,
                "score": total_score,
                "updated_at": node.updated_at,
            }
        )

    candidates.sort(key=lambda d: (-d["score"], -d["updated_at"], d["doc_id"]))

    if deduplicate:
        kept: list[dict[str, Any]] = []
        n_cand = len(candidates)
        consumed = [False] * n_cand
        for i in range(n_cand):
            if consumed[i]:
                continue
            rep = dict(candidates[i])
            rep_reg = rep["_canon_reg"]
            rep_tokens = rep["_dedup_tokens"]
            cluster_size = 1
            if rep_reg:
                for j in range(i + 1, n_cand):
                    if consumed[j]:
                        continue
                    cand_j = candidates[j]
                    if rep_reg != cand_j["_canon_reg"]:
                        continue
                    sim = jaccard_similarity_from_token_sets(
                        rep_tokens,
                        cand_j["_dedup_tokens"],
                        threshold=DEDUP_JACCARD_THRESHOLD,
                    )
                    if sim >= DEDUP_JACCARD_THRESHOLD:
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

    reverse_flag = norm_sort_dir != "asc"
    sort_field = norm_sort_by
    if reverse_flag:
        final_list.sort(key=lambda d: (-d[sort_field], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_field], d["doc_id"]))

    total_matched = len(final_list)
    if lim_val < 0:
        sliced = final_list[off_val:]
    else:
        sliced = final_list[off_val : off_val + lim_val]

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
    """按文档 ID 列表批量获取完整合规文档内容（严格执行租户、ACTIVE、未隔离、实时密级与利益冲突墙校验）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_DOCS:
        raise ValueError(f"doc_ids count exceeds maximum limit ({MAX_BATCH_GET_DOCS})")

    clean_ids: list[str] = []
    for did in doc_ids:
        if not isinstance(did, str) or not did.strip() or len(did) > 128:
            raise ValueError("Each doc_id must be a valid non-empty string")
        clean_ids.append(did.strip())

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )

    unique_ids = list(dict.fromkeys(clean_ids))
    placeholders = ",".join("?" for _ in unique_ids)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 "
            f"AND doc_id IN ({placeholders})",
            (caller.tenant_id, *unique_ids),
        ).fetchall()
    finally:
        conn.close()

    by_id = {str(r["doc_id"]): r for r in rows}
    items = []
    for did in clean_ids:
        r = by_id.get(did)
        if not r:
            continue
        if int(r["clearance_level"]) > live_clearance:
            continue
        if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, did):
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
        "requested": len(clean_ids),
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
    """紧急隔离或解封文档（内存中通过 reverse_dependents 执行 O(deg) 增量引用计数更新）。"""
    require_admin(caller)
    clean_id = str(doc_id or "").strip()
    if not clean_id:
        raise ValueError("doc_id is required")
    q_bool = strict_bool(quarantined, "quarantined")
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if q_bool else 0

    with get_tenant_doc_lock(db_path, caller.tenant_id):
        idx = get_loaded_tenant_doc_index(db_path, caller.tenant_id)
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, clean_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {clean_id}")
            conn.commit()
        finally:
            conn.close()

        new_epoch = bump_doc_epoch(db_path, caller.tenant_id)
        if idx is not None:
            idx.update_doc_state(
                clean_id,
                quarantined=q_bool,
                updated_at=now_ts,
                new_epoch=new_epoch,
            )

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": clean_id,
        "quarantined": q_bool,
        "updated_at": now_ts,
    }
