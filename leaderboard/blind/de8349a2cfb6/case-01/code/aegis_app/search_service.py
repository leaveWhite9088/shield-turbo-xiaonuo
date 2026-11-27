# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import get_blocked_doc_ids_for_user
from .auth import (
    CallerContext,
    is_doc_blocked_by_acl,
    require_admin,
    resolve_effective_permissions,
)
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    MAX_BATCH_GET_DOC_IDS,
    MAX_QUERY_CHARS,
    MAX_QUERY_TERMS,
    parse_strict_int,
)
from .db import bump_domain_epoch, open_connection
from .doc_indexer import (
    compute_phrase_proximity_bonus_from_positions,
    get_tenant_doc_index,
    jaccard_similarity_from_sets,
    tokenize_text,
)


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    """统计文档当前有效的唯一引用源数量（内部 doc_ 引用须严格绑定本租户且处于 ACTIVE 未隔离状态）。"""
    idx = get_tenant_doc_index(db_path, tenant_id)
    with idx.lock:
        node = idx.docs.get(doc_id)
        if node is not None:
            return node.effective_citation_count

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
                ref_row = conn.execute(
                    "SELECT status, quarantined FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                    (tenant_id, ref),
                ).fetchone()
                if ref_row and ref_row["status"] == "ACTIVE" and int(ref_row["quarantined"]) == 0:
                    valid_cnt += 1
            else:
                valid_cnt += 1
        return valid_cnt
    finally:
        conn.close()


_ALLOWED_SORT_FIELDS = frozenset({"score", "updated_at", "risk_weight"})
_ALLOWED_SORT_DIRS = frozenset({"asc", "desc"})


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
    if norm_sort_by not in _ALLOWED_SORT_FIELDS:
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    if norm_sort_dir not in _ALLOWED_SORT_DIRS:
        raise ValueError(f"Unsupported sort_dir: {sort_dir}")

    lim_val = parse_strict_int(limit, "limit")
    off_val = parse_strict_int(offset, "offset")
    if off_val < 0:
        raise ValueError("offset must be non-negative")

    q_str = str(query or "")
    if len(q_str) > MAX_QUERY_CHARS:
        raise ValueError("Search query exceeds maximum allowed length")

    raw_terms = list(dict.fromkeys(tokenize_text(q_str)))
    if len(raw_terms) > MAX_QUERY_TERMS:
        raise ValueError(f"Search query exceeds maximum allowed unique terms ({MAX_QUERY_TERMS})")
    query_terms = raw_terms

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    blocked_docs = get_blocked_doc_ids_for_user(db_path, caller.tenant_id, caller.user_id)

    doc_index = get_tenant_doc_index(db_path, caller.tenant_id)
    candidates: list[dict[str, Any]] = []

    with doc_index.lock:
        if query_terms:
            hit_doc_ids: set[str] = set()
            for term in query_terms:
                bucket = doc_index.inverted.get(term)
                if bucket:
                    hit_doc_ids |= bucket
            candidate_nodes = [doc_index.docs[did] for did in hit_doc_ids if did in doc_index.docs]
        else:
            candidate_nodes = [n for n in doc_index.docs.values() if n.is_searchable]

        for node in candidate_nodes:
            if not node.is_searchable:
                continue
            if category and node.category != category:
                continue
            if tag_filter and node.custom_tag != tag_filter:
                continue
            if node.clearance_level > live_clearance:
                continue
            if node.doc_id in blocked_docs:
                continue

            if query_terms:
                t_tf = node.title_tf
                b_tf = node.body_tf
                term_score = 0.0
                for t in query_terms:
                    term_score += 3.5 * t_tf.get(t, 0) + 1.0 * b_tf.get(t, 0)
                prox_bonus = compute_phrase_proximity_bonus_from_positions(
                    node.body_positions,
                    query_terms,
                )
            else:
                term_score = 0.0
                prox_bonus = 0.0

            cite_cnt = node.effective_citation_count
            risk_w = node.risk_weight
            total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

            candidates.append(
                {
                    "doc_id": node.doc_id,
                    "category": node.category,
                    "regulation_code": node.regulation_code,
                    "_canon_reg": node.canon_reg,
                    "_vocab_set": node.vocab_set,
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
        reps_by_reg: dict[str, list[tuple[frozenset[str], dict[str, Any]]]] = {}
        for item in candidates:
            creg = item["_canon_reg"]
            vset: frozenset[str] = item["_vocab_set"]
            len_v = len(vset)
            matched_rep: dict[str, Any] | None = None
            if creg:
                reg_group = reps_by_reg.get(creg)
                if reg_group:
                    for rep_vset, rep_dict in reg_group:
                        len_r = len(rep_vset)
                        max_l = len_v if len_v >= len_r else len_r
                        min_l = len_r if len_v >= len_r else len_v
                        if max_l > 0 and (min_l / max_l) < DEDUP_JACCARD_THRESHOLD:
                            continue
                        if jaccard_similarity_from_sets(rep_vset, vset) >= DEDUP_JACCARD_THRESHOLD:
                            matched_rep = rep_dict
                            break
            if matched_rep is not None:
                matched_rep["cluster_size"] += 1
            else:
                rep = dict(item)
                rep["cluster_size"] = 1
                kept.append(rep)
                if creg:
                    reps_by_reg.setdefault(creg, []).append((vset, rep))
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
        sliced = final_list[max(0, off_val):]
    else:
        sliced = final_list[max(0, off_val): max(0, off_val) + lim_val]

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
    """按文档 ID 列表批量获取调用者有权访问的完整合规文档内容（严格遵守租户、状态、隔离、密级与利益冲突墙约束）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_DOC_IDS:
        raise ValueError(f"doc_ids exceeds maximum batch limit ({MAX_BATCH_GET_DOC_IDS})")

    clean_ids: list[str] = []
    for d in doc_ids:
        if not isinstance(d, str) or not d.strip():
            raise ValueError("Each doc_id must be a non-empty string")
        clean_ids.append(d.strip())

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    blocked_docs = get_blocked_doc_ids_for_user(db_path, caller.tenant_id, caller.user_id)

    placeholders = ",".join("?" for _ in clean_ids)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *clean_ids),
        ).fetchall()
    finally:
        conn.close()

    by_id = {r["doc_id"]: r for r in rows}
    items = []
    for did in clean_ids:
        r = by_id.get(did)
        if not r:
            continue
        if r["tenant_id"] != caller.tenant_id:
            continue
        if r["status"] != "ACTIVE" or int(r["quarantined"]) != 0:
            continue
        if int(r["clearance_level"]) > live_clearance:
            continue
        if did in blocked_docs or is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, did):
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
    if not doc_id:
        raise ValueError("doc_id is required")
    if not isinstance(quarantined, bool):
        raise ValueError("quarantined must be a boolean")
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if quarantined else 0
    doc_index = get_tenant_doc_index(db_path, caller.tenant_id)

    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
            "WHERE tenant_id = ? AND doc_id = ?",
            (q_val, now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            conn.rollback()
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
    finally:
        conn.close()

    doc_index.apply_status_change(doc_id, quarantined=q_val, updated_at=now_ts)
    bump_domain_epoch(db_path, caller.tenant_id, "doc")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
