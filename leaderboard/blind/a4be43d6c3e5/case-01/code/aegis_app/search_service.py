# -*- coding: utf-8 -*-
"""企业合规文档增量倒排检索、双指针邻近度打分、集合剪枝簇折叠与密级管控编排服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import _get_acl_cache, evaluate_wall_rules, get_org_lineage_from_map
from .auth import CallerContext, require_admin, resolve_effective_permissions
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .doc_indexer import (
    compute_phrase_proximity_bonus_from_seq,
    jaccard_similarity_from_sets,
    tokenize_text,
)
from .doc_store import CompactDocEntry, get_or_load_doc_index
from .state import get_gateway_state


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    """获取文档当前有效的唯一引用源数量（优先从增量引用图 O(1) 读取，且严格隔离租户）。"""
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(tenant_id)
    idx = get_or_load_doc_index(gw_state, t_state)
    entry = idx.docs.get(doc_id)
    return entry.valid_citation_count if entry is not None else 0


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
    """执行合规文档检索：基于增量倒排索引、独立 ACL 纪元缓存、双指针词距与集合剪枝去重。"""
    if sort_by not in ("score", "updated_at", "risk_weight"):
        sort_by = "score"
    norm_dir = str(sort_dir or "desc").lower()
    if norm_dir not in ("asc", "desc"):
        norm_dir = "desc"
    if offset < 0:
        offset = 0

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    idx = get_or_load_doc_index(gw_state, t_state)
    acl_cache = _get_acl_cache(gw_state, caller.tenant_id)

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    user_lineage = get_org_lineage_from_map(acl_cache.org_parents, caller.org_node_id)

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    query_tids: list[int] = []
    if query_terms:
        for t in query_terms:
            tid = gw_state.interner.lookup(t)
            query_tids.append(tid if tid is not None else -1)

    with t_state.doc_lock:
        if query_terms:
            candidate_ids: set[str] = set()
            inv = idx.inverted_index
            for tid in query_tids:
                if tid != -1:
                    postings = inv.get(tid)
                    if postings:
                        candidate_ids.update(postings)
        else:
            candidate_ids = set(idx.active_doc_ids)

        cat_upper = category.strip().upper() if category else ""
        candidates: list[tuple[dict[str, Any], CompactDocEntry]] = []
        rules_by_doc = acl_cache.rules_by_doc

        for doc_id in candidate_ids:
            entry = idx.docs.get(doc_id)
            if entry is None or entry.status != "ACTIVE" or entry.quarantined != 0:
                continue
            if cat_upper and entry.category != cat_upper:
                continue
            if tag_filter and entry.custom_tag != tag_filter:
                continue
            if entry.clearance_level > live_clearance:
                continue
            doc_rules = rules_by_doc.get(doc_id)
            if doc_rules and evaluate_wall_rules(doc_rules, caller.user_id, user_lineage):
                continue

            if query_tids:
                t_tf = entry.title_tf
                b_tf = entry.body_tf
                term_score = 0.0
                for tid in query_tids:
                    if tid == -1:
                        continue
                    tc = t_tf.get(tid, 0)
                    bc = b_tf.get(tid, 0)
                    if tc:
                        term_score += 3.5 * (tc if tc <= 5 else 5)
                    if bc:
                        term_score += 1.0 * (bc if bc <= 12 else 12)
                prox_bonus = compute_phrase_proximity_bonus_from_seq(entry.body_seq, query_tids)
            else:
                term_score = 0.0
                prox_bonus = 0.0

            cite_cnt = entry.valid_citation_count
            risk_w = entry.risk_weight
            total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

            candidates.append(
                (
                    {
                        "doc_id": entry.doc_id,
                        "category": entry.category,
                        "regulation_code": entry.regulation_code,
                        "clearance_level": entry.clearance_level,
                        "risk_weight": risk_w,
                        "custom_tag": entry.custom_tag,
                        "title": entry.title,
                        "snippet": entry.snippet,
                        "citation_count": cite_cnt,
                        "score": total_score,
                        "updated_at": entry.updated_at,
                    },
                    entry,
                )
            )

    candidates.sort(key=lambda pair: (-pair[0]["score"], -pair[0]["updated_at"], pair[0]["doc_id"]))

    if deduplicate:
        kept: list[dict[str, Any]] = []
        consumed = [False] * len(candidates)
        n_cand = len(candidates)
        for i in range(n_cand):
            if consumed[i]:
                continue
            rep_dict, rep_entry = candidates[i]
            rep_canon = rep_entry.canon_reg
            rep_tokens = rep_entry.uniq_tokens
            cluster_size = 1
            if rep_canon:
                for j in range(i + 1, n_cand):
                    if consumed[j]:
                        continue
                    cand_entry = candidates[j][1]
                    if cand_entry.canon_reg != rep_canon:
                        continue
                    sim = jaccard_similarity_from_sets(
                        rep_tokens,
                        cand_entry.uniq_tokens,
                        min_threshold=DEDUP_JACCARD_THRESHOLD,
                    )
                    if sim >= DEDUP_JACCARD_THRESHOLD:
                        consumed[j] = True
                        cluster_size += 1
            rep_out = dict(rep_dict)
            rep_out["cluster_size"] = cluster_size
            kept.append(rep_out)
        final_list = kept
    else:
        final_list = []
        for item_dict, _ in candidates:
            copied = dict(item_dict)
            copied["cluster_size"] = 1
            final_list.append(copied)

    reverse_flag = norm_dir != "asc"
    if reverse_flag:
        final_list.sort(key=lambda d: (-d[sort_by], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_by], d["doc_id"]))

    total_matched = len(final_list)
    if limit < 0:
        sliced = final_list[offset:]
    else:
        sliced = final_list[offset : offset + limit]

    return {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(sliced),
        "items": sliced,
    }


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取当前租户内调用者有权访问的完整合规文档内容。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > 200:
        raise ValueError("doc_ids exceeds maximum batch size (200)")

    gw_state = get_gateway_state(db_path)
    acl_cache = _get_acl_cache(gw_state, caller.tenant_id)
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    user_lineage = get_org_lineage_from_map(acl_cache.org_parents, caller.org_node_id)
    rules_by_doc = acl_cache.rules_by_doc

    placeholders = ",".join("?" for _ in doc_ids)
    with gw_state.pool.borrow() as conn:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *doc_ids),
        ).fetchall()

    by_id = {r["doc_id"]: r for r in rows}
    items = []
    for did in doc_ids:
        r = by_id.get(did)
        if not r or r["status"] != "ACTIVE" or int(r["quarantined"]) != 0:
            continue
        if int(r["clearance_level"]) > live_clearance:
            continue
        doc_rules = rules_by_doc.get(did)
        if doc_rules and evaluate_wall_rules(doc_rules, caller.user_id, user_lineage):
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

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    with t_state.doc_lock:
        idx = get_or_load_doc_index(gw_state, t_state)
        with gw_state.pool.borrow() as conn:
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

        idx.apply_status_change(doc_id, quarantined=q_val, updated_at=now_ts)
        t_state.doc_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
