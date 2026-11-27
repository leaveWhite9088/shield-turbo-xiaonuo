# -*- coding: utf-8 -*-
"""企业合规文档多维增量检索、双指针邻近度打分、剪枝法规簇折叠与密级隔离墙管控服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import get_acl_snapshot
from .auth import (
    CallerContext,
    require_admin,
    resolve_effective_permissions,
)
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    MAX_BATCH_GET_IDS,
    MAX_QUERY_CHARS,
    MAX_QUERY_TERMS,
)
from .db import borrow_connection, get_db_hub, write_transaction
from .delegation import get_perm_snapshot
from .doc_indexer import (
    DocIndexNode,
    TenantDocIndex,
    compute_proximity_from_positions,
    get_tenant_doc_index,
    jaccard_similarity_from_sets,
    tokenize_text,
)
from .middleware import strict_bool, strict_int

_ALLOWED_SORT_BY = frozenset({"score", "updated_at", "risk_weight", ""})
_ALLOWED_SORT_DIR = frozenset({"asc", "desc", ""})


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
    """执行合规文档检索：融合二级借调有效密级、独立 acl_epoch 隔离墙、增量倒排与剪枝去重。"""
    if not isinstance(query, str) or len(query) > MAX_QUERY_CHARS:
        raise ValueError("Query string exceeds maximum allowed length")
    if not isinstance(category, str) or len(category) > 128:
        raise ValueError("Invalid category filter")
    if not isinstance(tag_filter, str) or len(tag_filter) > 128:
        raise ValueError("Invalid tag_filter")

    norm_sort_by = str(sort_by or "")
    norm_sort_dir = str(sort_dir or "").lower()
    if norm_sort_by not in _ALLOWED_SORT_BY:
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    if norm_sort_dir not in _ALLOWED_SORT_DIR:
        raise ValueError(f"Unsupported sort_dir: {sort_dir}")

    lim_val = strict_int(limit, "limit")
    off_val = strict_int(offset, "offset")

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > MAX_QUERY_TERMS:
        raise ValueError("Query term count exceeds maximum budget")

    # 每次请求仅核验一次实时权限、隔离墙快照与组织链（零循环内重复查库）
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    perm_snap = get_perm_snapshot(db_path, caller.tenant_id)
    u_rec = perm_snap.users.get(caller.user_id)
    if u_rec is None or not u_rec.active:
        return {
            "tenant_id": caller.tenant_id,
            "total_matched": 0,
            "returned_count": 0,
            "items": [],
        }
    user_lineage = perm_snap.org_lineage.get(u_rec.org_node_id, (u_rec.org_node_id,))
    acl_snap = get_acl_snapshot(db_path, caller.tenant_id)

    hub = get_db_hub(db_path)
    doc_idx = get_tenant_doc_index(db_path, caller.tenant_id)

    with hub.tenant_doc_lock(caller.tenant_id):
        # 1. 利用倒排索引与分类/标签二级集合快速收敛候选文档 ID
        filter_sets: list[set[str]] = []
        if category:
            cat_ids = doc_idx.by_category.get(category)
            if not cat_ids:
                candidate_ids: set[str] | list[str] = ()
            else:
                filter_sets.append(cat_ids)
        if tag_filter and (not category or filter_sets):
            tag_ids = doc_idx.by_tag.get(tag_filter)
            if not tag_ids:
                candidate_ids = ()
            else:
                filter_sets.append(tag_ids)

        if (category and not filter_sets) or (tag_filter and len(filter_sets) < (2 if category else 1)):
            candidate_ids = ()
        elif query_terms:
            posting_hits: set[str] = set()
            postings_map = doc_idx.postings
            for qt in query_terms:
                pset = postings_map.get(qt)
                if pset:
                    posting_hits.update(pset)
            if not posting_hits:
                candidate_ids = ()
            else:
                for fset in filter_sets:
                    posting_hits.intersection_update(fset)
                candidate_ids = posting_hits
        else:
            if filter_sets:
                filter_sets.sort(key=len)
                base_set = set(filter_sets[0])
                for fset in filter_sets[1:]:
                    base_set.intersection_update(fset)
                candidate_ids = base_set
            else:
                candidate_ids = doc_idx.searchable_ids

        # 2. 密级与三级隔离墙过滤 + 精确 TF / 双指针词距 / O(1) 有效引用打分
        nodes_map = doc_idx.nodes
        cite_counts = doc_idx.valid_citation_count
        uid = caller.user_id
        has_acl_rules = bool(acl_snap.by_doc)

        scored_candidates: list[tuple[DocIndexNode, int, float]] = []
        for did in candidate_ids:
            node = nodes_map.get(did)
            if node is None or not node.is_searchable:
                continue
            if node.clearance_level > live_clearance:
                continue
            if has_acl_rules and acl_snap.is_blocked(uid, user_lineage, did):
                continue

            if query_terms:
                t_tf = node.title_tf
                b_pos = node.body_pos
                term_score = 0.0
                for qt in query_terms:
                    tc = t_tf.get(qt, 0)
                    bp = b_pos.get(qt)
                    bc = len(bp) if bp is not None else 0
                    if tc:
                        term_score += 3.5 * (tc if tc < 5 else 5)
                    if bc:
                        term_score += 1.0 * (bc if bc < 12 else 12)
                prox_bonus = compute_proximity_from_positions(b_pos, query_terms)
            else:
                term_score = 0.0
                prox_bonus = 0.0

            cite_cnt = cite_counts.get(did, 0)
            total_score = round(
                term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * node.risk_weight,
                4,
            )
            scored_candidates.append((node, cite_cnt, total_score))

        # 3. 确定性预排序：(-score, -updated_at, doc_id)
        scored_candidates.sort(key=lambda item: (-item[2], -item[0].updated_at, item[0].doc_id))

        # 4. 按归一化法规号分桶 + 集合大小比值剪枝（min_l / max_l < 0.70）执行近似修订簇折叠
        n_cand = len(scored_candidates)
        if deduplicate and n_cand > 0:
            reg_buckets: dict[str, list[int]] = {}
            for idx_pos, (node, _, _) in enumerate(scored_candidates):
                if node.canon_reg:
                    reg_buckets.setdefault(node.canon_reg, []).append(idx_pos)

            consumed = [False] * n_cand
            final_list: list[dict[str, Any]] = []
            for i in range(n_cand):
                if consumed[i]:
                    continue
                rep_node, rep_cite, rep_score = scored_candidates[i]
                cluster_size = 1
                creg = rep_node.canon_reg
                if creg:
                    bucket = reg_buckets[creg]
                    rep_tokens = rep_node.uniq_tokens
                    rep_len = rep_node.uniq_len
                    thresh = DEDUP_JACCARD_THRESHOLD
                    for j in bucket:
                        if j <= i or consumed[j]:
                            continue
                        cand_node = scored_candidates[j][0]
                        cand_len = cand_node.uniq_len
                        if rep_len == 0 and cand_len == 0:
                            consumed[j] = True
                            cluster_size += 1
                            continue
                        if rep_len == 0 or cand_len == 0:
                            continue
                        min_l = rep_len if rep_len < cand_len else cand_len
                        max_l = cand_len if rep_len < cand_len else rep_len
                        if (min_l / max_l) < thresh:
                            continue
                        inter_cnt = len(rep_tokens & cand_node.uniq_tokens)
                        union_cnt = rep_len + cand_len - inter_cnt
                        if union_cnt > 0 and (inter_cnt / union_cnt) >= thresh:
                            consumed[j] = True
                            cluster_size += 1

                final_list.append(
                    {
                        "doc_id": rep_node.doc_id,
                        "category": rep_node.category,
                        "regulation_code": rep_node.regulation_code,
                        "clearance_level": rep_node.clearance_level,
                        "risk_weight": rep_node.risk_weight,
                        "custom_tag": rep_node.custom_tag,
                        "title": rep_node.title,
                        "snippet": rep_node.snippet,
                        "citation_count": rep_cite,
                        "score": rep_score,
                        "updated_at": rep_node.updated_at,
                        "cluster_size": cluster_size,
                    }
                )
        else:
            final_list = [
                {
                    "doc_id": node.doc_id,
                    "category": node.category,
                    "regulation_code": node.regulation_code,
                    "clearance_level": node.clearance_level,
                    "risk_weight": node.risk_weight,
                    "custom_tag": node.custom_tag,
                    "title": node.title,
                    "snippet": node.snippet,
                    "citation_count": cite_cnt,
                    "score": total_score,
                    "updated_at": node.updated_at,
                    "cluster_size": 1,
                }
                for node, cite_cnt, total_score in scored_candidates
            ]

    reverse_flag = norm_sort_dir != "asc"
    sort_field = norm_sort_by if norm_sort_by in ("score", "updated_at", "risk_weight") else "score"
    if reverse_flag:
        final_list.sort(key=lambda d: (-d[sort_field], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_field], d["doc_id"]))

    total_matched = len(final_list)
    start_pos = max(0, off_val)
    if lim_val < 0:
        sliced = final_list[start_pos:]
    else:
        sliced = final_list[start_pos : start_pos + lim_val]

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
    """按文档 ID 列表批量获取完整合规文档（强制核验本租户、ACTIVE、未隔离、实时密级与三级隔离墙）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_IDS:
        raise ValueError("doc_ids exceeds maximum batch size")

    cleaned_ids: list[str] = []
    for raw_id in doc_ids:
        if not isinstance(raw_id, str) or not raw_id or len(raw_id) > 128:
            raise ValueError("Each doc_id must be a non-empty string within length limit")
        cleaned_ids.append(raw_id)

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    perm_snap = get_perm_snapshot(db_path, caller.tenant_id)
    u_rec = perm_snap.users.get(caller.user_id)
    if u_rec is None or not u_rec.active:
        return {"requested": len(cleaned_ids), "found": 0, "items": []}
    user_lineage = perm_snap.org_lineage.get(u_rec.org_node_id, (u_rec.org_node_id,))
    acl_snap = get_acl_snapshot(db_path, caller.tenant_id)

    unique_ids = list(dict.fromkeys(cleaned_ids))
    placeholders = ",".join("?" for _ in unique_ids)
    params = (caller.tenant_id, *unique_ids)

    with borrow_connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs "
            f"WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 AND doc_id IN ({placeholders})",
            params,
        ).fetchall()

    authorized_by_id: dict[str, dict[str, Any]] = {}
    for r in rows:
        did = str(r["doc_id"])
        cl = int(r["clearance_level"])
        if cl > live_clearance:
            continue
        if acl_snap.is_blocked(caller.user_id, user_lineage, did):
            continue
        authorized_by_id[did] = {
            "doc_id": did,
            "tenant_id": str(r["tenant_id"]),
            "category": str(r["category"]),
            "regulation_code": str(r["regulation_code"]),
            "clearance_level": cl,
            "risk_weight": int(r["risk_weight"]),
            "custom_tag": str(r["custom_tag"]),
            "title": str(r["title"]),
            "body": str(r["body"]),
            "updated_at": int(r["updated_at"]),
        }

    items = [authorized_by_id[did] for did in cleaned_ids if did in authorized_by_id]
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
    """紧急隔离或解封文档，并通过 reverse_dependents O(deg) 联动刷新引用计数。"""
    require_admin(caller)
    clean_doc_id = str(doc_id or "").strip()
    if not clean_doc_id or len(clean_doc_id) > 128:
        raise ValueError("Valid doc_id is required")
    q_bool = strict_bool(quarantined, "quarantined")
    q_val = 1 if q_bool else 0
    now_ts = int(caller.request_ts or int(time.time()))

    hub = get_db_hub(db_path)
    with hub.tenant_doc_lock(caller.tenant_id):
        with write_transaction(db_path) as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, clean_doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {clean_doc_id}")

        new_ep = hub.bump_doc_epoch(caller.tenant_id)
        cached_idx: TenantDocIndex | None = hub.doc_indices.get(caller.tenant_id)
        if cached_idx is not None and cached_idx.epoch == new_ep - 1:
            cached_idx.apply_quarantine(clean_doc_id, q_bool, now_ts, new_ep)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": clean_doc_id,
        "quarantined": q_bool,
        "updated_at": now_ts,
    }
