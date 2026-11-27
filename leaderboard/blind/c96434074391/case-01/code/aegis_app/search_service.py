# -*- coding: utf-8 -*-
"""企业合规文档多维倒排检索、双指针邻近度打分、比值剪枝法规簇折叠与密级/隔离墙管控服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import get_tenant_acl_state, is_doc_blocked_in_memory
from .auth import CallerContext, require_admin, resolve_effective_permissions
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    MAX_BATCH_GET_IDS,
    MAX_SEARCH_LIMIT,
    MAX_SEARCH_QUERY_LEN,
    MAX_SEARCH_QUERY_TERMS,
)
from .db import get_db_runtime
from .delegation import get_tenant_auth_state
from .doc_indexer import (
    compute_proximity_from_term_ids,
    get_tenant_doc_index,
    is_jaccard_cluster_match,
    tokenize_text,
)
from .middleware import strict_bool, strict_int

_ALLOWED_SORT_BY = frozenset({"", "score", "updated_at", "risk_weight"})
_ALLOWED_SORT_DIR = frozenset({"", "asc", "desc"})


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
    """执行合规文档检索：融合委托有效密级、三级利益冲突墙、双指针词距与比值剪枝法规号折叠。"""
    if not isinstance(query, str) or len(query) > MAX_SEARCH_QUERY_LEN:
        raise ValueError("Invalid or oversized search query")
    if not isinstance(category, str) or len(category) > 64:
        raise ValueError("Invalid category filter")
    if not isinstance(tag_filter, str) or len(tag_filter) > 128:
        raise ValueError("Invalid tag_filter")
    if not isinstance(sort_by, str) or sort_by not in _ALLOWED_SORT_BY:
        raise ValueError(f"Unsupported sort_by parameter: {sort_by!r}")
    norm_sort_dir = str(sort_dir).lower() if isinstance(sort_dir, str) else "__bad__"
    if norm_sort_dir not in _ALLOWED_SORT_DIR:
        raise ValueError(f"Unsupported sort_dir parameter: {sort_dir!r}")

    lim_val = strict_int(limit, "limit", min_val=-1, max_val=MAX_SEARCH_LIMIT)
    off_val = strict_int(offset, "offset", min_val=0, max_val=1_000_000)

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > MAX_SEARCH_QUERY_TERMS:
        raise ValueError("Too many distinct search terms in query")

    rt = get_db_runtime(db_path)
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    auth_state = get_tenant_auth_state(rt, caller.tenant_id)
    if auth_state is None:
        return {"tenant_id": caller.tenant_id, "total_matched": 0, "returned_count": 0, "items": []}
    u_rec = auth_state.users.get(caller.user_id)
    if u_rec is None or not u_rec.active:
        return {"tenant_id": caller.tenant_id, "total_matched": 0, "returned_count": 0, "items": []}
    org_lineage = auth_state.org_lineage.get(u_rec.org_node_id, (u_rec.org_node_id,))

    acl_state = get_tenant_acl_state(rt, caller.tenant_id)

    with rt.tenant_meta_lock(caller.tenant_id):
        doc_index = get_tenant_doc_index(rt, caller.tenant_id)

        # 1. 利用倒排索引与分类/标签二级集合缩小候选空间
        base_filter: set[str] | None = None
        if category:
            cat_docs = doc_index.by_category.get(category)
            if not cat_docs:
                return {"tenant_id": caller.tenant_id, "total_matched": 0, "returned_count": 0, "items": []}
            base_filter = set(cat_docs)

        if tag_filter:
            tag_docs = doc_index.by_tag.get(tag_filter)
            if not tag_docs:
                return {"tenant_id": caller.tenant_id, "total_matched": 0, "returned_count": 0, "items": []}
            if base_filter is None:
                base_filter = set(tag_docs)
            else:
                base_filter &= tag_docs
                if not base_filter:
                    return {"tenant_id": caller.tenant_id, "total_matched": 0, "returned_count": 0, "items": []}

        if query_terms:
            q_term_ids: list[int | None] = [doc_index.lookup_term_id(t) for t in query_terms]
            hit_doc_ids: set[str] = set()
            for tid in q_term_ids:
                if tid is not None:
                    post = doc_index.inverted.get(tid)
                    if post:
                        hit_doc_ids.update(post)
            if not hit_doc_ids:
                return {"tenant_id": caller.tenant_id, "total_matched": 0, "returned_count": 0, "items": []}
            candidate_ids = hit_doc_ids if base_filter is None else (hit_doc_ids & base_filter)
        else:
            q_term_ids = []
            candidate_ids = doc_index.active_searchable_ids if base_filter is None else (
                doc_index.active_searchable_ids & base_filter
            )

        # 紧凑元组候选: (-score, -updated_at, doc_id, score, CompactDocNode)
        cand_tuples: list[tuple[float, int, str, float, Any]] = []
        present_q_ids = [tid for tid in q_term_ids if tid is not None]

        for did in candidate_ids:
            node = doc_index.docs.get(did)
            if node is None or node.status != "ACTIVE" or node.quarantined:
                continue
            if node.clearance_level > live_clearance:
                continue
            if is_doc_blocked_in_memory(acl_state, caller.user_id, org_lineage, did):
                continue

            if query_terms:
                t_tf = node.title_tf
                b_pos = node.body_pos
                term_score = 0.0
                for tid in present_q_ids:
                    tc = t_tf.get(tid, 0)
                    bp = b_pos.get(tid)
                    bc = len(bp) if bp is not None else 0
                    if tc:
                        term_score += 3.5 * (tc if tc <= 5 else 5)
                    if bc:
                        term_score += 1.0 * (bc if bc <= 12 else 12)
                prox_bonus = compute_proximity_from_term_ids(b_pos, q_term_ids)
            else:
                term_score = 0.0
                prox_bonus = 0.0

            cite_cnt = node.valid_citation_count
            risk_w = node.risk_weight
            total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

            cand_tuples.append((-total_score, -node.updated_at, did, total_score, node))

        cand_tuples.sort()

        # 聚类阶段仅操作轻量元组 (node, score, cite_cnt, cluster_size)，延迟到分页切片后再分配输出字典
        kept_tuples: list[tuple[Any, float, int, int]] = []
        if deduplicate and cand_tuples:
            reg_buckets: dict[str, list[int]] = {}
            for idx, ct in enumerate(cand_tuples):
                creg = ct[4].canon_reg
                if creg:
                    reg_buckets.setdefault(creg, []).append(idx)

            consumed = [False] * len(cand_tuples)
            bucket_cursor: dict[str, int] = {}

            for i, ct_i in enumerate(cand_tuples):
                if consumed[i]:
                    continue
                rep_node = ct_i[4]
                rep_score = ct_i[3]
                cluster_size = 1
                creg = rep_node.canon_reg
                if creg:
                    b_indices = reg_buckets[creg]
                    start_pos = bucket_cursor.get(creg, 0)
                    while start_pos < len(b_indices) and b_indices[start_pos] <= i:
                        start_pos += 1
                    bucket_cursor[creg] = start_pos
                    rep_terms = rep_node.uniq_terms
                    for b_pos_idx in range(start_pos, len(b_indices)):
                        j = b_indices[b_pos_idx]
                        if consumed[j]:
                            continue
                        if is_jaccard_cluster_match(
                            rep_terms,
                            cand_tuples[j][4].uniq_terms,
                            DEDUP_JACCARD_THRESHOLD,
                        ):
                            consumed[j] = True
                            cluster_size += 1
                kept_tuples.append((rep_node, rep_score, rep_node.valid_citation_count, cluster_size))
        else:
            for ct in cand_tuples:
                nd = ct[4]
                kept_tuples.append((nd, ct[3], nd.valid_citation_count, 1))

    reverse_flag = norm_sort_dir != "asc"
    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
    if sort_field == "score":
        if reverse_flag:
            kept_tuples.sort(key=lambda t: (-t[1], t[0].doc_id))
        else:
            kept_tuples.sort(key=lambda t: (t[1], t[0].doc_id))
    elif sort_field == "updated_at":
        if reverse_flag:
            kept_tuples.sort(key=lambda t: (-t[0].updated_at, t[0].doc_id))
        else:
            kept_tuples.sort(key=lambda t: (t[0].updated_at, t[0].doc_id))
    else:
        if reverse_flag:
            kept_tuples.sort(key=lambda t: (-t[0].risk_weight, t[0].doc_id))
        else:
            kept_tuples.sort(key=lambda t: (t[0].risk_weight, t[0].doc_id))

    total_matched = len(kept_tuples)
    if lim_val < 0:
        sliced_tuples = kept_tuples[off_val:]
    else:
        sliced_tuples = kept_tuples[off_val: off_val + lim_val]

    items_out = [
        {
            "doc_id": nd.doc_id,
            "category": nd.category,
            "regulation_code": nd.regulation_code,
            "clearance_level": nd.clearance_level,
            "risk_weight": nd.risk_weight,
            "custom_tag": nd.custom_tag,
            "title": nd.title,
            "snippet": nd.snippet,
            "citation_count": cite_c,
            "score": sc,
            "updated_at": nd.updated_at,
            "cluster_size": c_sz,
        }
        for nd, sc, cite_c, c_sz in sliced_tuples
    ]
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
    """按文档 ID 列表批量获取调用者有权访问的完整文档（严格执行租户、状态、隔离、密级与隔离墙五重校验）。"""
    if not isinstance(doc_ids, list) or len(doc_ids) == 0:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_IDS:
        raise ValueError(f"doc_ids length exceeds maximum batch limit ({MAX_BATCH_GET_IDS})")

    clean_ids: list[str] = []
    for raw_id in doc_ids:
        if not isinstance(raw_id, str) or not raw_id.strip() or len(raw_id) > 128:
            raise ValueError("Each doc_id in doc_ids must be a valid non-empty string")
        clean_ids.append(raw_id.strip())

    rt = get_db_runtime(db_path)
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    auth_state = get_tenant_auth_state(rt, caller.tenant_id)
    if auth_state is None:
        return {"requested": len(clean_ids), "found": 0, "items": []}
    u_rec = auth_state.users.get(caller.user_id)
    if u_rec is None or not u_rec.active:
        return {"requested": len(clean_ids), "found": 0, "items": []}
    org_lineage = auth_state.org_lineage.get(u_rec.org_node_id, (u_rec.org_node_id,))
    acl_state = get_tenant_acl_state(rt, caller.tenant_id)

    unique_query_ids = list(dict.fromkeys(clean_ids))
    placeholders = ",".join("?" for _ in unique_query_ids)
    sql = (
        "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
        "risk_weight, custom_tag, title, body, status, quarantined, updated_at "
        f"FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 "
        f"AND clearance_level <= ? AND doc_id IN ({placeholders})"
    )
    params = (caller.tenant_id, live_clearance, *unique_query_ids)
    with rt.read_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    by_id = {}
    for r in rows:
        did = str(r["doc_id"])
        if not is_doc_blocked_in_memory(acl_state, caller.user_id, org_lineage, did):
            by_id[did] = r

    items = []
    for did in clean_ids:
        r = by_id.get(did)
        if r is None:
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
    require_admin(caller)
    q_bool = strict_bool(quarantined, "quarantined")
    if not isinstance(doc_id, str) or not doc_id.strip() or len(doc_id) > 128:
        raise ValueError("Valid doc_id is required")
    norm_doc = doc_id.strip()
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if q_bool else 0

    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(caller.tenant_id):
        doc_index = get_tenant_doc_index(rt, caller.tenant_id)
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, norm_doc),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {norm_doc}")
        doc_index.apply_quarantine(norm_doc, q_bool, now_ts)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": norm_doc,
        "quarantined": q_bool,
        "updated_at": now_ts,
    }
