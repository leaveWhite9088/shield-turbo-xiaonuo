# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import get_acl_index, get_org_cache
from .auth import (
    CallerContext,
    require_admin,
    resolve_effective_permissions,
)
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .doc_indexer import (
    TenantDocIndex,
    _CompactDocNode,
    compute_phrase_proximity_bonus_from_positions,
    get_doc_index,
    jaccard_similarity_sets,
    tokenize_text,
)
from .middleware import parse_strict_bool, parse_strict_int
from .runtime import get_runtime

_VALID_SORT_FIELDS = frozenset({"score", "updated_at", "risk_weight"})
_VALID_SORT_DIRS = frozenset({"asc", "desc"})
MAX_QUERY_LEN = 1024
MAX_QUERY_TERMS = 32
MAX_BATCH_GET_IDS = 200


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    """统计文档当前有效的唯一引用源数量（全参数化 + 严格同租户隔离，杜绝二阶 SQLi 与跨租户侧信道）。"""
    rt = get_runtime(db_path)
    with rt.read_conn() as conn:
        rows = conn.execute(
            "SELECT cited_by_ref FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchall()
        seen_refs: set[str] = set()
        internal_refs: list[str] = []
        valid_cnt = 0
        for r in rows:
            ref = str(r["cited_by_ref"] or "").strip()
            if not ref or ref == doc_id or ref in seen_refs:
                continue
            seen_refs.add(ref)
            if ref.startswith("doc_"):
                internal_refs.append(ref)
            else:
                valid_cnt += 1

        if internal_refs:
            placeholders = ",".join("?" for _ in internal_refs)
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM compliance_docs "
                f"WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 "
                f"AND doc_id IN ({placeholders})",
                (tenant_id, *internal_refs),
            ).fetchone()
            valid_cnt += int(row["cnt"]) if row else 0
        return valid_cnt


def _deduplicate_candidates(
    candidates: list[tuple[dict[str, Any], _CompactDocNode]],
) -> list[dict[str, Any]]:
    """按归一化法规编号分桶 + 集合大小比值剪枝执行 Jaccard >= 0.70 近似修订簇折叠。"""
    n = len(candidates)
    if n == 0:
        return []

    consumed = [False] * n
    reg_buckets: dict[str, list[int]] = {}
    for idx, (_, node) in enumerate(candidates):
        if node.canon_reg:
            reg_buckets.setdefault(node.canon_reg, []).append(idx)

    # 记录每个文档在其 canon_reg 桶中的位置，便于仅向后扫描同桶候选
    pos_in_bucket: dict[int, int] = {}
    for indices in reg_buckets.values():
        for pos, idx in enumerate(indices):
            pos_in_bucket[idx] = pos

    kept: list[dict[str, Any]] = []
    for i in range(n):
        if consumed[i]:
            continue
        rep_item, rep_node = candidates[i]
        rep = dict(rep_item)
        cluster_size = 1
        creg = rep_node.canon_reg
        if creg:
            bucket = reg_buckets[creg]
            start_pos = pos_in_bucket[i] + 1
            rep_tokens = rep_node.token_ids
            for b_pos in range(start_pos, len(bucket)):
                j = bucket[b_pos]
                if consumed[j]:
                    continue
                cand_tokens = candidates[j][1].token_ids
                sim = jaccard_similarity_sets(
                    rep_tokens,
                    cand_tokens,
                    threshold=DEDUP_JACCARD_THRESHOLD,
                )
                if sim >= DEDUP_JACCARD_THRESHOLD:
                    consumed[j] = True
                    cluster_size += 1
        rep["cluster_size"] = cluster_size
        kept.append(rep)
    return kept


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
    """基于紧凑内存倒排索引执行合规文档检索，融合实时借调密级、三级隔离墙、双指针词距与双轨法规折叠。"""
    if not isinstance(query, str) or len(query) > MAX_QUERY_LEN:
        raise ValueError("Query string exceeds maximum length limit")
    if not isinstance(category, str) or len(category) > 64:
        raise ValueError("Invalid category filter")
    if not isinstance(tag_filter, str) or len(tag_filter) > 128:
        raise ValueError("Invalid tag_filter")

    norm_sort_by = str(sort_by or "score").strip().lower()
    norm_sort_dir = str(sort_dir or "desc").strip().lower()
    if norm_sort_by not in _VALID_SORT_FIELDS:
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    if norm_sort_dir not in _VALID_SORT_DIRS:
        raise ValueError(f"Unsupported sort_dir: {sort_dir}")

    safe_limit = parse_strict_int(limit, "limit", default=DEFAULT_PAGE_LIMIT)
    safe_offset = parse_strict_int(offset, "offset", default=0, min_val=0)

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > MAX_QUERY_TERMS:
        raise ValueError(f"Query contains too many distinct terms (max {MAX_QUERY_TERMS})")

    # 实时核验调用者有效密级（自然到期零写自动降级、源头撤权瞬间级联失效）
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    org_lineage = get_org_cache(db_path, caller.tenant_id).get_lineage(caller.org_node_id)

    rt = get_runtime(db_path)
    doc_idx = get_doc_index(db_path, caller.tenant_id)
    acl_idx = get_acl_index(db_path, caller.tenant_id)
    sc = rt.search_cache(caller.tenant_id)

    # 固定单向锁序 doc_lock -> acl_lock 读取一致快照与解耦纪元
    with rt.doc_lock(caller.tenant_id):
        with rt.acl_lock(caller.tenant_id):
            ep = rt.epochs(caller.tenant_id)
            cache_key = (
                ep.doc_epoch,
                ep.acl_epoch,
                caller.user_id,
                live_clearance,
                tuple(query_terms),
                category,
                tag_filter,
                bool(deduplicate),
                norm_sort_by,
                norm_sort_dir,
                safe_limit,
                safe_offset,
            )
            cached = sc.get(cache_key)
            if cached is not None:
                return {
                    "tenant_id": cached["tenant_id"],
                    "total_matched": cached["total_matched"],
                    "returned_count": cached["returned_count"],
                    "items": [dict(x) for x in cached["items"]],
                }

            # 1. 倒排集合候选召回
            if query_terms:
                term_ids = doc_idx.lookup_term_ids(query_terms)
                cand_ids: set[str] = set()
                for tid in term_ids:
                    if tid >= 0:
                        p = doc_idx.postings.get(tid)
                        if p:
                            cand_ids.update(p)
            else:
                term_ids = []
                cand_ids = set(doc_idx.active_docs)

            if category and cand_ids:
                cat_set = doc_idx.by_category.get(category)
                if not cat_set:
                    cand_ids.clear()
                else:
                    cand_ids &= cat_set

            if tag_filter and cand_ids:
                tag_set = doc_idx.by_tag.get(tag_filter)
                if not tag_set:
                    cand_ids.clear()
                else:
                    cand_ids &= tag_set

            # 2. 权限密级 + 三级隔离墙过滤 + 相关性/双指针词距/有效引用打分
            scored_candidates: list[tuple[dict[str, Any], _CompactDocNode]] = []
            nodes = doc_idx.nodes
            has_query = bool(query_terms)
            for did in cand_ids:
                node = nodes.get(did)
                if node is None:
                    continue
                if node.clearance_level > live_clearance:
                    continue
                if acl_idx.is_blocked(caller.user_id, org_lineage, did):
                    continue

                if has_query:
                    term_score = 0.0
                    ttf = node.title_tf
                    bpos = node.body_pos
                    for tid in term_ids:
                        if tid < 0:
                            continue
                        tc = ttf.get(tid, 0)
                        bp = bpos.get(tid)
                        bc = len(bp) if bp is not None else 0
                        if tc > 0 or bc > 0:
                            term_score += 3.5 * (tc if tc <= 5 else 5) + 1.0 * (bc if bc <= 12 else 12)
                    prox_bonus = compute_phrase_proximity_bonus_from_positions(bpos, term_ids)
                else:
                    term_score = 0.0
                    prox_bonus = 0.0

                total_score = round(
                    term_score + prox_bonus + 0.25 * node.citation_count + 0.1 * node.risk_weight,
                    4,
                )
                scored_candidates.append(
                    (
                        {
                            "doc_id": node.doc_id,
                            "category": node.category,
                            "regulation_code": node.regulation_code,
                            "clearance_level": node.clearance_level,
                            "risk_weight": node.risk_weight,
                            "custom_tag": node.custom_tag,
                            "title": node.title,
                            "snippet": node.snippet,
                            "citation_count": node.citation_count,
                            "score": total_score,
                            "updated_at": node.updated_at,
                        },
                        node,
                    )
                )

            # 3. 折叠前稳定排序 + 双轨法规近似修订簇折叠
            scored_candidates.sort(
                key=lambda pair: (-pair[0]["score"], -pair[0]["updated_at"], pair[0]["doc_id"])
            )

            if deduplicate:
                final_list = _deduplicate_candidates(scored_candidates)
            else:
                final_list = []
                for item, _ in scored_candidates:
                    item["cluster_size"] = 1
                    final_list.append(item)

            # 4. 最终排序与分页切片
            reverse_flag = norm_sort_dir != "asc"
            if reverse_flag:
                final_list.sort(key=lambda d: (-d[norm_sort_by], d["doc_id"]))
            else:
                final_list.sort(key=lambda d: (d[norm_sort_by], d["doc_id"]))

            total_matched = len(final_list)
            if safe_limit < 0:
                sliced = final_list[safe_offset:]
            else:
                sliced = final_list[safe_offset: safe_offset + safe_limit]

            result = {
                "tenant_id": caller.tenant_id,
                "total_matched": total_matched,
                "returned_count": len(sliced),
                "items": sliced,
            }
            sc.put(
                cache_key,
                {
                    "tenant_id": result["tenant_id"],
                    "total_matched": result["total_matched"],
                    "returned_count": result["returned_count"],
                    "items": [dict(x) for x in sliced],
                },
            )
            return result


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取完整合规文档（强制全维度租户/状态/隔离/密级/利益冲突墙鉴权）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_IDS:
        raise ValueError(f"doc_ids count exceeds limit ({MAX_BATCH_GET_IDS})")

    cleaned_ids: list[str] = []
    for raw_id in doc_ids:
        if not isinstance(raw_id, str) or not raw_id.strip() or len(raw_id) > 128:
            raise ValueError("Each doc_id must be a non-empty string")
        cleaned_ids.append(raw_id.strip())

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    org_lineage = get_org_cache(db_path, caller.tenant_id).get_lineage(caller.org_node_id)
    rt = get_runtime(db_path)
    acl_idx = get_acl_index(db_path, caller.tenant_id)

    unique_ids = list(dict.fromkeys(cleaned_ids))
    placeholders = ",".join("?" for _ in unique_ids)
    with rt.read_conn() as conn:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs "
            f"WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 "
            f"AND doc_id IN ({placeholders})",
            (caller.tenant_id, *unique_ids),
        ).fetchall()

    by_id = {str(r["doc_id"]): r for r in rows}
    items = []
    with rt.acl_lock(caller.tenant_id):
        for did in cleaned_ids:
            r = by_id.get(did)
            if not r:
                continue
            if int(r["clearance_level"]) > live_clearance:
                continue
            if acl_idx.is_blocked(caller.user_id, org_lineage, did):
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
    """紧急隔离或解除隔离文档，单篇增量更新倒排表并 O(deg) 联动内部引用计数。"""
    require_admin(caller)
    norm_doc_id = str(doc_id or "").strip()
    if not norm_doc_id:
        raise ValueError("doc_id is required")
    q_bool = parse_strict_bool(quarantined, "quarantined")
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if q_bool else 0

    rt = get_runtime(db_path)
    with rt.doc_lock(caller.tenant_id):
        with rt.write_tx() as conn:
            row = conn.execute(
                "SELECT status FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (caller.tenant_id, norm_doc_id),
            ).fetchone()
            if not row:
                raise LookupError(f"Document not found in tenant: {norm_doc_id}")
            doc_status = str(row["status"])
            conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, norm_doc_id),
            )

        now_valid = doc_status == "ACTIVE" and q_val == 0
        doc_idx: TenantDocIndex | None = rt.doc_indices.get(caller.tenant_id)
        if doc_idx is not None:
            doc_idx.apply_status_change(
                rt,
                doc_id=norm_doc_id,
                now_valid=now_valid,
                updated_at=now_ts,
            )
        rt.epochs(caller.tenant_id).doc_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": norm_doc_id,
        "quarantined": q_bool,
        "updated_at": now_ts,
    }
