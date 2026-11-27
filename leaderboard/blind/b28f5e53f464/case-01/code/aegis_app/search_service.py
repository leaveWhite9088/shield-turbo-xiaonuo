# -*- coding: utf-8 -*-
"""企业合规文档多维检索、紧凑增量索引、双指针邻近度打分与剪枝双轨法规簇折叠服务。"""
from __future__ import annotations

from array import array
import time
from typing import Any

from .auth import (
    CallerContext,
    is_doc_blocked_by_acl,
    require_admin,
    resolve_effective_permissions,
)
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .doc_indexer import (
    compute_phrase_proximity_from_ids,
    jaccard_from_sorted_ids,
    tokenize_text,
)
from .runtime import CompactDocNode, GatewayRuntime, get_runtime
from .validation import strict_int

_ALLOWED_SORT_BY = frozenset({"score", "updated_at", "risk_weight"})
_ALLOWED_SORT_DIR = frozenset({"asc", "desc"})
_UNKNOWN_TERM_SENTINEL = 0xFFFFFFFF


def _get_doc_citation_count(
    db_path: str,
    tenant_id: str,
    doc_id: str,
    *,
    runtime: GatewayRuntime | None = None,
) -> int:
    """从租户增量索引返回文档当前有效的唯一引用源数量（隔离跨租户引用侧信道）。"""
    rt = runtime or get_runtime(db_path)
    doc_index = rt.get_doc_index(tenant_id)
    node = doc_index.docs_by_id.get(doc_id)
    if node is not None:
        return node.valid_citation_count
    return 0


def _is_blocked_fast(
    acl_rules_by_doc: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]],
    lineage: list[str],
    user_id: str,
    doc_id: str,
) -> bool:
    pair = acl_rules_by_doc.get(doc_id)
    if pair is None:
        return False
    user_map, org_map = pair
    u_effs = user_map.get(user_id)
    if u_effs:
        if "ALLOW" in u_effs:
            return False
        if "DENY" in u_effs:
            return True
    if not org_map:
        return False
    for node_id in lineage:
        effs = org_map.get(node_id)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False
    return False


def _has_adjacent_body_pair(hit_mask: int, num_terms: int) -> bool:
    if num_terms < 2:
        return False
    for idx in range(num_terms - 1):
        if ((hit_mask >> idx) & 1) and ((hit_mask >> (idx + 1)) & 1):
            return True
    return False


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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """执行合规文档检索：融合委托有效密级、独立隔离墙纪元、增量倒排与剪枝去重簇折叠。"""
    norm_sort_by = str(sort_by or "score").strip()
    norm_sort_dir = str(sort_dir or "desc").strip().lower()
    if norm_sort_by not in _ALLOWED_SORT_BY:
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    if norm_sort_dir not in _ALLOWED_SORT_DIR:
        raise ValueError(f"Unsupported sort_dir: {sort_dir}")

    lim = strict_int(limit, "limit", min_val=-1, max_val=10000)
    off = strict_int(offset, "offset", min_val=0)
    q_str = str(query or "")
    if len(q_str) > 2048:
        raise ValueError("Search query exceeds maximum allowed length")
    cat_filter = str(category or "").strip()
    tag_flt = str(tag_filter or "").strip()

    rt = runtime or get_runtime(db_path)
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
        runtime=rt,
    )
    perm_state = rt.get_perm_state(caller.tenant_id)
    u_info = perm_state.users.get(caller.user_id)
    if not u_info or u_info[3] != 1:
        return {
            "tenant_id": caller.tenant_id,
            "total_matched": 0,
            "returned_count": 0,
            "items": [],
        }
    lineage = perm_state.get_org_lineage(u_info[1])
    acl_rules_by_doc = rt.get_acl_state(caller.tenant_id).rules_by_doc

    query_terms = list(dict.fromkeys(tokenize_text(q_str)))
    num_q = len(query_terms)

    # 阶段 1：在单租户文档锁内利用紧凑倒排索引快速筛选候选节点（不触碰原始正文）
    matched_entries: list[list[Any]] = []
    missing_body_entries: list[list[Any]] = []
    q_term_ids: list[int] = []
    vocab_snapshot: dict[str, int] = {}

    doc_index = rt.get_doc_index(caller.tenant_id)
    with rt.doc_lock(caller.tenant_id):
        if query_terms:
            q_term_ids = [doc_index.vocab.get(t, -1) for t in query_terms]
            term_scores: dict[int, float] = {}
            body_masks: dict[int, int] = {}
            for q_idx, tid in enumerate(q_term_ids):
                if tid < 0:
                    continue
                plist = doc_index.postings.get(tid)
                if not plist:
                    continue
                bit = 1 << q_idx
                for d_int, packed in plist.items():
                    t_tf = packed >> 4
                    b_tf = packed & 0x0F
                    term_scores[d_int] = term_scores.get(d_int, 0.0) + (3.5 * t_tf + 1.0 * b_tf)
                    if b_tf > 0 and num_q >= 2:
                        body_masks[d_int] = body_masks.get(d_int, 0) | bit

            for d_int, t_score in term_scores.items():
                node = doc_index.docs_by_int.get(d_int)
                if node is None or not node.is_active_unquarantined():
                    continue
                if node.clearance_level > live_clearance:
                    continue
                if cat_filter and node.category != cat_filter:
                    continue
                if tag_flt and node.custom_tag != tag_flt:
                    continue
                if _is_blocked_fast(acl_rules_by_doc, lineage, caller.user_id, node.doc_id):
                    continue

                need_prox = num_q >= 2 and _has_adjacent_body_pair(body_masks.get(d_int, 0), num_q)
                cached_body: array | None = None
                if need_prox:
                    cached_body = doc_index.body_token_lru.get(node.doc_id)
                    if cached_body is not None:
                        doc_index.body_token_lru.move_to_end(node.doc_id)
                entry = [node, t_score, 0.0, cached_body, need_prox]
                matched_entries.append(entry)
                if need_prox and cached_body is None:
                    missing_body_entries.append(entry)
                    if not vocab_snapshot:
                        vocab_snapshot = dict(doc_index.vocab)
        else:
            for node in doc_index.docs_by_id.values():
                if not node.is_active_unquarantined():
                    continue
                if node.clearance_level > live_clearance:
                    continue
                if cat_filter and node.category != cat_filter:
                    continue
                if tag_flt and node.custom_tag != tag_flt:
                    continue
                if _is_blocked_fast(acl_rules_by_doc, lineage, caller.user_id, node.doc_id):
                    continue
                matched_entries.append([node, 0.0, 0.0, None, False])

    # 阶段 2：仅对 LRU 未命中且正文同时出现相邻查询词对的极少数文档按主键批量回表提取正文
    if missing_body_entries:
        fetched_bodies: dict[str, str] = {}
        missing_ids = [e[0].doc_id for e in missing_body_entries]
        with rt.connection() as conn:
            for start in range(0, len(missing_ids), 400):
                chunk = missing_ids[start : start + 400]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT doc_id, body FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
                    (caller.tenant_id, *chunk),
                ).fetchall()
                for r in rows:
                    fetched_bodies[str(r["doc_id"])] = str(r["body"])

        to_cache: list[tuple[str, array]] = []
        for entry in missing_body_entries:
            did = entry[0].doc_id
            raw_body = fetched_bodies.get(did, "")
            body_arr = array(
                "I",
                (vocab_snapshot.get(tok, _UNKNOWN_TERM_SENTINEL) for tok in tokenize_text(raw_body)),
            )
            entry[3] = body_arr
            to_cache.append((did, body_arr))

        if to_cache:
            with rt.doc_lock(caller.tenant_id):
                for did, body_arr in to_cache:
                    if did in doc_index.docs_by_id and did not in doc_index.body_token_lru:
                        doc_index._put_body_lru(did, body_arr)

    # 阶段 3：计算邻近度加分与最终相关度评分
    candidates: list[tuple[float, int, str, CompactDocNode]] = []
    for node, t_score, _, body_arr, need_prox in matched_entries:
        prox_bonus = (
            compute_phrase_proximity_from_ids(body_arr, q_term_ids)
            if (need_prox and body_arr is not None)
            else 0.0
        )
        total_score = round(
            t_score + prox_bonus + 0.25 * node.valid_citation_count + 0.1 * node.risk_weight,
            4,
        )
        candidates.append((total_score, node.updated_at, node.doc_id, node))

    candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))

    # 阶段 4：双轨法规编号分桶 + 集合大小剪枝 Jaccard 近似修订簇折叠
    clustered: list[tuple[float, int, str, CompactDocNode, int]] = []
    if deduplicate:
        reg_buckets: dict[str, list[int]] = {}
        for idx, cand in enumerate(candidates):
            canon = cand[3].canon_reg
            if canon:
                reg_buckets.setdefault(canon, []).append(idx)

        consumed = [False] * len(candidates)
        for i, cand_i in enumerate(candidates):
            if consumed[i]:
                continue
            score_i, upd_i, did_i, node_i = cand_i
            canon = node_i.canon_reg
            cluster_size = 1
            if canon:
                bucket = reg_buckets.get(canon, ())
                for j in bucket:
                    if j <= i or consumed[j]:
                        continue
                    node_j = candidates[j][3]
                    sim = jaccard_from_sorted_ids(
                        node_i.uniq_token_ids,
                        node_j.uniq_token_ids,
                        DEDUP_JACCARD_THRESHOLD,
                    )
                    if sim >= DEDUP_JACCARD_THRESHOLD:
                        consumed[j] = True
                        cluster_size += 1
            clustered.append((score_i, upd_i, did_i, node_i, cluster_size))
    else:
        clustered = [(s, u, did, n, 1) for s, u, did, n in candidates]

    reverse_flag = norm_sort_dir != "asc"
    if norm_sort_by == "score":
        if reverse_flag:
            clustered.sort(key=lambda x: (-x[0], x[2]))
        else:
            clustered.sort(key=lambda x: (x[0], x[2]))
    elif norm_sort_by == "updated_at":
        if reverse_flag:
            clustered.sort(key=lambda x: (-x[1], x[2]))
        else:
            clustered.sort(key=lambda x: (x[1], x[2]))
    else:  # risk_weight
        if reverse_flag:
            clustered.sort(key=lambda x: (-x[3].risk_weight, x[2]))
        else:
            clustered.sort(key=lambda x: (x[3].risk_weight, x[2]))

    total_matched = len(clustered)
    if lim < 0:
        sliced = clustered[off:]
    else:
        sliced = clustered[off : off + lim]

    items_out = [
        {
            "doc_id": node.doc_id,
            "category": node.category,
            "regulation_code": node.regulation_code,
            "clearance_level": node.clearance_level,
            "risk_weight": node.risk_weight,
            "custom_tag": node.custom_tag,
            "title": node.title,
            "snippet": node.snippet,
            "citation_count": node.valid_citation_count,
            "score": sc,
            "updated_at": upd,
            "cluster_size": csize,
        }
        for sc, upd, _, node, csize in sliced
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
    *,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """按文档 ID 列表批量获取当前租户内调用者有权访问的完整合规文档（强制隔离、密级与冲突墙校验）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > 500:
        raise ValueError("doc_ids batch size exceeds maximum allowed limit")

    clean_ids: list[str] = []
    for raw_id in doc_ids:
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise ValueError("Each doc_id must be a non-empty string")
        clean_ids.append(raw_id.strip())

    rt = runtime or get_runtime(db_path)
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
        runtime=rt,
    )

    unique_ids = list(dict.fromkeys(clean_ids))
    placeholders = ",".join("?" for _ in unique_ids)
    with rt.connection() as conn:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *unique_ids),
        ).fetchall()

    by_id = {str(r["doc_id"]): r for r in rows}
    items = []
    for did in clean_ids:
        r = by_id.get(did)
        if not r or r["status"] != "ACTIVE" or int(r["quarantined"]) != 0:
            continue
        if int(r["clearance_level"]) > live_clearance:
            continue
        if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, did, runtime=rt):
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    require_admin(caller)
    clean_doc_id = str(doc_id or "").strip()
    if not clean_doc_id:
        raise ValueError("doc_id is required")
    if not isinstance(quarantined, bool):
        raise ValueError("quarantined must be a boolean")

    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if quarantined else 0
    rt = runtime or get_runtime(db_path)

    with rt.doc_lock(caller.tenant_id):
        doc_index = rt.get_doc_index(caller.tenant_id)
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, clean_doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {clean_doc_id}")

        doc_index.apply_status_change(
            clean_doc_id,
            quarantined=q_val,
            updated_at=now_ts,
        )

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": clean_doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
