# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。

性能契约：
- 检索全程走进程内紧凑倒排索引（index_cache），单篇 upsert/retire/quarantine 仅做
  单篇增量更新，绝不整库重建；
- 调用者有效权限（含 1~2 跳借调）每次检索仅解析一次（原版逐文档重复解析）；
- 利益冲突墙基于 acl 纪元缓存一次构建、O(1) 逐文档裁决（原版逐文档逐节点查库）；
- 有效引用计数基于反向依赖图脏标记惰性重算（原版逐文档逐引用查库）；
- 近似去重增加集合大小比值剪枝（min/max < 0.70 直接跳过 Jaccard 计算）；
- 全部 SQL 参数化，零字符串拼接注入。
"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import evaluate_doc_wall_cached
from .auth import (
    CallerContext,
    require_admin,
    resolve_effective_permissions,
)
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    MAX_DOC_IDS_BATCH,
)
from .db import open_connection
from .doc_indexer import (
    compute_phrase_proximity_bonus_from_positions,
    jaccard_similarity_from_sets,
    min_len_ratio_prunable,
)
from .index_cache import get_state
from .legacy_compat import canonicalize_regulation_code


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
    state = get_state(db_path)
    tstate = state.tenant(caller.tenant_id)
    tstate.ensure_docs(db_path)

    # 有效密级（含 1~2 跳借调）每次检索只解析一次
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )

    with tstate.lock:
        entries_snapshot = list(tstate.docs.values())
    wall_rules = tstate.wall_rules(db_path)
    user_row = tstate.users(db_path).get(caller.user_id)
    user_org_node = user_row["org_node_id"] if user_row else ""

    query_terms = list(dict.fromkeys(tokenize(query)))

    candidates: list[dict[str, Any]] = []
    for entry in entries_snapshot:
        if not entry.searchable:
            continue
        if category and entry.category != category:
            continue
        if tag_filter and entry.custom_tag != tag_filter:
            continue
        if entry.clearance_level > live_clearance:
            continue
        if evaluate_doc_wall_cached(db_path, wall_rules, tstate, caller.user_id, user_org_node, entry.doc_id):
            continue

        title_tf = entry.title_tf
        positions = entry.body_positions
        if query_terms:
            hit_any = any((t in title_tf or t in positions) for t in query_terms)
            if not hit_any:
                continue
            term_score = sum(
                3.5 * min(title_tf.get(t, 0), 5) + 1.0 * min(len(positions.get(t, ())), 12)
                for t in query_terms
            )
            prox_bonus = compute_phrase_proximity_bonus_from_positions(positions, query_terms)
        else:
            term_score = 0.0
            prox_bonus = 0.0

        cite_cnt = tstate.citation_count(entry.doc_id)
        risk_w = entry.risk_weight
        total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

        candidates.append(
            {
                "doc_id": entry.doc_id,
                "category": entry.category,
                "regulation_code": entry.regulation_code,
                "_canon_reg": entry.canon_reg,
                "clearance_level": entry.clearance_level,
                "risk_weight": risk_w,
                "custom_tag": entry.custom_tag,
                "title": entry.title,
                "snippet": entry.snippet,
                "citation_count": cite_cnt,
                "score": total_score,
                "updated_at": entry.updated_at,
                "_uniq": entry.uniq_tokens,
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
            rep_uniq = rep["_uniq"]
            rep_canon = rep["_canon_reg"]
            cluster_size = 1
            for j in range(i + 1, len(candidates)):
                if consumed[j]:
                    continue
                cand = candidates[j]
                same_reg = bool(rep_canon) and rep_canon == cand["_canon_reg"]
                if not same_reg:
                    # 原版在 canon 不一致时也计算 Jaccard 但从不使用其结果——安全跳过
                    continue
                # 集合大小比值剪枝：Jaccard <= min/max，比值不足阈值必然不可折叠
                if min_len_ratio_prunable(len(rep_uniq), len(cand["_uniq"]), DEDUP_JACCARD_THRESHOLD):
                    continue
                if jaccard_similarity_from_sets(rep_uniq, cand["_uniq"]) >= DEDUP_JACCARD_THRESHOLD:
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


def tokenize(text: str) -> list[str]:
    from .doc_indexer import tokenize_text as _tok

    return _tok(text)


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取完整合规文档内容（严格租户/状态/隔离/密级/利益冲突墙约束）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_DOC_IDS_BATCH:
        raise ValueError(f"doc_ids exceeds maximum batch size of {MAX_DOC_IDS_BATCH}")
    normalized = [str(did) for did in doc_ids]

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    state = get_state(db_path)
    tstate = state.tenant(caller.tenant_id)
    wall_rules = tstate.wall_rules(db_path)
    user_row = tstate.users(db_path).get(caller.user_id)
    if not user_row or not user_row["active"]:
        raise LookupError("Operator not found in tenant")
    user_org_node = user_row["org_node_id"]

    placeholders = ",".join("?" for _ in normalized)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *normalized),
        ).fetchall()
    finally:
        conn.close()

    by_id = {r["doc_id"]: r for r in rows}
    items = []
    for did in normalized:
        r = by_id.get(did)
        if not r or r["status"] != "ACTIVE" or int(r["quarantined"]) != 0:
            continue
        if int(r["clearance_level"]) > live_clearance:
            continue
        if evaluate_doc_wall_cached(db_path, wall_rules, tstate, caller.user_id, user_org_node, did):
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

    # 单篇增量：翻转隔离状态并沿反向依赖图脏标记被引用方计数
    state = get_state(db_path)
    state.tenant(caller.tenant_id).apply_quarantine(doc_id, q_val)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
