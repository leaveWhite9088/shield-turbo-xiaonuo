# -*- coding: utf-8 -*-
"""基于租户增量倒排的合规检索、近似修订簇折叠与全约束批量读取。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import acl_rows_by_doc, decide_wall, get_org_lineage
from .auth import CallerContext, require_admin
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import open_connection
from .doc_indexer import (
    DocEntry,
    compute_phrase_proximity_bonus,
    get_tenant_doc_index,
    jaccard_similarity_from_sets,
    tokenize_text,
)
from .runtime import RUNTIME
from .security import bounded_text, strict_bool, strict_int


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    index = get_tenant_doc_index(db_path, tenant_id)
    with index.lock:
        index.ensure_loaded()
        entry = index.entries.get(doc_id)
        return entry.citation_count if entry else 0


def _candidate_dict(entry: DocEntry, query_ids: list[int]) -> dict[str, Any]:
    if query_ids:
        term_score = sum(
            3.5 * min(entry.title_counts.get(token_id, 0), 5)
            + 1.0 * min(entry.body_counts.get(token_id, 0), 12)
            for token_id in query_ids
        )
        proximity = compute_phrase_proximity_bonus(entry.body_tokens, query_ids)
    else:
        term_score = proximity = 0.0
    score = round(term_score + proximity + 0.25 * entry.citation_count + 0.1 * entry.risk_weight, 4)
    return {
        "doc_id": entry.doc_id,
        "category": entry.category,
        "regulation_code": entry.regulation_code,
        "_canon_reg": entry.canon_reg,
        "clearance_level": entry.clearance_level,
        "risk_weight": entry.risk_weight,
        "custom_tag": entry.custom_tag,
        "title": entry.title,
        "snippet": entry.snippet,
        "citation_count": entry.citation_count,
        "score": score,
        "updated_at": entry.updated_at,
        "_tokens": entry.token_set,
    }


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
    query = bounded_text(query, "q", max_length=4096, allow_empty=True)
    category = bounded_text(category, "category", max_length=32, allow_empty=True)
    tag_filter = bounded_text(tag_filter, "tag_filter", max_length=128, allow_empty=True)
    limit = strict_int(limit, "limit", minimum=-1, maximum=500)
    offset = strict_int(offset, "offset", minimum=0, maximum=1_000_000)
    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > 32:
        raise ValueError("Query contains too many distinct terms")
    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
    reverse = str(sort_dir).lower() != "asc"

    index = get_tenant_doc_index(db_path, caller.tenant_id)
    lineage = get_org_lineage(db_path, caller.tenant_id, caller.org_node_id)
    with index.lock:
        entries = index.candidates(query_terms, category, tag_filter)
        query_ids = [index.token_ids.get(term, -1) for term in query_terms]
        acl_by_doc = acl_rows_by_doc(db_path, caller.tenant_id)
        candidates: list[dict[str, Any]] = []
        for entry in entries:
            if entry.clearance_level > caller.max_clearance:
                continue
            if decide_wall(
                user_id=caller.user_id,
                lineage=lineage,
                acl_rows=acl_by_doc.get(entry.doc_id, ()),
            ):
                continue
            candidates.append(_candidate_dict(entry, query_ids))

    # 与原实现一致：先按综合分确定每簇代表，再仅与代表比较，不做传递并查集。
    candidates.sort(key=lambda item: (-item["score"], -item["updated_at"], item["doc_id"]))
    if deduplicate:
        by_regulation: dict[str, list[int]] = {}
        for position, item in enumerate(candidates):
            if item["_canon_reg"]:
                by_regulation.setdefault(item["_canon_reg"], []).append(position)
        consumed = [False] * len(candidates)
        final_list: list[dict[str, Any]] = []
        for i, representative in enumerate(candidates):
            if consumed[i]:
                continue
            cluster_size = 1
            rep_tokens = representative["_tokens"]
            for j in by_regulation.get(representative["_canon_reg"], ()):
                if j <= i or consumed[j]:
                    continue
                other = candidates[j]
                other_tokens = other["_tokens"]
                # |A∩B|/|A∪B| 不超过集合大小比，可安全剪枝且零精度损失。
                larger = max(len(rep_tokens), len(other_tokens))
                smaller = min(len(rep_tokens), len(other_tokens))
                if larger and smaller / larger < DEDUP_JACCARD_THRESHOLD:
                    continue
                if jaccard_similarity_from_sets(rep_tokens, other_tokens) >= DEDUP_JACCARD_THRESHOLD:
                    consumed[j] = True
                    cluster_size += 1
            copied = dict(representative)
            copied["cluster_size"] = cluster_size
            final_list.append(copied)
    else:
        final_list = [dict(item, cluster_size=1) for item in candidates]

    if reverse:
        final_list.sort(key=lambda item: (-item[sort_field], item["doc_id"]))
    else:
        final_list.sort(key=lambda item: (item[sort_field], item["doc_id"]))
    start = max(0, offset)
    sliced = final_list[start:] if limit < 0 else final_list[start:start + limit]
    items = [{key: value for key, value in item.items() if not key.startswith("_")} for item in sliced]
    return {
        "tenant_id": caller.tenant_id,
        "total_matched": len(final_list),
        "returned_count": len(items),
        "items": items,
    }


def batch_get_documents(db_path: str, caller: CallerContext, doc_ids: list[str]) -> dict[str, Any]:
    if not isinstance(doc_ids, list) or not doc_ids or len(doc_ids) > 100:
        raise ValueError("doc_ids must be a non-empty list with at most 100 entries")
    normalized = [bounded_text(doc_id, "doc_id", max_length=128) for doc_id in doc_ids]
    placeholders = ",".join("?" for _ in normalized)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
            f"custom_tag, title, body, status, quarantined, updated_at FROM compliance_docs "
            f"WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *normalized),
        ).fetchall()
    finally:
        conn.close()
    by_id = {row["doc_id"]: row for row in rows}
    lineage = get_org_lineage(db_path, caller.tenant_id, caller.org_node_id)
    acl_by_doc = acl_rows_by_doc(db_path, caller.tenant_id)
    items: list[dict[str, Any]] = []
    for doc_id in normalized:
        row = by_id.get(doc_id)
        if not row or row["status"] != "ACTIVE" or row["quarantined"]:
            continue
        if int(row["clearance_level"]) > caller.max_clearance:
            continue
        if decide_wall(
            user_id=caller.user_id, lineage=lineage,
            acl_rows=acl_by_doc.get(doc_id, ()),
        ):
            continue
        items.append({
            "doc_id": row["doc_id"],
            "tenant_id": row["tenant_id"],
            "category": row["category"],
            "regulation_code": row["regulation_code"],
            "clearance_level": int(row["clearance_level"]),
            "risk_weight": int(row["risk_weight"]),
            "custom_tag": row["custom_tag"],
            "title": row["title"],
            "body": row["body"],
            "updated_at": int(row["updated_at"]),
        })
    return {"requested": len(normalized), "found": len(items), "items": items}


def set_document_quarantine(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    quarantined: bool,
) -> dict[str, Any]:
    require_admin(caller)
    doc_id = bounded_text(doc_id, "doc_id", max_length=128)
    quarantined = strict_bool(quarantined, "quarantined")
    now_ts = caller.request_ts or int(time.time())
    index = get_tenant_doc_index(db_path, caller.tenant_id)
    with index.lock:
        index.ensure_loaded()
        with RUNTIME.tenant_write(db_path, caller.tenant_id):
            conn = open_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ?",
                    (int(quarantined), now_ts, caller.tenant_id, doc_id),
                )
                if cursor.rowcount == 0:
                    raise LookupError("Document not found in tenant")
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            index.set_state(doc_id, quarantined=quarantined, updated_at=now_ts)
    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": quarantined,
        "updated_at": now_ts,
    }
