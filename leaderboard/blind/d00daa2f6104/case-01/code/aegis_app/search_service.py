# -*- coding: utf-8 -*-
"""基于紧凑增量索引的多维合规检索与安全批量取文。"""
from __future__ import annotations

import time
from typing import Any

from .acl_wall import get_wall_snapshot
from .auth import CallerContext, require_admin
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import open_connection
from .doc_indexer import (
    compute_positions_proximity_bonus,
    get_document_index,
    jaccard_similarity_sets,
    tokenize_text,
)
from .runtime import bounded_text


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    index = get_document_index(db_path, tenant_id)
    with index.lock:
        index.ensure_loaded()
        node = index.docs.get(doc_id)
        return int(node.citation_count) if node else 0


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
    if not isinstance(query, str) or len(query) > 8192:
        raise ValueError("query is too long")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit > 500:
        raise ValueError("limit must be an integer no greater than 500")
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 1_000_000:
        raise ValueError("offset is outside the supported range")
    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > 64:
        raise ValueError("Too many query terms")
    category = bounded_text(category, "category", 64, allow_empty=True)
    tag_filter = bounded_text(tag_filter, "tag_filter", 128, allow_empty=True)
    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
    reverse_flag = str(sort_dir).lower() != "asc"

    index = get_document_index(db_path, caller.tenant_id)
    wall = get_wall_snapshot(db_path, caller.tenant_id)
    candidates: list[dict[str, Any]] = []
    with index.lock:
        index.ensure_loaded()
        if query_terms:
            candidate_ids: set[str] = set()
            for term in query_terms:
                candidate_ids.update(index.term_docs.get(term, ()))
            nodes = (index.docs[doc_id] for doc_id in candidate_ids)
        else:
            nodes = iter(index.docs.values())
        for node in nodes:
            if node.status != "ACTIVE" or node.quarantined:
                continue
            if category and node.category != category:
                continue
            if tag_filter and node.custom_tag != tag_filter:
                continue
            if node.clearance_level > caller.max_clearance:
                continue
            if wall.blocked(caller.user_id, caller.org_node_id, node.doc_id):
                continue

            if query_terms:
                if not any(term in node.title_tf or term in node.body_positions for term in query_terms):
                    continue
                term_score = sum(
                    3.5 * min(node.title_tf.get(term, 0), 5)
                    + min(len(node.body_positions.get(term, ())), 12)
                    for term in query_terms
                )
                prox_bonus = compute_positions_proximity_bonus(node.body_positions, query_terms)
            else:
                term_score = 0.0
                prox_bonus = 0.0
            total_score = round(term_score + prox_bonus + 0.25 * node.citation_count + 0.1 * node.risk_weight, 4)
            candidates.append({
                "doc_id": node.doc_id,
                "category": node.category,
                "regulation_code": node.regulation_code,
                "_canon_reg": node.canon_reg,
                "clearance_level": node.clearance_level,
                "risk_weight": node.risk_weight,
                "custom_tag": node.custom_tag,
                "title": node.title,
                "snippet": node.snippet,
                "citation_count": node.citation_count,
                "score": total_score,
                "updated_at": node.updated_at,
                "_token_set": node.token_set,
            })

        candidates.sort(key=lambda doc: (-doc["score"], -doc["updated_at"], doc["doc_id"]))
        if deduplicate:
            final_list: list[dict[str, Any]] = []
            consumed = [False] * len(candidates)
            regulation_groups: dict[str, list[int]] = {}
            for candidate_index, candidate in enumerate(candidates):
                if candidate["_canon_reg"]:
                    regulation_groups.setdefault(candidate["_canon_reg"], []).append(candidate_index)
            for i, candidate in enumerate(candidates):
                if consumed[i]:
                    continue
                rep = dict(candidate)
                cluster_size = 1
                for j in regulation_groups.get(rep["_canon_reg"], ()):
                    if j <= i or consumed[j]:
                        continue
                    other = candidates[j]
                    if jaccard_similarity_sets(rep["_token_set"], other["_token_set"]) >= DEDUP_JACCARD_THRESHOLD:
                        consumed[j] = True
                        cluster_size += 1
                rep["cluster_size"] = cluster_size
                final_list.append(rep)
        else:
            final_list = [dict(item, cluster_size=1) for item in candidates]

    if reverse_flag:
        final_list.sort(key=lambda doc: (-doc[sort_field], doc["doc_id"]))
    else:
        final_list.sort(key=lambda doc: (doc[sort_field], doc["doc_id"]))
    total_matched = len(final_list)
    start = max(0, offset)
    sliced = final_list[start:] if limit < 0 else final_list[start:start + limit]
    items = [{key: value for key, value in doc.items() if not key.startswith("_")} for doc in sliced]
    return {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items),
        "items": items,
    }


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    if not isinstance(doc_ids, list) or not doc_ids or len(doc_ids) > 256:
        raise ValueError("doc_ids must be a non-empty list of at most 256 IDs")
    clean_ids = [bounded_text(doc_id, "doc_id", 128) for doc_id in doc_ids]
    placeholders = ",".join("?" for _ in clean_ids)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, body, status, quarantined, updated_at FROM compliance_docs "
            f"WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *clean_ids),
        ).fetchall()
    finally:
        conn.close()
    by_id = {row["doc_id"]: row for row in rows}
    wall = get_wall_snapshot(db_path, caller.tenant_id)
    items: list[dict[str, Any]] = []
    for doc_id in clean_ids:
        row = by_id.get(doc_id)
        if not row or row["status"] != "ACTIVE" or int(row["quarantined"]) != 0:
            continue
        if int(row["clearance_level"]) > caller.max_clearance:
            continue
        if wall.blocked(caller.user_id, caller.org_node_id, doc_id):
            continue
        items.append({
            "doc_id": row["doc_id"], "tenant_id": caller.tenant_id,
            "category": row["category"], "regulation_code": row["regulation_code"],
            "clearance_level": int(row["clearance_level"]), "risk_weight": int(row["risk_weight"]),
            "custom_tag": row["custom_tag"], "title": row["title"], "body": row["body"],
            "updated_at": int(row["updated_at"]),
        })
    return {"requested": len(clean_ids), "found": len(items), "items": items}


def set_document_quarantine(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    quarantined: bool,
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(quarantined, bool):
        raise ValueError("quarantined must be boolean")
    doc_id = bounded_text(doc_id, "doc_id", 128)
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if quarantined else 0
    index = get_document_index(db_path, caller.tenant_id)
    with index.lock:
        index.ensure_loaded()
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError("Document not found")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        index.apply_state(doc_id, quarantined=q_val, updated_at=now_ts)
    return {
        "tenant_id": caller.tenant_id, "doc_id": doc_id,
        "quarantined": bool(q_val), "updated_at": now_ts,
    }
