# -*- coding: utf-8 -*-
"""企业合规文档检索、相关性打分、利益冲突墙校验与近似修订簇折叠服务。"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import re
import time
from typing import Any

from .auth import (
    CallerContext,
    require_admin,
    resolve_effective_permissions,
    resolve_org_ancestors,
)
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .runtime import get_runtime

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")

MAX_QUERY_LEN = 512
MAX_QUERY_TERMS = 32
MAX_PAGE_LIMIT = 200
MAX_PAGE_OFFSET = 100000
MAX_BATCH_GET_IDS = 200


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


@dataclass(frozen=True)
class IndexedDoc:
    doc_id: str
    tenant_id: str
    category: str
    regulation_code: str
    clearance_level: int
    risk_weight: int
    custom_tag: str
    title: str
    body: str
    snippet: str
    quarantined: bool
    updated_at: int
    cite_count: int
    title_tf: Counter[str]
    body_tf: Counter[str]
    token_set: frozenset[str]
    denied_users: frozenset[str]
    denied_orgs: frozenset[str]


class TenantDocIndex:
    """单租户合规文档预分词倒排索引与利益冲突隔离墙快照。"""

    def __init__(
        self,
        docs: list[IndexedDoc],
        inverted_index: dict[str, list[int]],
        by_id: dict[str, IndexedDoc],
    ) -> None:
        self.docs = docs
        self.inverted_index = inverted_index
        self.by_id = by_id


def _build_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    rt = get_runtime(db_path)
    conn = rt.get_connection()

    doc_rows = conn.execute(
        "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
        "risk_weight, custom_tag, title, body, quarantined, updated_at "
        "FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE'",
        (tenant_id,),
    ).fetchall()

    cite_rows = conn.execute(
        "SELECT doc_id, COUNT(*) AS cnt FROM doc_citations WHERE tenant_id = ? GROUP BY doc_id",
        (tenant_id,),
    ).fetchall()
    cite_map = {r["doc_id"]: int(r["cnt"]) for r in cite_rows}

    acl_rows = conn.execute(
        "SELECT doc_id, subject_type, subject_id FROM doc_acl_rules "
        "WHERE tenant_id = ? AND active = 1 AND effect = 'DENY'",
        (tenant_id,),
    ).fetchall()
    acl_users_map: dict[str, set[str]] = defaultdict(set)
    acl_orgs_map: dict[str, set[str]] = defaultdict(set)
    for r in acl_rows:
        if r["subject_type"] == "USER":
            acl_users_map[r["doc_id"]].add(r["subject_id"])
        elif r["subject_type"] == "ORG_NODE":
            acl_orgs_map[r["doc_id"]].add(r["subject_id"])

    docs: list[IndexedDoc] = []
    inverted_index: dict[str, list[int]] = defaultdict(list)
    by_id: dict[str, IndexedDoc] = {}

    for idx, r in enumerate(doc_rows):
        did = r["doc_id"]
        title = r["title"]
        body = r["body"]
        title_tokens = tokenize_text(title)
        body_tokens = tokenize_text(body)
        title_tf = Counter(title_tokens)
        body_tf = Counter(body_tokens)
        token_set = frozenset(title_tf.keys()) | frozenset(body_tf.keys())

        for tok in token_set:
            inverted_index[tok].append(idx)

        item = IndexedDoc(
            doc_id=did,
            tenant_id=r["tenant_id"],
            category=r["category"],
            regulation_code=r["regulation_code"],
            clearance_level=int(r["clearance_level"]),
            risk_weight=int(r["risk_weight"]),
            custom_tag=r["custom_tag"],
            title=title,
            body=body,
            snippet=body[:140],
            quarantined=bool(r["quarantined"]),
            updated_at=int(r["updated_at"]),
            cite_count=cite_map.get(did, 0),
            title_tf=title_tf,
            body_tf=body_tf,
            token_set=token_set,
            denied_users=frozenset(acl_users_map.get(did, ())),
            denied_orgs=frozenset(acl_orgs_map.get(did, ())),
        )
        docs.append(item)
        by_id[did] = item

    return TenantDocIndex(docs=docs, inverted_index=dict(inverted_index), by_id=by_id)


def _get_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    rt = get_runtime(db_path)
    ep_before, cached = rt.get_doc_index_cached(tenant_id)
    if cached is not None:
        return cached
    index = _build_tenant_doc_index(db_path, tenant_id)
    rt.put_doc_index_cached(tenant_id, ep_before, index)
    return index


def _jaccard_from_sets(set_a: frozenset[str], set_b: frozenset[str]) -> float:
    if not set_a and not set_b:
        return 1.0
    inter_cnt = len(set_a & set_b)
    union_cnt = len(set_a) + len(set_b) - inter_cnt
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt


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
    """执行多关键词合规文档检索，按调用者实时密级与利益冲突墙过滤，并折叠近似修订版。"""
    if len(query) > MAX_QUERY_LEN:
        raise ValueError("Search query exceeds maximum allowed length")
    if len(category) > 64 or len(tag_filter) > 128:
        raise ValueError("Filter parameter exceeds maximum allowed length")
    if sort_by not in ("score", "updated_at", "risk_weight"):
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    sort_dir_norm = str(sort_dir).lower()
    if sort_dir_norm not in ("asc", "desc"):
        raise ValueError(f"Unsupported sort_dir: {sort_dir}")
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
    if offset < 0 or offset > MAX_PAGE_OFFSET:
        raise ValueError(f"offset must be between 0 and {MAX_PAGE_OFFSET}")

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > MAX_QUERY_TERMS:
        raise ValueError(f"Too many query terms (max {MAX_QUERY_TERMS})")

    _, live_clearance = resolve_effective_permissions(db_path, caller.tenant_id, caller.user_id)
    org_ancestors = caller.org_ancestors
    if not org_ancestors:
        org_ancestors = tuple(resolve_org_ancestors(db_path, caller.tenant_id, caller.org_node_id))
    org_ancestors_set = frozenset(org_ancestors)

    index = _get_tenant_doc_index(db_path, caller.tenant_id)

    if query_terms:
        matched_indices_set: set[int] = set()
        for t in query_terms:
            postings = index.inverted_index.get(t)
            if postings:
                matched_indices_set.update(postings)
        candidate_indices = list(matched_indices_set)
    else:
        candidate_indices = list(range(len(index.docs)))

    candidates: list[tuple[dict[str, Any], frozenset[str]]] = []
    for idx in candidate_indices:
        doc = index.docs[idx]
        if doc.quarantined or doc.clearance_level > live_clearance:
            continue
        if category and doc.category != category:
            continue
        if tag_filter and doc.custom_tag != tag_filter:
            continue
        if caller.user_id in doc.denied_users or not org_ancestors_set.isdisjoint(doc.denied_orgs):
            continue

        if query_terms:
            term_score = sum(
                3.5 * min(doc.title_tf.get(t, 0), 5) + 1.0 * min(doc.body_tf.get(t, 0), 12)
                for t in query_terms
            )
        else:
            term_score = 0.0

        total_score = round(term_score + 0.25 * doc.cite_count + 0.1 * doc.risk_weight, 4)
        candidates.append((
            {
                "doc_id": doc.doc_id,
                "category": doc.category,
                "regulation_code": doc.regulation_code,
                "clearance_level": doc.clearance_level,
                "risk_weight": doc.risk_weight,
                "custom_tag": doc.custom_tag,
                "title": doc.title,
                "snippet": doc.snippet,
                "citation_count": doc.cite_count,
                "score": total_score,
                "updated_at": doc.updated_at,
            },
            doc.token_set,
        ))

    candidates.sort(key=lambda item: (-item[0]["score"], -item[0]["updated_at"], item[0]["doc_id"]))

    if deduplicate:
        # 按 regulation_code 分桶去重：仅同非空 regulation_code 内可折叠，复杂度从 O(N^2) 降至按桶局部比对
        reg_buckets: dict[str, list[int]] = defaultdict(list)
        for pos, (doc_dict, _) in enumerate(candidates):
            rc = doc_dict["regulation_code"]
            if rc:
                reg_buckets[rc].append(pos)

        consumed = [False] * len(candidates)
        cluster_sizes = [1] * len(candidates)

        for positions in reg_buckets.values():
            m = len(positions)
            if m <= 1:
                continue
            for a_idx in range(m):
                i = positions[a_idx]
                if consumed[i]:
                    continue
                set_i = candidates[i][1]
                c_size = 1
                for b_idx in range(a_idx + 1, m):
                    j = positions[b_idx]
                    if consumed[j]:
                        continue
                    if _jaccard_from_sets(set_i, candidates[j][1]) >= DEDUP_JACCARD_THRESHOLD:
                        consumed[j] = True
                        c_size += 1
                cluster_sizes[i] = c_size

        final_list: list[dict[str, Any]] = []
        for pos, (doc_dict, _) in enumerate(candidates):
            if not consumed[pos]:
                doc_dict["cluster_size"] = cluster_sizes[pos]
                final_list.append(doc_dict)
    else:
        final_list = []
        for doc_dict, _ in candidates:
            doc_dict["cluster_size"] = 1
            final_list.append(doc_dict)

    reverse_flag = sort_dir_norm != "asc"
    if reverse_flag:
        final_list.sort(key=lambda d: (-d[sort_by], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_by], d["doc_id"]))

    total_matched = len(final_list)
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
    """按文档 ID 列表批量获取当前租户内调用者有权访问的完整合规文档内容（严格隔离租户、密级与隔离墙）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_GET_IDS:
        raise ValueError(f"doc_ids exceeds maximum batch size ({MAX_BATCH_GET_IDS})")

    _, live_clearance = resolve_effective_permissions(db_path, caller.tenant_id, caller.user_id)
    org_ancestors = caller.org_ancestors
    if not org_ancestors:
        org_ancestors = tuple(resolve_org_ancestors(db_path, caller.tenant_id, caller.org_node_id))
    org_ancestors_set = frozenset(org_ancestors)

    index = _get_tenant_doc_index(db_path, caller.tenant_id)
    items: list[dict[str, Any]] = []
    for did in doc_ids:
        if not isinstance(did, str):
            continue
        doc = index.by_id.get(did)
        if not doc or doc.quarantined or doc.clearance_level > live_clearance:
            continue
        if caller.user_id in doc.denied_users or not org_ancestors_set.isdisjoint(doc.denied_orgs):
            continue
        items.append(
            {
                "doc_id": doc.doc_id,
                "tenant_id": doc.tenant_id,
                "category": doc.category,
                "regulation_code": doc.regulation_code,
                "clearance_level": doc.clearance_level,
                "risk_weight": doc.risk_weight,
                "custom_tag": doc.custom_tag,
                "title": doc.title,
                "body": doc.body,
                "updated_at": doc.updated_at,
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
    """由合规管理员将指定合规文档置为隔离下架或解除隔离状态，并立即失效文档索引缓存。"""
    require_admin(caller)
    if not doc_id:
        raise ValueError("doc_id is required")

    now_ts = int(time.time())
    q_val = 1 if quarantined else 0
    rt = get_runtime(db_path)
    with rt.get_tenant_lock(caller.tenant_id):
        conn = rt.get_connection()
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
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        rt.bump_epoch("doc", caller.tenant_id)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
