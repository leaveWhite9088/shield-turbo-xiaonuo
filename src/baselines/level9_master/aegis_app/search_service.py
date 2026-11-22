# -*- coding: utf-8 -*-
"""高性能合规文档检索引擎：共享预分词倒排表 + Chinese Wall 隔离签名 + 双检纪元有界 LRU 缓存。"""
from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass
import re
import threading
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    MAX_BATCH_DOCS,
    MAX_PAGE_LIMIT,
    MAX_PAGE_OFFSET,
    MAX_QUERY_LENGTH,
    MAX_QUERY_TERMS,
)
from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    normalize_db_key,
    require_strict_int,
)

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
ALLOWED_SORT_FIELDS = {"score", "updated_at", "risk_weight"}
ALLOWED_SORT_DIRS = {"asc", "desc"}
SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
MAX_SEARCH_CACHE_ENTRIES = 512


@dataclass(frozen=True)
class IndexedDoc:
    doc_id: str
    category: str
    regulation_code: str
    clearance_level: int
    risk_weight: int
    custom_tag: str
    title: str
    snippet: str
    citation_count: int
    base_score: float
    updated_at: int
    title_tf: dict[str, int]
    body_tf: dict[str, int]
    token_set: frozenset[str]
    token_set_len: int


class TenantDocIndex:
    def __init__(self, docs: list[IndexedDoc], postings: dict[str, list[int]]) -> None:
        self.docs = docs
        self.postings = postings


_INDEX_CACHE_LOCK = threading.Lock()
_TENANT_INDEX_CACHE: dict[tuple[str, str, int], TenantDocIndex] = {}

_RESULT_CACHE_LOCK = threading.Lock()
_SEARCH_RESULT_CACHE: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def _get_or_build_tenant_index(db_path: str, tenant_id: str, doc_epoch: int) -> TenantDocIndex:
    db_key = normalize_db_key(db_path)
    ck = (db_key, tenant_id, doc_epoch)
    with _INDEX_CACHE_LOCK:
        idx = _TENANT_INDEX_CACHE.get(ck)
    if idx is not None:
        return idx

    lock = get_striped_lock(db_path, tenant_id, "doc_index")
    with lock:
        with _INDEX_CACHE_LOCK:
            idx = _TENANT_INDEX_CACHE.get(ck)
            if idx is not None:
                return idx

        conn = get_thread_connection(db_path)
        doc_rows = conn.execute(
            "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, body, updated_at "
            "FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
            (tenant_id,),
        ).fetchall()
        cite_rows = conn.execute(
            "SELECT doc_id, COUNT(*) AS cnt FROM doc_citations WHERE tenant_id = ? GROUP BY doc_id",
            (tenant_id,),
        ).fetchall()
        cite_map = {r["doc_id"]: int(r["cnt"]) for r in cite_rows}

        docs: list[IndexedDoc] = []
        postings: dict[str, list[int]] = {}

        for pos, r in enumerate(doc_rows):
            title_tokens = tokenize_text(r["title"])
            body_tokens = tokenize_text(r["body"])
            t_tf = dict(Counter(title_tokens))
            b_tf = dict(Counter(body_tokens))
            tok_set = frozenset(t_tf.keys()) | frozenset(b_tf.keys())
            c_cnt = cite_map.get(r["doc_id"], 0)
            r_weight = int(r["risk_weight"])
            b_score = round(0.25 * c_cnt + 0.1 * r_weight, 4)

            idoc = IndexedDoc(
                doc_id=r["doc_id"],
                category=r["category"],
                regulation_code=r["regulation_code"],
                clearance_level=int(r["clearance_level"]),
                risk_weight=r_weight,
                custom_tag=r["custom_tag"],
                title=r["title"],
                snippet=r["body"][:140],
                citation_count=c_cnt,
                base_score=b_score,
                updated_at=int(r["updated_at"]),
                title_tf=t_tf,
                body_tf=b_tf,
                token_set=tok_set,
                token_set_len=len(tok_set),
            )
            docs.append(idoc)
            for term in tok_set:
                postings.setdefault(term, []).append(pos)

        built = TenantDocIndex(docs=docs, postings=postings)
        with _INDEX_CACHE_LOCK:
            _, live_doc_ep, _ = get_tenant_epochs(db_path, tenant_id)
            if live_doc_ep == doc_epoch:
                stale_keys = [
                    k for k in _TENANT_INDEX_CACHE if k[0] == db_key and k[1] == tenant_id and k[2] != doc_epoch
                ]
                for sk in stale_keys:
                    _TENANT_INDEX_CACHE.pop(sk, None)
                _TENANT_INDEX_CACHE[ck] = built
        return built


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
    limit: Any = DEFAULT_PAGE_LIMIT,
    offset: Any = 0,
) -> dict[str, Any]:
    if not isinstance(query, str) or len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"Query length exceeds maximum {MAX_QUERY_LENGTH}")
    if query.count("%") > 4 or query.count("*") > 6:
        raise ValueError("Excessive wildcard characters in query")

    norm_sort_by = str(sort_by or "score").strip()
    norm_sort_dir = str(sort_dir or "desc").strip().lower()
    if norm_sort_by not in ALLOWED_SORT_FIELDS:
        raise ValueError(f"Unsupported sort_by field: {norm_sort_by}")
    if norm_sort_dir not in ALLOWED_SORT_DIRS:
        raise ValueError(f"Unsupported sort_dir value: {norm_sort_dir}")

    checked_limit = require_strict_int(limit, "limit", min_val=1, max_val=MAX_PAGE_LIMIT)
    checked_offset = require_strict_int(offset, "offset", min_val=0, max_val=MAX_PAGE_OFFSET)

    if category and len(category) > 64:
        raise ValueError("Invalid category parameter")
    if tag_filter and not SAFE_TAG_RE.match(tag_filter):
        raise ValueError("Invalid tag_filter format")

    raw_terms = tokenize_text(query)
    query_terms = tuple(dict.fromkeys(raw_terms))
    if len(query_terms) > MAX_QUERY_TERMS:
        raise ValueError(f"Query term count exceeds maximum {MAX_QUERY_TERMS}")

    db_key = normalize_db_key(db_path)
    perm_epoch, doc_epoch, _ = get_tenant_epochs(db_path, caller.tenant_id)
    max_cl = caller.max_clearance
    denied_set = caller.denied_doc_ids

    # 缓存键融合租户、文档纪元、权限纪元、最高密级以及 Chinese Wall 被禁文档集合签名！
    res_cache_key = (
        db_key,
        caller.tenant_id,
        doc_epoch,
        perm_epoch,
        max_cl,
        denied_set,
        query_terms,
        category,
        tag_filter,
        bool(deduplicate),
        norm_sort_by,
        norm_sort_dir,
        checked_limit,
        checked_offset,
    )
    with _RESULT_CACHE_LOCK:
        cached_resp = _SEARCH_RESULT_CACHE.get(res_cache_key)
        if cached_resp is not None:
            _SEARCH_RESULT_CACHE.move_to_end(res_cache_key)
            return cached_resp

    t_index = _get_or_build_tenant_index(db_path, caller.tenant_id, doc_epoch)
    all_docs = t_index.docs

    if query_terms:
        candidate_indices: set[int] = set()
        for term in query_terms:
            plist = t_index.postings.get(term)
            if plist:
                candidate_indices.update(plist)
        iter_docs = [all_docs[i] for i in candidate_indices]
    else:
        iter_docs = all_docs

    scored_candidates: list[tuple[IndexedDoc, float]] = []
    for idoc in iter_docs:
        if idoc.clearance_level > max_cl:
            continue
        if denied_set and idoc.doc_id in denied_set:
            continue
        if category and idoc.category != category:
            continue
        if tag_filter and idoc.custom_tag != tag_filter:
            continue

        if query_terms:
            t_tf = idoc.title_tf
            b_tf = idoc.body_tf
            term_score = 0.0
            for t in query_terms:
                tc = t_tf.get(t, 0)
                bc = b_tf.get(t, 0)
                if tc:
                    term_score += 3.5 * (tc if tc < 5 else 5)
                if bc:
                    term_score += 1.0 * (bc if bc < 12 else 12)
            total_score = round(term_score + idoc.base_score, 4)
        else:
            total_score = idoc.base_score

        scored_candidates.append((idoc, total_score))

    scored_candidates.sort(key=lambda pair: (-pair[1], -pair[0].updated_at, pair[0].doc_id))

    if deduplicate:
        kept_entries: list[dict[str, Any]] = []
        kept_by_reg: dict[str, list[tuple[frozenset[str], int, dict[str, Any]]]] = {}

        for idoc, sc in scored_candidates:
            reg = idoc.regulation_code
            merged = False
            if reg:
                bucket = kept_by_reg.get(reg)
                if bucket:
                    cand_set = idoc.token_set
                    cand_len = idoc.token_set_len
                    for rep_set, rep_len, rep_dict in bucket:
                        if cand_len == 0 and rep_len == 0:
                            rep_dict["cluster_size"] += 1
                            merged = True
                            break
                        max_l = rep_len if rep_len >= cand_len else cand_len
                        min_l = cand_len if rep_len >= cand_len else rep_len
                        if max_l == 0 or (min_l / max_l) < DEDUP_JACCARD_THRESHOLD:
                            continue
                        inter_len = len(rep_set & cand_set)
                        union_len = rep_len + cand_len - inter_len
                        if union_len > 0 and (inter_len / union_len) >= DEDUP_JACCARD_THRESHOLD:
                            rep_dict["cluster_size"] += 1
                            merged = True
                            break

            if not merged:
                entry = {
                    "doc_id": idoc.doc_id,
                    "category": idoc.category,
                    "regulation_code": reg,
                    "clearance_level": idoc.clearance_level,
                    "risk_weight": idoc.risk_weight,
                    "custom_tag": idoc.custom_tag,
                    "title": idoc.title,
                    "snippet": idoc.snippet,
                    "citation_count": idoc.citation_count,
                    "score": sc,
                    "updated_at": idoc.updated_at,
                    "cluster_size": 1,
                }
                kept_entries.append(entry)
                if reg:
                    kept_by_reg.setdefault(reg, []).append((idoc.token_set, idoc.token_set_len, entry))

        final_list = kept_entries
    else:
        final_list = [
            {
                "doc_id": idoc.doc_id,
                "category": idoc.category,
                "regulation_code": idoc.regulation_code,
                "clearance_level": idoc.clearance_level,
                "risk_weight": idoc.risk_weight,
                "custom_tag": idoc.custom_tag,
                "title": idoc.title,
                "snippet": idoc.snippet,
                "citation_count": idoc.citation_count,
                "score": sc,
                "updated_at": idoc.updated_at,
                "cluster_size": 1,
            }
            for idoc, sc in scored_candidates
        ]

    if norm_sort_dir != "asc":
        if norm_sort_by != "score":
            final_list.sort(key=lambda d: (-d[norm_sort_by], d["doc_id"]))
        else:
            final_list.sort(key=lambda d: (-d["score"], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[norm_sort_by], d["doc_id"]))

    total_matched = len(final_list)
    items_out = final_list[checked_offset: checked_offset + checked_limit]

    response = {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items_out),
        "items": items_out,
    }

    # 双检纪元锁 + 有界 LRU 淘汰（防并发撤权脏回填 + 防随机查询穿透打爆内存）
    with _RESULT_CACHE_LOCK:
        live_perm_ep, live_doc_ep, _ = get_tenant_epochs(db_path, caller.tenant_id)
        if live_perm_ep == perm_epoch and live_doc_ep == doc_epoch:
            _SEARCH_RESULT_CACHE[res_cache_key] = response
            _SEARCH_RESULT_CACHE.move_to_end(res_cache_key)
            while len(_SEARCH_RESULT_CACHE) > MAX_SEARCH_CACHE_ENTRIES:
                _SEARCH_RESULT_CACHE.popitem(last=False)
    return response


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """同时执行横向租户边界、纵向密级上限、隔离下架状态与 Chinese Wall 利益冲突规则四重过滤。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_BATCH_DOCS:
        raise ValueError(f"doc_ids count exceeds limit {MAX_BATCH_DOCS}")
    for did in doc_ids:
        if not isinstance(did, str) or not did or len(did) > 128:
            raise ValueError("Invalid doc_id element")

    unique_ids = [did for did in dict.fromkeys(doc_ids) if did not in caller.denied_doc_ids]
    if not unique_ids:
        return {"requested": len(doc_ids), "found": 0, "items": []}

    placeholders = ",".join("?" for _ in unique_ids)
    conn = get_thread_connection(db_path)
    rows = conn.execute(
        f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
        f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
        f"FROM compliance_docs "
        f"WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 "
        f"AND clearance_level <= ? AND doc_id IN ({placeholders})",
        (caller.tenant_id, caller.max_clearance, *unique_ids),
    ).fetchall()

    by_id = {r["doc_id"]: r for r in rows}
    items = []
    for did in doc_ids:
        if did in caller.denied_doc_ids:
            continue
        r = by_id.get(did)
        if not r:
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
    if not isinstance(doc_id, str) or not doc_id or len(doc_id) > 128:
        raise ValueError("Invalid doc_id")
    now_ts = int(time.time())
    q_val = 1 if quarantined else 0

    lock = get_striped_lock(db_path, caller.tenant_id, "doc_write")
    with lock:
        conn = get_thread_connection(db_path)
        cur = conn.execute(
            "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
            "WHERE tenant_id = ? AND doc_id = ?",
            (q_val, now_ts, caller.tenant_id, doc_id),
        )
        if cur.rowcount == 0:
            conn.rollback()
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
        bump_tenant_epoch(db_path, caller.tenant_id, "doc")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
