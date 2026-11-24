# -*- coding: utf-8 -*-
"""高性能合规文档检索引擎：单篇 O(L) 写时复制增量倒排表 + 双指针词距加成 + 五维纪元有界 LRU。"""
from __future__ import annotations

from collections import OrderedDict
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
    register_cache_reset_hook,
    require_strict_int,
)
from .doc_indexer import (
    IndexedDoc,
    build_indexed_doc,
    compute_phrase_proximity_bonus_indexed,
    tokenize_text,
)

ALLOWED_SORT_FIELDS = {"score", "updated_at", "risk_weight"}
ALLOWED_SORT_DIRS = {"asc", "desc"}
SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
MAX_SEARCH_CACHE_ENTRIES = 256


class TenantDocIndex:
    """不可变快照式租户文档倒排结构，支持无锁并发读取与单篇写时复制增量演进。"""

    __slots__ = ("doc_epoch", "docs_by_id", "postings")

    def __init__(
        self,
        *,
        doc_epoch: int,
        docs_by_id: dict[str, IndexedDoc],
        postings: dict[str, frozenset[str]],
    ) -> None:
        self.doc_epoch = doc_epoch
        self.docs_by_id = docs_by_id
        self.postings = postings


_INDEX_CACHE_LOCK = threading.Lock()
# 仅保留每个 (db_key, tenant_id) 最新一代索引快照，杜绝多代历史拷贝驻留堆内存
_TENANT_INDEX_CACHE: dict[tuple[str, str], TenantDocIndex] = {}

_RESULT_CACHE_LOCK = threading.Lock()
_SEARCH_RESULT_CACHE: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()


def _clear_search_caches(db_key: str) -> None:
    with _INDEX_CACHE_LOCK:
        for k in [k for k in _TENANT_INDEX_CACHE if k[0] == db_key]:
            _TENANT_INDEX_CACHE.pop(k, None)
    with _RESULT_CACHE_LOCK:
        for k in [k for k in _SEARCH_RESULT_CACHE if k[0] == db_key]:
            _SEARCH_RESULT_CACHE.pop(k, None)


register_cache_reset_hook(_clear_search_caches)


def sync_single_doc_in_index(
    db_path: str,
    tenant_id: str,
    doc_id: str,
    new_doc_epoch: int,
) -> None:
    """当单篇文档发生 Upsert / Retire / Quarantine 时，在已构建倒排快照上执行 O(L) 增量差量替换。"""
    db_key = normalize_db_key(db_path)
    tk = (db_key, tenant_id)
    with _INDEX_CACHE_LOCK:
        cur_idx = _TENANT_INDEX_CACHE.get(tk)
    if cur_idx is None:
        return

    conn = get_thread_connection(db_path)
    row = conn.execute(
        "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
        "custom_tag, title, body, status, quarantined, updated_at "
        "FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
        (tenant_id, doc_id),
    ).fetchone()

    new_idoc: IndexedDoc | None = None
    if row is not None and row["status"] == "ACTIVE" and int(row["quarantined"]) == 0:
        c_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchone()
        cite_cnt = int(c_row["cnt"]) if c_row else 0
        new_idoc = build_indexed_doc(
            doc_id=str(row["doc_id"]),
            category=str(row["category"]),
            regulation_code=str(row["regulation_code"]),
            clearance_level=int(row["clearance_level"]),
            risk_weight=int(row["risk_weight"]),
            custom_tag=str(row["custom_tag"]),
            title=str(row["title"]),
            body=str(row["body"]),
            citation_count=cite_cnt,
            updated_at=int(row["updated_at"]),
        )

    with _INDEX_CACHE_LOCK:
        cur_idx = _TENANT_INDEX_CACHE.get(tk)
        if cur_idx is None or cur_idx.doc_epoch != new_doc_epoch - 1:
            # 若期间发生了跳跃版本并发写，安全移除使下次读取按最新纪元对齐重建
            if cur_idx is not None and cur_idx.doc_epoch < new_doc_epoch:
                _TENANT_INDEX_CACHE.pop(tk, None)
            return

        new_docs = dict(cur_idx.docs_by_id)
        new_postings = dict(cur_idx.postings)
        old_idoc = new_docs.pop(doc_id, None)
        if old_idoc is not None:
            rm_set = frozenset((doc_id,))
            for term in old_idoc.token_set:
                prev_p = new_postings.get(term)
                if prev_p:
                    rem = prev_p - rm_set
                    if rem:
                        new_postings[term] = rem
                    else:
                        new_postings.pop(term, None)

        if new_idoc is not None:
            new_docs[doc_id] = new_idoc
            add_set = frozenset((doc_id,))
            for term in new_idoc.token_set:
                prev_p = new_postings.get(term)
                new_postings[term] = (prev_p | add_set) if prev_p else add_set

        _TENANT_INDEX_CACHE[tk] = TenantDocIndex(
            doc_epoch=new_doc_epoch,
            docs_by_id=new_docs,
            postings=new_postings,
        )


def _get_or_build_tenant_index(db_path: str, tenant_id: str, doc_epoch: int) -> TenantDocIndex:
    db_key = normalize_db_key(db_path)
    tk = (db_key, tenant_id)
    with _INDEX_CACHE_LOCK:
        idx = _TENANT_INDEX_CACHE.get(tk)
        if idx is not None and idx.doc_epoch == doc_epoch:
            return idx

    lock = get_striped_lock(db_path, tenant_id, "doc_index")
    with lock:
        with _INDEX_CACHE_LOCK:
            idx = _TENANT_INDEX_CACHE.get(tk)
            if idx is not None and idx.doc_epoch == doc_epoch:
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
        cite_map = {str(r["doc_id"]): int(r["cnt"]) for r in cite_rows}

        docs_by_id: dict[str, IndexedDoc] = {}
        postings_tmp: dict[str, set[str]] = {}

        for r in doc_rows:
            did = str(r["doc_id"])
            idoc = build_indexed_doc(
                doc_id=did,
                category=str(r["category"]),
                regulation_code=str(r["regulation_code"]),
                clearance_level=int(r["clearance_level"]),
                risk_weight=int(r["risk_weight"]),
                custom_tag=str(r["custom_tag"]),
                title=str(r["title"]),
                body=str(r["body"]),
                citation_count=cite_map.get(did, 0),
                updated_at=int(r["updated_at"]),
            )
            docs_by_id[did] = idoc
            for term in idoc.token_set:
                postings_tmp.setdefault(term, set()).add(did)

        postings = {term: frozenset(dset) for term, dset in postings_tmp.items()}
        built = TenantDocIndex(doc_epoch=doc_epoch, docs_by_id=docs_by_id, postings=postings)

        with _INDEX_CACHE_LOCK:
            live_eps = get_tenant_epochs(db_path, tenant_id)
            if live_eps.doc == doc_epoch:
                _TENANT_INDEX_CACHE[tk] = built
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
    if query.count("%") > 3 or query.count("*") > 4 or query.count("?") > 6:
        raise ValueError("Excessive wildcard characters in query")
    stripped_q = query.strip()
    if stripped_q and all(ch in "%*?_." for ch in stripped_q):
        raise ValueError("Pure wildcard query flood rejected")

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
    eps = get_tenant_epochs(db_path, caller.tenant_id)
    max_cl = caller.max_clearance
    denied_set = caller.denied_doc_ids

    res_cache_key = (
        db_key,
        caller.tenant_id,
        eps.doc,
        eps.perm,
        eps.acl,
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

    t_index = _get_or_build_tenant_index(db_path, caller.tenant_id, eps.doc)
    docs_map = t_index.docs_by_id

    if query_terms:
        candidate_ids: set[str] = set()
        for term in query_terms:
            pset = t_index.postings.get(term)
            if pset:
                candidate_ids.update(pset)
        iter_docs = [docs_map[did] for did in candidate_ids if did in docs_map]
    else:
        iter_docs = list(docs_map.values())

    need_prox = len(query_terms) >= 2
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
            prox_bonus = (
                compute_phrase_proximity_bonus_indexed(idoc.body_positions, query_terms)
                if need_prox
                else 0.0
            )
            total_score = round(term_score + prox_bonus + idoc.base_score, 4)
        else:
            total_score = idoc.base_score

        scored_candidates.append((idoc, total_score))

    scored_candidates.sort(key=lambda pair: (-pair[1], -pair[0].updated_at, pair[0].doc_id))

    if deduplicate:
        kept_entries: list[dict[str, Any]] = []
        kept_by_canon_reg: dict[str, list[tuple[frozenset[str], int, dict[str, Any]]]] = {}

        for idoc, sc in scored_candidates:
            creg = idoc.canon_reg
            merged = False
            if creg:
                bucket = kept_by_canon_reg.get(creg)
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
                kept_entries.append(entry)
                if creg:
                    kept_by_canon_reg.setdefault(creg, []).append((idoc.token_set, idoc.token_set_len, entry))

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

    with _RESULT_CACHE_LOCK:
        live_eps = get_tenant_epochs(db_path, caller.tenant_id)
        if live_eps.perm == eps.perm and live_eps.acl == eps.acl and live_eps.doc == eps.doc:
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
    """同时执行横向租户边界、纵向密级上限、退役/隔离状态与三级利益冲突隔离墙四重过滤。"""
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

    by_id = {str(r["doc_id"]): r for r in rows}
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
    now_ts = int(caller.request_ts or int(time.time()))
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
            if conn.in_transaction:
                conn.rollback()
            raise LookupError(f"Document not found in tenant: {doc_id}")
        conn.commit()
        new_ep = bump_tenant_epoch(db_path, caller.tenant_id, "doc")
        sync_single_doc_in_index(db_path, caller.tenant_id, doc_id, new_ep)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
