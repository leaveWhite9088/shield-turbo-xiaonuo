# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。

本模块是端到端延迟的第一大户，原实现存在四处放大：

1. **循环内逐行解析权限**：每篇文档都重新解析一次实时借调权限（多次开库）；
2. **循环内逐行查引用**：每篇文档都新建连接并逐条扫描引用记录；
3. **循环内逐行查隔离墙**：每篇文档都新建连接回溯组织树；
4. **O(N²) 近似去重**：每一对候选都重新分词两遍正文来算 Jaccard。

改造后的检索链路：

    权限解析 1 次 → 隔离墙/组织树快照 1 次 → 文档索引（增量维护）→
    候选集内存筛选 → 单遍词元扫描同时得到词频与词距位置 →
    同簇分组 + 集合大小比值剪枝 + 预分词集合求交 → 稳定排序输出

全过程 **零逐行数据库往返**，且常驻结构不含原始正文。
"""
from __future__ import annotations

import sqlite3
import time
from typing import Any

from .acl_wall import is_user_blocked_by_wall_rules
from .auth import CallerContext, require_admin
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import open_connection, write_transaction
from .doc_indexer import (
    compute_proximity_bonus_from_positions,
    jaccard_from_token_sets,
    jaccard_may_exceed_threshold,
    tokenize_text,
)
from .legacy_compat import canonicalize_regulation_code
from .tenant_cache import load_acl_rules, load_doc_index, load_org_snapshot, peek_doc_index

# 单次批量取文档正文的分块大小（控制 SQL 变量上限与单次内存峰值）。
_BODY_FETCH_CHUNK = 200


class _ScoredDoc:
    """检索候选的紧凑结构（``__slots__``，无 ``__dict__`` 常驻开销）。"""

    __slots__ = (
        "doc_id",
        "category",
        "regulation_code",
        "canon_reg",
        "clearance_level",
        "risk_weight",
        "custom_tag",
        "title",
        "updated_at",
        "score",
        "citation_count",
        "cluster_size",
        "token_set",
        "title_tokens",
        "body_tokens",
    )

    def __init__(self, **kwargs: Any) -> None:
        for key in self.__slots__:
            setattr(self, key, kwargs.get(key))


def _compute_citation_counts(
    conn: sqlite3.Connection,
    tenant_id: str,
    doc_ids: list[str],
) -> dict[str, int]:
    """批量统计有效引用数（一次查询取引用 + 一次查询核验被引用文档状态）。

    与历史逐文档实现逐位等价，并额外满足跨租户边界：
    ``doc_`` 前缀的内部引用只有在 **引用源文档属于本租户** 且处于
    ``ACTIVE`` 且未被 ``quarantined`` 隔离时才计入有效引用。
    """
    if not doc_ids:
        return {}

    unique_refs: dict[str, set[str]] = {}
    for chunk_start in range(0, len(doc_ids), _BODY_FETCH_CHUNK):
        chunk = doc_ids[chunk_start : chunk_start + _BODY_FETCH_CHUNK]
        placeholders = ",".join("?" for _ in chunk)
        rows = conn.execute(
            f"SELECT doc_id, cited_by_ref FROM doc_citations "
            f"WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (tenant_id, *chunk),
        ).fetchall()
        for row in rows:
            ref = str(row["cited_by_ref"] or "").strip()
            doc_id = str(row["doc_id"])
            if not ref or ref == doc_id:
                continue
            unique_refs.setdefault(doc_id, set()).add(ref)

    internal_refs: set[str] = set()
    for refs in unique_refs.values():
        for ref in refs:
            if ref.startswith("doc_"):
                internal_refs.add(ref)

    internal_state: dict[str, tuple[str, int]] = {}
    if internal_refs:
        ref_list = list(internal_refs)
        for chunk_start in range(0, len(ref_list), _BODY_FETCH_CHUNK):
            chunk = ref_list[chunk_start : chunk_start + _BODY_FETCH_CHUNK]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT doc_id, status, quarantined FROM compliance_docs "
                f"WHERE tenant_id = ? AND doc_id IN ({placeholders})",
                (tenant_id, *chunk),
            ).fetchall()
            for row in rows:
                internal_state[str(row["doc_id"])] = (
                    str(row["status"]),
                    int(row["quarantined"]),
                )

    counts: dict[str, int] = {}
    for doc_id, refs in unique_refs.items():
        valid = 0
        for ref in refs:
            if ref.startswith("doc_"):
                state = internal_state.get(ref)
                if state and state[0] == "ACTIVE" and state[1] == 0:
                    valid += 1
            else:
                valid += 1
        counts[doc_id] = valid
    return counts


def _term_positions(tokens: list[str] | tuple[str, ...], term: str) -> list[int]:
    """用 C 层 ``list.index`` 扫描枚举某词元的全部出现下标（避免 Python 层逐词循环）。"""
    positions: list[int] = []
    start = 0
    length = len(tokens)
    while start < length:
        try:
            idx = tokens.index(term, start)  # type: ignore[arg-type]
        except ValueError:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def _score_candidate(
    *,
    doc_id: str,
    category: str,
    regulation_code: str,
    canon_reg: str,
    clearance_level: int,
    risk_weight: int,
    custom_tag: str,
    title: str,
    updated_at: int,
    title_tokens: list[str] | tuple[str, ...],
    body_tokens: list[str] | tuple[str, ...],
    query_terms: list[str],
    citation_count: int,
) -> _ScoredDoc:
    """对单篇文档打分（词频 + 邻近度 + 有效引用 + 风险权重）。

    词频统计与词元下标枚举全部走 C 层容器原语（``count`` / ``index``），
    把「逐词 Python 循环」降为「逐查询词 C 扫描」，是检索热路径的关键优化。
    """
    hit_any = False
    title_tf: dict[str, int] = {}
    body_tf: dict[str, int] = {}
    if query_terms:
        for t in query_terms:
            title_count = title_tokens.count(t)  # type: ignore[arg-type]
            body_count = body_tokens.count(t)  # type: ignore[arg-type]
            if title_count:
                title_tf[t] = title_count
            if body_count:
                body_tf[t] = body_count
            if title_count or body_count:
                hit_any = True
        if not hit_any:
            return None  # type: ignore[return-value]

        term_score = sum(
            3.5 * min(title_tf.get(t, 0), 5) + 1.0 * min(body_tf.get(t, 0), 12)
            for t in query_terms
        )
        # 仅当正文中出现 >= 2 个不同查询词时才可能产生邻近度加分。
        if len(body_tf) >= 2:
            positions: dict[str, list[int]] = {}
            for t in body_tf:
                positions[t] = _term_positions(body_tokens, t)
            prox_bonus = compute_proximity_bonus_from_positions(positions, query_terms)
        else:
            prox_bonus = 0.0
    else:
        term_score = 0.0
        prox_bonus = 0.0

    total_score = round(term_score + prox_bonus + 0.25 * citation_count + 0.1 * risk_weight, 4)
    return _ScoredDoc(
        doc_id=doc_id,
        category=category,
        regulation_code=regulation_code,
        canon_reg=canon_reg,
        clearance_level=clearance_level,
        risk_weight=risk_weight,
        custom_tag=custom_tag,
        title=title,
        updated_at=updated_at,
        score=total_score,
        citation_count=citation_count,
        cluster_size=1,
        token_set=None,
    )


def _cluster_and_fold(candidates: list[_ScoredDoc]) -> list[_ScoredDoc]:
    """双轨法规近似修订簇折叠（同归一化法规号 + Jaccard ≥ 阈值）。"""
    if not candidates:
        return []

    # 按归一化法规号分组：不同分组的文档在历史上永远不可能合并，
    # 因此无需做跨组的 O(N²) 比较。
    groups: dict[str, list[_ScoredDoc]] = {}
    for item in candidates:
        if not item.canon_reg:
            continue
        groups.setdefault(item.canon_reg, []).append(item)

    consumed: set[str] = set()
    token_cache: dict[str, set[str]] = {}

    def token_set(doc: _ScoredDoc) -> set[str]:
        cached = token_cache.get(doc.doc_id)
        if cached is None:
            cached = set(doc.title_tokens) | set(doc.body_tokens)
            token_cache[doc.doc_id] = cached
        return cached

    for group in groups.values():
        if len(group) < 2:
            continue
        for i, rep in enumerate(group):
            if rep.doc_id in consumed:
                continue
            cluster_size = 1
            rep_set = token_set(rep)
            rep_size = len(rep_set)
            for j in range(i + 1, len(group)):
                other = group[j]
                if other.doc_id in consumed:
                    continue
                other_set = token_set(other)
                # 集合大小比值剪枝：Jaccard 上界已低于阈值时不可能合并。
                if not jaccard_may_exceed_threshold(rep_size, len(other_set), DEDUP_JACCARD_THRESHOLD):
                    continue
                if jaccard_from_token_sets(rep_set, other_set) >= DEDUP_JACCARD_THRESHOLD:
                    consumed.add(other.doc_id)
                    cluster_size += 1
            rep.cluster_size = cluster_size

    return [item for item in candidates if item.doc_id not in consumed]


def _fetch_snippets(
    db_path: str,
    tenant_id: str,
    doc_ids: list[str],
) -> dict[str, str]:
    """按需取回正文片段（仅对最终返回页取回，常驻内存不受整库正文影响）。"""
    snippets: dict[str, str] = {}
    if not doc_ids:
        return snippets
    conn = open_connection(db_path)
    try:
        for chunk_start in range(0, len(doc_ids), _BODY_FETCH_CHUNK):
            chunk = doc_ids[chunk_start : chunk_start + _BODY_FETCH_CHUNK]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT doc_id, body FROM compliance_docs "
                f"WHERE tenant_id = ? AND doc_id IN ({placeholders})",
                (tenant_id, *chunk),
            ).fetchall()
            for row in rows:
                snippets[str(row["doc_id"])] = str(row["body"])[:140]
    finally:
        conn.close()
    return snippets


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
    query_terms = list(dict.fromkeys(tokenize_text(query)))
    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
    reverse_flag = str(sort_dir).lower() != "asc"

    org_snapshot = load_org_snapshot(db_path, caller.tenant_id)
    acl_rules = load_acl_rules(db_path, caller.tenant_id)
    live_clearance = caller.max_clearance

    index = load_doc_index(db_path, caller.tenant_id)
    candidates: list[_ScoredDoc] = []

    if index.usable and index.nodes:
        # ---- 索引路径：内存筛选 + 单遍词元扫描 -----------------------------
        for node in index.nodes.values():
            if node.status != "ACTIVE" or node.quarantined:
                continue
            if category and node.category != category:
                continue
            if tag_filter and node.custom_tag != tag_filter:
                continue
            if node.clearance_level > live_clearance:
                continue
            if is_user_blocked_by_wall_rules(org_snapshot, acl_rules, caller.user_id, node.doc_id):
                continue
            scored = _score_candidate(
                doc_id=node.doc_id,
                category=node.category,
                regulation_code=node.regulation_code,
                canon_reg=node.canon_reg,
                clearance_level=node.clearance_level,
                risk_weight=node.risk_weight,
                custom_tag=node.custom_tag,
                title=node.title,
                updated_at=node.updated_at,
                title_tokens=node.title_tokens,
                body_tokens=node.body_tokens,
                query_terms=query_terms,
                citation_count=index.effective_citation_count(node.doc_id),
            )
            if scored is None:
                continue
            scored.title_tokens = node.title_tokens  # type: ignore[attr-defined]
            scored.body_tokens = node.body_tokens  # type: ignore[attr-defined]
            candidates.append(scored)
    else:
        # ---- 降级路径：数据库流式扫描（不常驻正文，内存峰值受限） -------------
        candidates = _search_by_streaming(
            db_path,
            caller,
            query_terms=query_terms,
            category=category,
            tag_filter=tag_filter,
            live_clearance=live_clearance,
            org_snapshot=org_snapshot,
            acl_rules=acl_rules,
        )

    candidates.sort(key=lambda d: (-d.score, -d.updated_at, d.doc_id))

    if deduplicate:
        final_list = _cluster_and_fold(candidates)
    else:
        final_list = candidates

    if reverse_flag:
        final_list.sort(key=lambda d: (-getattr(d, sort_field), d.doc_id))
    else:
        final_list.sort(key=lambda d: (getattr(d, sort_field), d.doc_id))

    total_matched = len(final_list)
    if limit < 0:
        sliced = final_list[max(0, offset) :]
    else:
        sliced = final_list[max(0, offset) : max(0, offset) + limit]

    snippets = _fetch_snippets(db_path, caller.tenant_id, [d.doc_id for d in sliced])

    items_out = [
        {
            "doc_id": doc.doc_id,
            "category": doc.category,
            "regulation_code": doc.regulation_code,
            "clearance_level": doc.clearance_level,
            "risk_weight": doc.risk_weight,
            "custom_tag": doc.custom_tag,
            "title": doc.title,
            "snippet": snippets.get(doc.doc_id, ""),
            "citation_count": doc.citation_count,
            "score": doc.score,
            "updated_at": doc.updated_at,
            "cluster_size": doc.cluster_size,
        }
        for doc in sliced
    ]
    return {
        "tenant_id": caller.tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items_out),
        "items": items_out,
    }


def _search_by_streaming(
    db_path: str,
    caller: CallerContext,
    *,
    query_terms: list[str],
    category: str,
    tag_filter: str,
    live_clearance: int,
    org_snapshot: dict[str, Any],
    acl_rules: dict[str, list[tuple[str, str, str]]],
) -> list[_ScoredDoc]:
    """索引降级/不可用时的流式扫描兜底路径（正确性不变，内存峰值受限）。"""
    clauses = [
        "tenant_id = ?",
        "status = 'ACTIVE'",
        "quarantined = 0",
    ]
    params: list[Any] = [caller.tenant_id]
    if category:
        clauses.append("category = ?")
        params.append(category)
    if tag_filter:
        clauses.append("custom_tag = ?")
        params.append(tag_filter)

    sql = (
        "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
        "custom_tag, title, body, updated_at "
        f"FROM compliance_docs WHERE {' AND '.join(clauses)}"
    )

    conn = open_connection(db_path)
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
        doc_ids = [str(r["doc_id"]) for r in rows]
        citation_counts = _compute_citation_counts(conn, caller.tenant_id, doc_ids)
    finally:
        conn.close()

    candidates: list[_ScoredDoc] = []
    for row in rows:
        if int(row["clearance_level"]) > live_clearance:
            continue
        doc_id = str(row["doc_id"])
        if is_user_blocked_by_wall_rules(org_snapshot, acl_rules, caller.user_id, doc_id):
            continue
        title_tokens = tokenize_text(str(row["title"]))
        body_tokens = tokenize_text(str(row["body"]))
        scored = _score_candidate(
            doc_id=doc_id,
            category=str(row["category"]),
            regulation_code=str(row["regulation_code"]),
            canon_reg=canonicalize_regulation_code(str(row["regulation_code"])),
            clearance_level=int(row["clearance_level"]),
            risk_weight=int(row["risk_weight"]),
            custom_tag=str(row["custom_tag"]),
            title=str(row["title"]),
            updated_at=int(row["updated_at"]),
            title_tokens=title_tokens,
            body_tokens=body_tokens,
            query_terms=query_terms,
            citation_count=citation_counts.get(doc_id, 0),
        )
        if scored is None:
            continue
        scored.title_tokens = title_tokens  # type: ignore[attr-defined]
        scored.body_tokens = body_tokens  # type: ignore[attr-defined]
        candidates.append(scored)
    return candidates


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取完整合规文档内容（严格遵守租户/状态/隔离/密级/利益冲突墙约束）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > 1000:
        raise ValueError("doc_ids exceeds the maximum batch size of 1000")

    clean_ids: list[str] = []
    seen: set[str] = set()
    for raw in doc_ids:
        doc_id = str(raw or "").strip()
        if not doc_id or doc_id in seen:
            continue
        seen.add(doc_id)
        clean_ids.append(doc_id)
    if not clean_ids:
        raise ValueError("doc_ids must be a non-empty list")

    placeholders = ",".join("?" for _ in clean_ids)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
            (caller.tenant_id, *clean_ids),
        ).fetchall()
    finally:
        conn.close()

    org_snapshot = load_org_snapshot(db_path, caller.tenant_id)
    acl_rules = load_acl_rules(db_path, caller.tenant_id)

    by_id = {r["doc_id"]: r for r in rows}
    items = []
    for did in clean_ids:
        r = by_id.get(did)
        if not r or r["status"] != "ACTIVE":
            continue
        if int(r["quarantined"]) != 0:
            continue
        if int(r["clearance_level"]) > caller.max_clearance:
            continue
        if is_user_blocked_by_wall_rules(org_snapshot, acl_rules, caller.user_id, did):
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
        with write_transaction(conn):
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, doc_id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {doc_id}")
    finally:
        conn.close()

    _sync_doc_index_status(db_path, caller.tenant_id, doc_id, quarantined=bool(q_val))

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }


def _sync_doc_index_status(
    db_path: str,
    tenant_id: str,
    doc_id: str,
    *,
    status: str | None = None,
    quarantined: bool | None = None,
) -> None:
    """把文档状态翻转同步到增量索引（沿反向引用图 O(deg) 局部联动）。"""
    from .tenant_cache import refresh_doc_index_signature

    index = peek_doc_index(db_path, tenant_id)
    if index is not None and index.usable:
        index.apply_status_change(doc_id, status=status, quarantined=quarantined)
        refresh_doc_index_signature(db_path, tenant_id, index)
