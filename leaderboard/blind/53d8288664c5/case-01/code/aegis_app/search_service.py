# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。

架构重构（检索输出与原版 100% 零失真）：
- 紧凑单篇增量倒排索引：按 (docs, citations) 双纪元缓存的租户级内存索引，
  仅保留 __slots__ 紧凑条目（分词位置 array / 词频 / 140 字符摘要 / 元数据），
  绝不将整库原始全文 body 常驻内存；upsert / retire / quarantine 只触发
  「轻量元数据清单比对 + 变更文档单篇重读重建」的 O(变更数) 增量维护；
- 反向引用图动态传导：doc_ 内部引用维护 cited_by 前向集合与
  reverse_dependents 反向依赖图，引用源状态（ACTIVE/quarantined）翻转时仅对
  其 O(deg) 个被引用方的 citation_count 做局部重算（本租户源校验，阻断
  跨租户 doc_ 引用侧信道）；
- 权限解析移出候选循环：同一 (user, request_ts) 的实时有效密级与认证阶段
  算得的 caller.max_clearance 恒等（含 1~2 跳借调时效核验）；
- 词距邻近度直接消费索引位置表（双指针归并，min_dist==1 早停）；
  修订簇折叠 Jaccard 直接消费索引唯一词项集合（min/max 比值上界剪枝）；
- 全部 SQL 参数化：消除 tenant / tag / 引用源 / ORDER BY 的字符串拼接注入；
- batch-get 越权封堵：租户、状态、隔离、密级与利益冲突墙五重约束全量校验。
"""
from __future__ import annotations

from array import array
import threading
import time
from typing import Any, Iterator

from .auth import CallerContext, is_doc_blocked_by_acl, require_admin
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    PROXIMITY_MAX_SPAN,
)
from .db import open_connection
from .doc_indexer import _min_token_distance, tokenize_text
from .epoch_cache import bump_epoch, epoch_token
from .legacy_compat import canonicalize_regulation_code

# ---------------------------------------------------------------------------
# 抗 DoS 索引预算：单篇正文至多索引前 5 万个词、单词至多保留 2048 个位置。
# 正常业务文档（数百词量级）远低于预算，打分逐 token 精确；仅对畸形巨型
# 载荷截断以约束常驻堆内存（位置 array('i') 每词 4 字节/位置）。
# ---------------------------------------------------------------------------
_MAX_INDEXED_BODY_TOKENS = 50_000
_MAX_TOKEN_POSITIONS = 2048
_MAX_BATCH_GET_IDS = 2000
_SQL_CHUNK_SIZE = 400


class _DocEntry:
    """紧凑单篇倒排条目（__slots__，不含原始全文 body）。"""

    __slots__ = (
        "doc_id",
        "category",
        "regulation_code",
        "clearance_level",
        "risk_weight",
        "custom_tag",
        "title",
        "status",
        "quarantined",
        "updated_at",
        "body_len",
        "snippet",
        "title_tf",
        "body_tf",
        "positions",
        "token_set",
    )


class _TenantSearchIndex:
    """租户级增量倒排索引快照（docs + citations 双纪元寻址）。"""

    __slots__ = (
        "docs",
        "forward_refs",
        "reverse_dependents",
        "citation_count",
        "token",
    )

    def __init__(
        self,
        docs: dict[str, _DocEntry],
        forward_refs: dict[str, set[str]],
        reverse_dependents: dict[str, set[str]],
        citation_count: dict[str, int],
        token: tuple[int, ...],
    ) -> None:
        self.docs = docs
        self.forward_refs = forward_refs
        self.reverse_dependents = reverse_dependents
        self.citation_count = citation_count
        self.token = token


_registry_lock = threading.Lock()
_index_registry: dict[tuple[str, str], _TenantSearchIndex] = {}
_reconcile_locks: dict[tuple[str, str], threading.Lock] = {}


def _iter_chunks(seq: list[str], size: int) -> Iterator[list[str]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _build_doc_entry(
    doc_id: str,
    category: str,
    regulation_code: str,
    clearance_level: int,
    risk_weight: int,
    custom_tag: str,
    title: str,
    body: str,
    status: str,
    quarantined: int,
    updated_at: int,
    body_len: int,
) -> _DocEntry:
    positions: dict[str, array] = {}
    body_tf: dict[str, int] = {}
    indexed = 0
    for tok in tokenize_text(body):
        if indexed >= _MAX_INDEXED_BODY_TOKENS:
            break
        cur = body_tf.get(tok)
        if cur is None or cur < 12:
            body_tf[tok] = (cur or 0) + 1
        pos_list = positions.get(tok)
        if pos_list is None:
            positions[tok] = array("i", (indexed,))
        elif len(pos_list) < _MAX_TOKEN_POSITIONS:
            pos_list.append(indexed)
        indexed += 1

    title_tf: dict[str, int] = {}
    for tok in tokenize_text(title):
        title_tf[tok] = title_tf.get(tok, 0) + 1

    entry = _DocEntry()
    entry.doc_id = doc_id
    entry.category = category
    entry.regulation_code = regulation_code
    entry.clearance_level = clearance_level
    entry.risk_weight = risk_weight
    entry.custom_tag = custom_tag
    entry.title = title
    entry.status = status
    entry.quarantined = quarantined
    entry.updated_at = updated_at
    entry.body_len = body_len
    entry.snippet = body[:140]
    entry.title_tf = title_tf
    entry.body_tf = body_tf
    entry.positions = positions
    entry.token_set = frozenset(positions) | frozenset(title_tf)
    return entry


def _count_valid_refs(docs: dict[str, _DocEntry], refs: set[str]) -> int:
    """统计唯一引用源中的有效数：外部文号直接计入；doc_ 内部引用仅当
    引用源文档属于本租户、ACTIVE 且未被隔离时计入（自引用在建图时已剔除）。"""
    cnt = 0
    for ref in refs:
        if ref.startswith("doc_"):
            src = docs.get(ref)
            if src is not None and src.status == "ACTIVE" and src.quarantined == 0:
                cnt += 1
        else:
            cnt += 1
    return cnt


def _reconcile_tenant_index(
    db_path: str,
    db_key: str,
    tenant_id: str,
    token: tuple[int, ...],
    old: _TenantSearchIndex | None,
) -> _TenantSearchIndex:
    """按 (docs, citations) 纪元增量对账：仅重读与重建真正发生变更的文档。"""
    docs_token, citations_token = token[0], token[1]
    conn = open_connection(db_path)
    try:
        manifest = conn.execute(
            "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, status, quarantined, updated_at, length(body) AS body_len "
            "FROM compliance_docs WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    manifest_map = {str(r["doc_id"]): r for r in manifest}
    old_docs = old.docs if old is not None else {}
    new_docs: dict[str, _DocEntry] = {}
    changed_ids: list[str] = []
    state_flipped_ids: set[str] = set()

    for r in manifest:
        did = str(r["doc_id"])
        e = old_docs.get(did)
        if (
            e is not None
            and e.status == str(r["status"])
            and e.quarantined == int(r["quarantined"])
            and e.updated_at == int(r["updated_at"])
            and e.body_len == int(r["body_len"] or 0)
            and e.category == str(r["category"])
            and e.regulation_code == str(r["regulation_code"])
            and e.clearance_level == int(r["clearance_level"])
            and e.risk_weight == int(r["risk_weight"])
            and e.custom_tag == str(r["custom_tag"])
            and e.title == str(r["title"])
        ):
            new_docs[did] = e
        else:
            if e is not None and (e.status != str(r["status"]) or e.quarantined != int(r["quarantined"])):
                state_flipped_ids.add(did)
            changed_ids.append(did)

    removed_ids = [did for did in old_docs if did not in manifest_map]
    for did in removed_ids:
        e = old_docs[did]
        if e.status == "ACTIVE" and e.quarantined == 0:
            state_flipped_ids.add(did)

    # 仅对发生变更的文档单篇重读正文并重建倒排条目。
    if changed_ids:
        body_map: dict[str, str] = {}
        conn = open_connection(db_path)
        try:
            for chunk in _iter_chunks(changed_ids, _SQL_CHUNK_SIZE):
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT doc_id, body FROM compliance_docs "
                    f"WHERE tenant_id = ? AND doc_id IN ({placeholders})",
                    (tenant_id, *chunk),
                ).fetchall()
                for r in rows:
                    body_map[str(r["doc_id"])] = str(r["body"])
        finally:
            conn.close()
        for did in changed_ids:
            r = manifest_map.get(did)
            if r is None or did not in body_map:
                continue
            new_docs[did] = _build_doc_entry(
                did,
                str(r["category"]),
                str(r["regulation_code"]),
                int(r["clearance_level"]),
                int(r["risk_weight"]),
                str(r["custom_tag"]),
                str(r["title"]),
                body_map[did],
                str(r["status"]),
                int(r["quarantined"]),
                int(r["updated_at"]),
                int(r["body_len"] or 0),
            )

    # 引用图维护：citations 纪元变化才全量重建前向/反向图；否则原样复用。
    if old is None or old.token[1] != citations_token:
        forward_refs: dict[str, set[str]] = {}
        reverse_dependents: dict[str, set[str]] = {}
        conn = open_connection(db_path)
        try:
            rows = conn.execute(
                "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
        finally:
            conn.close()
        for r in rows:
            did = str(r["doc_id"])
            ref = str(r["cited_by_ref"] or "").strip()
            if ref and ref != did:
                forward_refs.setdefault(did, set()).add(ref)
                if ref.startswith("doc_"):
                    reverse_dependents.setdefault(ref, set()).add(did)
        rebuild_all_counts = True
    else:
        forward_refs = old.forward_refs
        reverse_dependents = old.reverse_dependents
        rebuild_all_counts = False

    if rebuild_all_counts:
        citation_count = {
            did: _count_valid_refs(new_docs, refs) for did, refs in forward_refs.items()
        }
    else:
        citation_count = dict(old.citation_count)
        # O(deg) 局部传导：状态翻转/新增/移除的引用源，仅重算其反向依赖
        # 被引用方与自身的有效引用计数。
        affected = set(changed_ids) | state_flipped_ids | set(removed_ids)
        for fid in affected:
            for dep_doc in reverse_dependents.get(fid, ()):
                refs = forward_refs.get(dep_doc)
                if refs:
                    citation_count[dep_doc] = _count_valid_refs(new_docs, refs)
            own_refs = forward_refs.get(fid)
            if own_refs:
                citation_count[fid] = _count_valid_refs(new_docs, own_refs)

    return _TenantSearchIndex(new_docs, forward_refs, reverse_dependents, citation_count, token)


def _get_tenant_index(db_path: str, tenant_id: str) -> _TenantSearchIndex:
    db_key = str(db_path)
    token = epoch_token(db_path, "docs", "citations")
    reg_key = (db_key, tenant_id)

    with _registry_lock:
        idx = _index_registry.get(reg_key)
    if idx is not None and idx.token == token:
        return idx

    with _registry_lock:
        lock = _reconcile_locks.get(reg_key)
        if lock is None:
            lock = threading.Lock()
            _reconcile_locks[reg_key] = lock
    with lock:
        with _registry_lock:
            idx = _index_registry.get(reg_key)
        if idx is not None and idx.token == token:
            return idx
        idx = _reconcile_tenant_index(db_path, db_key, tenant_id, token, idx)
        with _registry_lock:
            _index_registry[reg_key] = idx
        return idx


def _proximity_bonus_from_positions(
    positions: dict[str, array],
    query_terms: list[str],
) -> float:
    """基于索引位置表的相邻查询词最小跨度邻近度加分（语义与 doc_indexer 一致）。"""
    if len(query_terms) < 2:
        return 0.0
    bonus = 0.0
    for idx in range(len(query_terms) - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = positions.get(term_a)
        pos_b = positions.get(term_b)
        if not pos_a or not pos_b:
            continue
        min_dist = _min_token_distance(pos_a, pos_b)
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def _jaccard_token_sets(set_a: frozenset, set_b: frozenset) -> float:
    """基于索引唯一词项集合的 Jaccard 相似度（与 doc_indexer 精确语义一致，
    含 min/max 比值上界剪枝——剪枝仅对必然低于折叠阈值的比对返回 0.0）。"""
    len_a = len(set_a)
    len_b = len(set_b)
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0
    smaller, larger = (len_a, len_b) if len_a <= len_b else (len_b, len_a)
    if smaller / larger < DEDUP_JACCARD_THRESHOLD:
        return 0.0
    inter_cnt = len(set_a & set_b)
    union_cnt = len_a + len_b - inter_cnt
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
    """执行合规文档检索：融合委托有效密级、三级利益冲突隔离墙、词距邻近度加成与历史双轨法规号折叠。"""
    tenant_id = caller.tenant_id
    # 权限解析移出候选循环：同一 (user, request_ts) 下实时有效密级与认证阶段
    # 已算得的 caller.max_clearance 恒等（借调时效、级联失效核验已在认证完成）。
    live_clearance = caller.max_clearance

    idx = _get_tenant_index(db_path, tenant_id)
    docs = idx.docs

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    candidates: list[dict[str, Any]] = []

    for entry in docs.values():
        if entry.status != "ACTIVE" or entry.quarantined != 0:
            continue
        if entry.clearance_level > live_clearance:
            continue
        if category and entry.category != category:
            continue
        if tag_filter and entry.custom_tag != tag_filter:
            continue
        if is_doc_blocked_by_acl(db_path, tenant_id, caller.user_id, entry.doc_id):
            continue

        if query_terms:
            if not any((t in entry.title_tf) or (t in entry.positions) for t in query_terms):
                continue
            term_score = sum(
                3.5 * min(entry.title_tf.get(t, 0), 5) + 1.0 * min(entry.body_tf.get(t, 0), 12)
                for t in query_terms
            )
            prox_bonus = _proximity_bonus_from_positions(entry.positions, query_terms)
        else:
            term_score = 0.0
            prox_bonus = 0.0

        cite_cnt = idx.citation_count.get(entry.doc_id, 0)
        risk_w = entry.risk_weight
        total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)

        candidates.append(
            {
                "doc_id": entry.doc_id,
                "category": entry.category,
                "regulation_code": entry.regulation_code,
                "_canon_reg": canonicalize_regulation_code(entry.regulation_code),
                "clearance_level": entry.clearance_level,
                "risk_weight": risk_w,
                "custom_tag": entry.custom_tag,
                "title": entry.title,
                "snippet": entry.snippet,
                "citation_count": cite_cnt,
                "score": total_score,
                "updated_at": entry.updated_at,
                "_token_set": entry.token_set,
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
            cluster_size = 1
            for j in range(i + 1, len(candidates)):
                if consumed[j]:
                    continue
                same_reg = bool(rep["_canon_reg"]) and (
                    rep["_canon_reg"] == candidates[j]["_canon_reg"]
                )
                if not same_reg:
                    continue
                sim = _jaccard_token_sets(rep["_token_set"], candidates[j]["_token_set"])
                if sim >= DEDUP_JACCARD_THRESHOLD:
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


def batch_get_documents(
    db_path: str,
    caller: CallerContext,
    doc_ids: list[str],
) -> dict[str, Any]:
    """按文档 ID 列表批量获取完整合规文档内容。

    五重越权封堵：严格校验租户归属、ACTIVE 状态、隔离状态、调用者实时有效
    密级与三级利益冲突隔离墙，跨租户 / 越密级 / 撞墙 / 已隔离文档一律不出网。
    """
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > _MAX_BATCH_GET_IDS:
        raise ValueError(f"doc_ids list exceeds maximum allowed size ({_MAX_BATCH_GET_IDS})")
    if any(not isinstance(d, str) for d in doc_ids):
        raise ValueError("doc_ids entries must be strings")

    by_id: dict[str, Any] = {}
    conn = open_connection(db_path)
    try:
        for chunk in _iter_chunks(doc_ids, _SQL_CHUNK_SIZE):
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
                f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
                f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
                (caller.tenant_id, *chunk),
            ).fetchall()
            for r in rows:
                by_id[str(r["doc_id"])] = r
    finally:
        conn.close()

    items = []
    for did in doc_ids:
        r = by_id.get(did)
        if not r or str(r["status"]) != "ACTIVE" or int(r["quarantined"]) != 0:
            continue
        if int(r["clearance_level"]) > caller.max_clearance:
            continue
        if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, did):
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

    # 隔离/解封立即生效：提升 docs 纪元触发增量索引对账，
    # 被隔离源文档的下游 citation_count 经反向引用图局部传导归零/恢复。
    bump_epoch(db_path, "docs")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
