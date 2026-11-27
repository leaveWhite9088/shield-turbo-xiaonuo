# -*- coding: utf-8 -*-
"""企业合规文档紧凑增量倒排索引、双向引用传播、词距邻近度打分与双轨法规簇折叠服务。"""
from __future__ import annotations

from collections import Counter
import sys
import time
from typing import Any

from .acl_wall import get_acl_snapshot, is_doc_blocked_with_snapshot
from .auth import CallerContext, require_admin, resolve_effective_permissions
from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
from .db import borrow_connection, write_transaction
from .doc_indexer import (
    build_body_positions,
    compute_phrase_proximity_from_positions,
    jaccard_similarity_sets,
    tokenize_text,
)
from .legacy_compat import canonicalize_regulation_code
from .runtime_state import get_runtime

_ALLOWED_SORT_BY = frozenset({"score", "updated_at", "risk_weight"})
_ALLOWED_SORT_DIR = frozenset({"asc", "desc"})
_MAX_QUERY_LEN = 2000
_MAX_QUERY_TERMS = 64
_MAX_BATCH_GET_IDS = 200


class _DocIndexNode:
    """紧凑常驻文档索引节点（__slots__，不保存原始大正文 body，仅保留 140 字符摘要）。"""

    __slots__ = (
        "doc_id",
        "category",
        "regulation_code",
        "canon_reg",
        "clearance_level",
        "risk_weight",
        "custom_tag",
        "title",
        "snippet",
        "updated_at",
        "title_tf",
        "body_pos",
        "uniq_tokens",
        "citation_count",
    )

    def __init__(
        self,
        *,
        doc_id: str,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        body: str,
        updated_at: int,
        citation_count: int,
    ) -> None:
        intern = sys.intern
        self.doc_id = doc_id
        self.category = intern(category)
        self.regulation_code = regulation_code
        self.canon_reg = intern(canonicalize_regulation_code(regulation_code))
        self.clearance_level = clearance_level
        self.risk_weight = risk_weight
        self.custom_tag = intern(custom_tag)
        self.title = title
        self.snippet = body[:140]
        self.updated_at = updated_at

        t_tokens = tokenize_text(title)
        b_tokens = tokenize_text(body)
        self.title_tf: dict[str, int] = {intern(k): v for k, v in Counter(t_tokens).items()}
        self.body_pos: dict[str, tuple[int, ...]] = build_body_positions(b_tokens)
        self.uniq_tokens: frozenset[str] = frozenset(self.title_tf.keys()) | frozenset(self.body_pos.keys())
        self.citation_count = citation_count


class TenantDocIndex:
    """单租户增量倒排索引 + 双向内部引用传播图（reverse_dependents）。"""

    __slots__ = (
        "nodes",
        "active_valid_docs",
        "inverted",
        "doc_ext_refs",
        "doc_int_refs",
        "reverse_dependents",
    )

    def __init__(self) -> None:
        self.nodes: dict[str, _DocIndexNode] = {}
        self.active_valid_docs: set[str] = set()
        self.inverted: dict[str, set[str]] = {}
        self.doc_ext_refs: dict[str, set[str]] = {}
        self.doc_int_refs: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}

    def _add_to_inverted(self, node: _DocIndexNode) -> None:
        inv = self.inverted
        did = node.doc_id
        for tok in node.uniq_tokens:
            bucket = inv.get(tok)
            if bucket is None:
                inv[tok] = {did}
            else:
                bucket.add(did)

    def _remove_from_inverted(self, node: _DocIndexNode) -> None:
        inv = self.inverted
        did = node.doc_id
        for tok in node.uniq_tokens:
            bucket = inv.get(tok)
            if bucket is not None:
                bucket.discard(did)
                if not bucket:
                    del inv[tok]

    def _compute_valid_citations(self, doc_id: str) -> int:
        ext = self.doc_ext_refs.get(doc_id)
        cnt = len(ext) if ext else 0
        int_refs = self.doc_int_refs.get(doc_id)
        if int_refs:
            active_set = self.active_valid_docs
            for ref in int_refs:
                if ref in active_set:
                    cnt += 1
        return cnt

    def _propagate_validity_change(self, source_doc_id: str, delta: int) -> None:
        """O(deg) 增量传播内部引用源状态翻转对被引用文档 citation_count 的影响。"""
        deps = self.reverse_dependents.get(source_doc_id)
        if not deps:
            return
        nodes = self.nodes
        for dep_id in deps:
            dep_node = nodes.get(dep_id)
            if dep_node is not None:
                dep_node.citation_count += delta

    def register_citations(self, doc_id: str, refs: list[str]) -> None:
        if not refs:
            return
        ext_set = self.doc_ext_refs.setdefault(doc_id, set())
        int_set = self.doc_int_refs.setdefault(doc_id, set())
        rev = self.reverse_dependents
        for raw_ref in refs:
            ref = str(raw_ref or "").strip()
            if not ref or ref == doc_id:
                continue
            if ref.startswith("doc_"):
                if ref not in int_set:
                    int_set.add(ref)
                    rev.setdefault(ref, set()).add(doc_id)
            else:
                ext_set.add(ref)

    def apply_upsert(
        self,
        *,
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
        new_citations: list[str],
    ) -> None:
        """单篇文档 O(|tokens| + deg) 增量更新倒排索引与引用图。"""
        self.register_citations(doc_id, new_citations)

        was_valid = doc_id in self.active_valid_docs
        is_valid = (status == "ACTIVE" and quarantined == 0)

        if was_valid:
            old_node = self.nodes.pop(doc_id, None)
            if old_node is not None:
                self._remove_from_inverted(old_node)

        if is_valid:
            self.active_valid_docs.add(doc_id)
            cite_cnt = self._compute_valid_citations(doc_id)
            node = _DocIndexNode(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                body=body,
                updated_at=updated_at,
                citation_count=cite_cnt,
            )
            self.nodes[doc_id] = node
            self._add_to_inverted(node)
            if not was_valid:
                self._propagate_validity_change(doc_id, +1)
        elif was_valid:
            self.active_valid_docs.discard(doc_id)
            self._propagate_validity_change(doc_id, -1)

    def apply_retire(self, doc_id: str) -> None:
        if doc_id in self.active_valid_docs:
            self.active_valid_docs.discard(doc_id)
            old_node = self.nodes.pop(doc_id, None)
            if old_node is not None:
                self._remove_from_inverted(old_node)
            self._propagate_validity_change(doc_id, -1)

    def apply_quarantine(self, db_path: str, tenant_id: str, doc_id: str, quarantined: bool) -> None:
        if quarantined:
            if doc_id in self.active_valid_docs:
                self.active_valid_docs.discard(doc_id)
                old_node = self.nodes.pop(doc_id, None)
                if old_node is not None:
                    self._remove_from_inverted(old_node)
                self._propagate_validity_change(doc_id, -1)
            return

        # 解除隔离：仅回查该单篇文档并增量激活，避免全表扫描
        if doc_id in self.active_valid_docs:
            return
        with borrow_connection(db_path) as conn:
            row = conn.execute(
                "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
                "custom_tag, title, body, status, quarantined, updated_at "
                "FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            ).fetchone()
        if not row or row["status"] != "ACTIVE" or int(row["quarantined"]) != 0:
            return
        self.active_valid_docs.add(doc_id)
        cite_cnt = self._compute_valid_citations(doc_id)
        node = _DocIndexNode(
            doc_id=doc_id,
            category=str(row["category"]),
            regulation_code=str(row["regulation_code"]),
            clearance_level=int(row["clearance_level"]),
            risk_weight=int(row["risk_weight"]),
            custom_tag=str(row["custom_tag"]),
            title=str(row["title"]),
            body=str(row["body"]),
            updated_at=int(row["updated_at"]),
            citation_count=cite_cnt,
        )
        self.nodes[doc_id] = node
        self._add_to_inverted(node)
        self._propagate_validity_change(doc_id, +1)


def _load_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    idx = TenantDocIndex()
    with borrow_connection(db_path) as conn:
        cite_rows = conn.execute(
            "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        for cr in cite_rows:
            did = str(cr["doc_id"])
            ref = str(cr["cited_by_ref"] or "").strip()
            if not ref or ref == did:
                continue
            if ref.startswith("doc_"):
                idx.doc_int_refs.setdefault(did, set()).add(ref)
                idx.reverse_dependents.setdefault(ref, set()).add(did)
            else:
                idx.doc_ext_refs.setdefault(did, set()).add(ref)

        doc_rows = conn.execute(
            "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, body, updated_at "
            "FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
            (tenant_id,),
        ).fetchall()

    for r in doc_rows:
        idx.active_valid_docs.add(str(r["doc_id"]))

    for r in doc_rows:
        did = str(r["doc_id"])
        cite_cnt = idx._compute_valid_citations(did)
        node = _DocIndexNode(
            doc_id=did,
            category=str(r["category"]),
            regulation_code=str(r["regulation_code"]),
            clearance_level=int(r["clearance_level"]),
            risk_weight=int(r["risk_weight"]),
            custom_tag=str(r["custom_tag"]),
            title=str(r["title"]),
            body=str(r["body"]),
            updated_at=int(r["updated_at"]),
            citation_count=cite_cnt,
        )
        idx.nodes[did] = node
        idx._add_to_inverted(node)
    return idx


def get_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    tstate = get_runtime(db_path).get_tenant(tenant_id)
    idx = tstate.doc_index
    if idx is not None:
        return idx
    with tstate.doc_lock:
        if tstate.doc_index is None:
            tstate.doc_index = _load_tenant_doc_index(db_path, tenant_id)
        return tstate.doc_index


def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
    """参数化且严格租户隔离的有效唯一引用源统计（防止二阶注入与跨租户引用侧信道）。"""
    with borrow_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT cited_by_ref FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchall()
        seen_refs: set[str] = set()
        for r in rows:
            ref = str(r["cited_by_ref"] or "").strip()
            if ref and ref != doc_id:
                seen_refs.add(ref)

        valid_cnt = 0
        for ref in seen_refs:
            if ref.startswith("doc_"):
                ref_row = conn.execute(
                    "SELECT status, quarantined FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                    (tenant_id, ref),
                ).fetchone()
                if ref_row and ref_row["status"] == "ACTIVE" and int(ref_row["quarantined"]) == 0:
                    valid_cnt += 1
            else:
                valid_cnt += 1
        return valid_cnt


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
    """执行合规文档检索：融合委托有效密级、独立 acl_epoch 隔离墙、双指针词距加成与双轨法规号折叠。"""
    if not isinstance(query, str) or len(query) > _MAX_QUERY_LEN:
        raise ValueError("Query string exceeds maximum allowed length")
    if sort_by not in _ALLOWED_SORT_BY:
        raise ValueError(f"Unsupported sort_by field: {sort_by}")
    norm_dir = str(sort_dir or "desc").lower()
    if norm_dir not in _ALLOWED_SORT_DIR:
        raise ValueError(f"Unsupported sort_dir value: {sort_dir}")
    if offset < 0:
        raise ValueError("offset must be non-negative")

    query_terms = list(dict.fromkeys(tokenize_text(query)))
    if len(query_terms) > _MAX_QUERY_TERMS:
        raise ValueError("Too many query terms")

    # 实时权限与独立隔离墙快照（与文档索引 doc_epoch 彻底解耦）
    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    acl_snap = get_acl_snapshot(db_path, caller.tenant_id)
    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)

    candidates: list[tuple[_DocIndexNode, float]] = []

    with tstate.doc_lock:
        if tstate.doc_index is None:
            tstate.doc_index = _load_tenant_doc_index(db_path, caller.tenant_id)
        doc_index: TenantDocIndex = tstate.doc_index

        if query_terms:
            matched_ids: set[str] = set()
            inv = doc_index.inverted
            for term in query_terms:
                bucket = inv.get(term)
                if bucket:
                    matched_ids.update(bucket)
            iter_nodes = [doc_index.nodes[did] for did in matched_ids if did in doc_index.nodes]
        else:
            iter_nodes = list(doc_index.nodes.values())

        for node in iter_nodes:
            if category and node.category != category:
                continue
            if tag_filter and node.custom_tag != tag_filter:
                continue
            if node.clearance_level > live_clearance:
                continue
            if is_doc_blocked_with_snapshot(acl_snap, caller.user_id, node.doc_id):
                continue

            if query_terms:
                title_tf = node.title_tf
                body_pos = node.body_pos
                term_score = 0.0
                for t in query_terms:
                    tf_t = title_tf.get(t, 0)
                    if tf_t:
                        term_score += 3.5 * (5 if tf_t > 5 else tf_t)
                    bp = body_pos.get(t)
                    if bp:
                        lbp = len(bp)
                        term_score += 1.0 * (12 if lbp > 12 else lbp)
                prox_bonus = compute_phrase_proximity_from_positions(body_pos, query_terms)
            else:
                term_score = 0.0
                prox_bonus = 0.0

            total_score = round(term_score + prox_bonus + 0.25 * node.citation_count + 0.1 * node.risk_weight, 4)
            candidates.append((node, total_score))

    candidates.sort(key=lambda pair: (-pair[1], -pair[0].updated_at, pair[0].doc_id))

    if deduplicate:
        # 按归一化法规号 canon_reg 分桶，仅对同法规号文档执行尺寸比剪枝 Jaccard 聚类
        cluster_sizes: dict[int, int] = {}
        consumed = [False] * len(candidates)
        by_reg: dict[str, list[int]] = {}
        for idx, (node, _) in enumerate(candidates):
            if node.canon_reg:
                by_reg.setdefault(node.canon_reg, []).append(idx)

        for indices in by_reg.values():
            m = len(indices)
            if m < 2:
                continue
            for a_pos in range(m):
                i = indices[a_pos]
                if consumed[i]:
                    continue
                rep_tokens = candidates[i][0].uniq_tokens
                c_size = 1
                for b_pos in range(a_pos + 1, m):
                    j = indices[b_pos]
                    if consumed[j]:
                        continue
                    sim = jaccard_similarity_sets(
                        rep_tokens,
                        candidates[j][0].uniq_tokens,
                        min_threshold=DEDUP_JACCARD_THRESHOLD,
                    )
                    if sim >= DEDUP_JACCARD_THRESHOLD:
                        consumed[j] = True
                        c_size += 1
                cluster_sizes[i] = c_size

        final_list: list[dict[str, Any]] = []
        for idx, (node, sc) in enumerate(candidates):
            if consumed[idx]:
                continue
            final_list.append(
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
                    "score": sc,
                    "updated_at": node.updated_at,
                    "cluster_size": cluster_sizes.get(idx, 1),
                }
            )
    else:
        final_list = [
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
                "score": sc,
                "updated_at": node.updated_at,
                "cluster_size": 1,
            }
            for node, sc in candidates
        ]

    if norm_dir != "asc":
        final_list.sort(key=lambda d: (-d[sort_by], d["doc_id"]))
    else:
        final_list.sort(key=lambda d: (d[sort_by], d["doc_id"]))

    total_matched = len(final_list)
    if limit < 0:
        sliced = final_list[offset:]
    else:
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
    """按文档 ID 列表批量获取完整合规文档（严格校验租户、状态、隔离、密级与利益冲突墙）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > _MAX_BATCH_GET_IDS:
        raise ValueError(f"doc_ids length exceeds limit ({_MAX_BATCH_GET_IDS})")

    cleaned_ids: list[str] = []
    for raw_id in doc_ids:
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise ValueError("Each doc_id must be a non-empty string")
        cleaned_ids.append(raw_id.strip())

    _, live_clearance = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        caller.user_id,
        at_ts=caller.request_ts,
    )
    acl_snap = get_acl_snapshot(db_path, caller.tenant_id)

    uniq_ids = list(dict.fromkeys(cleaned_ids))
    placeholders = ",".join("?" for _ in uniq_ids)
    with borrow_connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            f"FROM compliance_docs "
            f"WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0 AND doc_id IN ({placeholders})",
            (caller.tenant_id, *uniq_ids),
        ).fetchall()

    by_id = {str(r["doc_id"]): r for r in rows}
    items = []
    for did in cleaned_ids:
        r = by_id.get(did)
        if not r:
            continue
        if int(r["clearance_level"]) > live_clearance:
            continue
        if is_doc_blocked_with_snapshot(acl_snap, caller.user_id, did):
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
    require_admin(caller)
    did = str(doc_id or "").strip()
    if not did:
        raise ValueError("doc_id is required")
    now_ts = int(caller.request_ts or int(time.time()))
    q_val = 1 if quarantined else 0

    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.doc_lock:
        with write_transaction(db_path) as conn:
            cur = conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ?",
                (q_val, now_ts, caller.tenant_id, did),
            )
            if cur.rowcount == 0:
                raise LookupError(f"Document not found in tenant: {did}")

        tstate.doc_epoch += 1
        if tstate.doc_index is not None:
            tstate.doc_index.apply_quarantine(db_path, caller.tenant_id, did, bool(q_val))

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": did,
        "quarantined": bool(q_val),
        "updated_at": now_ts,
    }
