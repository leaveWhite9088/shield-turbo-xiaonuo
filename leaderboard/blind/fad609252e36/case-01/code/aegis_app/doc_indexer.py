# -*- coding: utf-8 -*-
"""合规文本分词、双指针早停词距邻近度、比值剪枝词袋相似度与紧凑单篇增量倒排/双向引用图引擎。"""
from __future__ import annotations

from collections import Counter
import re
from typing import Iterable

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN
from .db import (
    bump_doc_epoch,
    get_tenant_doc_lock,
    get_tenant_epochs,
    normalize_db_key,
    open_connection,
    register_reset_callback,
)
from .legacy_compat import canonicalize_regulation_code

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def build_body_positions(body_tokens: list[str]) -> dict[str, tuple[int, ...]]:
    """将正文词序列压缩为每个词项的升序位置元组映射（元组长度即为词频 body_tf）。"""
    pos_lists: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        lst = pos_lists.get(tok)
        if lst is None:
            pos_lists[tok] = [idx]
        else:
            lst.append(idx)
    return {k: tuple(v) for k, v in pos_lists.items()}


def compute_proximity_bonus_from_positions(
    body_positions: dict[str, tuple[int, ...]],
    query_terms: list[str],
) -> float:
    """利用升序位置列表执行 O(|P_a| + |P_b|) 双指针线性扫描，并在 min_dist == 1 时立即早停。"""
    n_q = len(query_terms)
    if n_q < 2 or not body_positions:
        return 0.0

    bonus = 0.0
    for idx in range(n_q - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = body_positions.get(term_a)
        pos_b = body_positions.get(term_b)
        if not pos_a or not pos_b:
            continue

        ia = 0
        ib = 0
        na = len(pos_a)
        nb = len(pos_b)
        min_dist = 1000000000
        while ia < na and ib < nb:
            pa = pos_a[ia]
            pb = pos_b[ib]
            diff = pa - pb
            if diff < 0:
                dist = -diff
                if dist < min_dist:
                    min_dist = dist
                    if min_dist == 1:
                        break
                ia += 1
            elif diff > 0:
                if diff < min_dist:
                    min_dist = diff
                    if min_dist == 1:
                        break
                ib += 1
            else:
                ia += 1
                ib += 1

        if 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针 + min_dist == 1 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    target_set = set(query_terms)
    pos_lists: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        if tok in target_set:
            lst = pos_lists.get(tok)
            if lst is None:
                pos_lists[tok] = [idx]
            else:
                lst.append(idx)
    body_positions = {k: tuple(v) for k, v in pos_lists.items()}
    return compute_proximity_bonus_from_positions(body_positions, query_terms)


def jaccard_similarity_from_token_sets(
    set_a: frozenset[str] | set[str],
    set_b: frozenset[str] | set[str],
    threshold: float = 0.0,
) -> float:
    """带集合大小比值上界剪枝（min_l / max_l < threshold）的快速 Jaccard 相似度计算。"""
    len_a = len(set_a)
    len_b = len(set_b)
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0
    if len_a >= len_b:
        max_l = len_a
        min_l = len_b
    else:
        max_l = len_b
        min_l = len_a
    if threshold > 0.0 and (min_l / max_l) < threshold:
        return 0.0
    inter_cnt = len(set_a & set_b)
    union_cnt = len_a + len_b - inter_cnt
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt


def jaccard_similarity_from_texts(
    title_a: str,
    body_a: str,
    title_b: str,
    body_b: str,
    threshold: float = 0.0,
) -> float:
    set_a = frozenset(tokenize_text(title_a) + tokenize_text(body_a))
    set_b = frozenset(tokenize_text(title_b) + tokenize_text(body_b))
    return jaccard_similarity_from_token_sets(set_a, set_b, threshold=threshold)


class DocIndexNode:
    """紧凑文档内存索引节点（使用 __slots__，仅保留 140 字符摘要 snippet，绝不常驻完整 raw body）。"""

    __slots__ = (
        "doc_id",
        "tenant_id",
        "category",
        "regulation_code",
        "canon_reg",
        "clearance_level",
        "risk_weight",
        "custom_tag",
        "title",
        "snippet",
        "status",
        "quarantined",
        "updated_at",
        "title_tf",
        "body_positions",
        "dedup_tokens",
        "all_terms",
        "external_refs",
        "internal_refs",
        "valid_citation_count",
    )

    def __init__(
        self,
        *,
        doc_id: str,
        tenant_id: str,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        body: str,
        status: str,
        quarantined: bool,
        updated_at: int,
    ) -> None:
        self.doc_id = doc_id
        self.tenant_id = tenant_id
        self.category = category
        self.regulation_code = regulation_code
        self.canon_reg = canonicalize_regulation_code(regulation_code)
        self.clearance_level = int(clearance_level)
        self.risk_weight = int(risk_weight)
        self.custom_tag = custom_tag
        self.title = title
        self.snippet = body[:140]
        self.status = status
        self.quarantined = bool(quarantined)
        self.updated_at = int(updated_at)

        t_tokens = tokenize_text(title)
        b_tokens = tokenize_text(body)
        self.title_tf: dict[str, int] = dict(Counter(t_tokens))
        self.body_positions: dict[str, tuple[int, ...]] = build_body_positions(b_tokens)
        self.dedup_tokens: frozenset[str] = frozenset(t_tokens + b_tokens)
        self.all_terms: frozenset[str] = self.dedup_tokens
        self.external_refs: set[str] = set()
        self.internal_refs: set[str] = set()
        self.valid_citation_count: int = 0

    @property
    def is_active_source(self) -> bool:
        return self.status == "ACTIVE" and not self.quarantined

    def update_content(
        self,
        *,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        body: str,
        status: str,
        quarantined: bool,
        updated_at: int,
    ) -> None:
        self.category = category
        self.regulation_code = regulation_code
        self.canon_reg = canonicalize_regulation_code(regulation_code)
        self.clearance_level = int(clearance_level)
        self.risk_weight = int(risk_weight)
        self.custom_tag = custom_tag
        self.title = title
        self.snippet = body[:140]
        self.status = status
        self.quarantined = bool(quarantined)
        self.updated_at = int(updated_at)

        t_tokens = tokenize_text(title)
        b_tokens = tokenize_text(body)
        self.title_tf = dict(Counter(t_tokens))
        self.body_positions = build_body_positions(b_tokens)
        self.dedup_tokens = frozenset(t_tokens + b_tokens)
        self.all_terms = self.dedup_tokens


class TenantDocIndex:
    """租户单篇增量倒排索引与内存反向引用图（reverse_dependents O(deg) 局部引用计数传播）。"""

    __slots__ = (
        "tenant_id",
        "doc_epoch",
        "docs",
        "active_doc_ids",
        "inverted_index",
        "reverse_dependents",
    )

    def __init__(self, tenant_id: str, doc_epoch: int) -> None:
        self.tenant_id = tenant_id
        self.doc_epoch = doc_epoch
        self.docs: dict[str, DocIndexNode] = {}
        self.active_doc_ids: set[str] = set()
        self.inverted_index: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}

    def _recompute_node_citations(self, node: DocIndexNode) -> None:
        valid_internal = 0
        for ref in node.internal_refs:
            target = self.docs.get(ref)
            if target is not None and target.is_active_source:
                valid_internal += 1
        node.valid_citation_count = len(node.external_refs) + valid_internal

    def _remove_postings(self, doc_id: str, terms: Iterable[str]) -> None:
        self.active_doc_ids.discard(doc_id)
        for tok in terms:
            postings = self.inverted_index.get(tok)
            if postings is not None:
                postings.discard(doc_id)
                if not postings:
                    self.inverted_index.pop(tok, None)

    def _add_postings(self, doc_id: str, terms: Iterable[str]) -> None:
        self.active_doc_ids.add(doc_id)
        for tok in terms:
            postings = self.inverted_index.get(tok)
            if postings is None:
                self.inverted_index[tok] = {doc_id}
            else:
                postings.add(doc_id)

    def _add_citations_to_node(self, node: DocIndexNode, citations: Iterable[str]) -> None:
        doc_id = node.doc_id
        for raw_ref in citations:
            ref = str(raw_ref or "").strip()
            if not ref or ref == doc_id:
                continue
            if ref.startswith("doc_"):
                if ref not in node.internal_refs:
                    node.internal_refs.add(ref)
                    deps = self.reverse_dependents.get(ref)
                    if deps is None:
                        self.reverse_dependents[ref] = {doc_id}
                    else:
                        deps.add(doc_id)
            else:
                node.external_refs.add(ref)

    def _propagate_reverse_dependents(self, source_doc_id: str) -> None:
        """当内部文档状态翻转时，仅沿 reverse_dependents[source_doc_id] 执行 O(deg) 局部计数更新。"""
        for dep_doc_id in self.reverse_dependents.get(source_doc_id, ()):
            dep_node = self.docs.get(dep_doc_id)
            if dep_node is not None:
                self._recompute_node_citations(dep_node)

    def upsert_single_doc(
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
        quarantined: bool,
        updated_at: int,
        new_citations: Iterable[str] = (),
        new_epoch: int,
    ) -> None:
        old_node = self.docs.get(doc_id)
        was_active = old_node.is_active_source if old_node is not None else False
        if old_node is not None:
            if was_active:
                self._remove_postings(doc_id, old_node.all_terms)
            old_node.update_content(
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                body=body,
                status=status,
                quarantined=quarantined,
                updated_at=updated_at,
            )
            node = old_node
        else:
            node = DocIndexNode(
                doc_id=doc_id,
                tenant_id=self.tenant_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                body=body,
                status=status,
                quarantined=quarantined,
                updated_at=updated_at,
            )
            self.docs[doc_id] = node

        self._add_citations_to_node(node, new_citations)
        self._recompute_node_citations(node)

        now_active = node.is_active_source
        if now_active:
            self._add_postings(doc_id, node.all_terms)

        if was_active != now_active:
            self._propagate_reverse_dependents(doc_id)
        self.doc_epoch = new_epoch

    def update_doc_state(
        self,
        doc_id: str,
        *,
        status: str | None = None,
        quarantined: bool | None = None,
        updated_at: int,
        new_epoch: int,
    ) -> None:
        node = self.docs.get(doc_id)
        if node is None:
            self.doc_epoch = new_epoch
            return
        was_active = node.is_active_source
        if status is not None:
            node.status = status
        if quarantined is not None:
            node.quarantined = bool(quarantined)
        node.updated_at = int(updated_at)
        now_active = node.is_active_source

        if was_active and not now_active:
            self._remove_postings(doc_id, node.all_terms)
            self._propagate_reverse_dependents(doc_id)
        elif not was_active and now_active:
            self._add_postings(doc_id, node.all_terms)
            self._propagate_reverse_dependents(doc_id)
        self.doc_epoch = new_epoch


_MAX_DOC_INDEXES = 128
_DOC_INDEXES: dict[tuple[str, str], TenantDocIndex] = {}


def _reset_doc_indexes(db_key: str) -> None:
    for k in [k for k in _DOC_INDEXES if k[0] == db_key]:
        _DOC_INDEXES.pop(k, None)


register_reset_callback(_reset_doc_indexes)


def _build_tenant_doc_index(db_path: str, tenant_id: str, target_epoch: int) -> TenantDocIndex:
    idx = TenantDocIndex(tenant_id, target_epoch)
    conn = open_connection(db_path)
    try:
        doc_rows = conn.execute(
            "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
            "risk_weight, custom_tag, title, body, status, quarantined, updated_at "
            "FROM compliance_docs WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        cite_rows = conn.execute(
            "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    for r in doc_rows:
        node = DocIndexNode(
            doc_id=str(r["doc_id"]),
            tenant_id=str(r["tenant_id"]),
            category=str(r["category"]),
            regulation_code=str(r["regulation_code"]),
            clearance_level=int(r["clearance_level"]),
            risk_weight=int(r["risk_weight"]),
            custom_tag=str(r["custom_tag"]),
            title=str(r["title"]),
            body=str(r["body"]),
            status=str(r["status"]),
            quarantined=int(r["quarantined"]) != 0,
            updated_at=int(r["updated_at"]),
        )
        idx.docs[node.doc_id] = node
        if node.is_active_source:
            idx._add_postings(node.doc_id, node.all_terms)

    cites_by_doc: dict[str, list[str]] = {}
    for cr in cite_rows:
        cites_by_doc.setdefault(str(cr["doc_id"]), []).append(str(cr["cited_by_ref"] or ""))

    for did, node in idx.docs.items():
        refs = cites_by_doc.get(did)
        if refs:
            idx._add_citations_to_node(node, refs)

    for node in idx.docs.values():
        idx._recompute_node_citations(node)

    return idx


def get_or_load_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    db_key = normalize_db_key(db_path)
    cur_epoch = get_tenant_epochs(db_path, tenant_id).doc_epoch
    cache_key = (db_key, tenant_id)
    idx = _DOC_INDEXES.get(cache_key)
    if idx is not None and idx.doc_epoch == cur_epoch:
        return idx

    with get_tenant_doc_lock(db_path, tenant_id):
        cur_epoch = get_tenant_epochs(db_path, tenant_id).doc_epoch
        idx = _DOC_INDEXES.get(cache_key)
        if idx is not None and idx.doc_epoch == cur_epoch:
            return idx
        idx = _build_tenant_doc_index(db_path, tenant_id, cur_epoch)
        if len(_DOC_INDEXES) >= _MAX_DOC_INDEXES and cache_key not in _DOC_INDEXES:
            _DOC_INDEXES.pop(next(iter(_DOC_INDEXES)), None)
        _DOC_INDEXES[cache_key] = idx
        return idx


def get_loaded_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex | None:
    """若当前租户文档索引已在内存中且与当前 doc_epoch 同步，则返回以执行单篇增量修改。"""
    db_key = normalize_db_key(db_path)
    cur_epoch = get_tenant_epochs(db_path, tenant_id).doc_epoch
    idx = _DOC_INDEXES.get((db_key, tenant_id))
    if idx is not None and idx.doc_epoch == cur_epoch:
        return idx
    return None
