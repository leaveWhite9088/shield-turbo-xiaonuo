# -*- coding: utf-8 -*-
"""合规文本分词、紧凑单篇增量倒排索引、双向引用传播与双指针词距邻近度计算模块。"""
from __future__ import annotations

from collections import Counter
import pathlib
import re
import threading
from typing import Any

from .config import PROXIMITY_MAX_SPAN
from .db import get_domain_epoch, open_connection
from .legacy_compat import canonicalize_regulation_code

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def compute_phrase_proximity_bonus_from_positions(
    pos_map: dict[str, tuple[int, ...]],
    query_terms: list[str],
) -> float:
    """利用预计算的词项有序位置表，执行 O(|pos_a| + |pos_b|) 双指针扫描计算最小距离邻近度加分（含 min_dist==1 早停）。"""
    if len(query_terms) < 2 or not pos_map:
        return 0.0

    bonus = 0.0
    for idx in range(len(query_terms) - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = pos_map.get(term_a)
        pos_b = pos_map.get(term_b)
        if not pos_a or not pos_b:
            continue

        i = 0
        j = 0
        len_a = len(pos_a)
        len_b = len(pos_b)
        min_dist = PROXIMITY_MAX_SPAN + 1

        while i < len_a and j < len_b:
            pa = pos_a[i]
            pb = pos_b[j]
            diff = pa - pb
            if diff < 0:
                dist = -diff
                i += 1
            elif diff > 0:
                dist = diff
                j += 1
            else:
                i += 1
                continue
            if dist < min_dist:
                min_dist = dist
                if min_dist == 1:
                    break

        if 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针扫描 + min_dist==1 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0

    needed = set(query_terms)
    pos_lists: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        if tok in needed:
            pos_lists.setdefault(tok, []).append(idx)
    pos_map = {k: tuple(v) for k, v in pos_lists.items()}
    return compute_phrase_proximity_bonus_from_positions(pos_map, query_terms)


def jaccard_similarity_from_sets(set_a: frozenset[str], set_b: frozenset[str]) -> float:
    len_a = len(set_a)
    len_b = len(set_b)
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0
    inter_cnt = len(set_a & set_b)
    union_cnt = len_a + len_b - inter_cnt
    if union_cnt <= 0:
        return 0.0
    return inter_cnt / union_cnt


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = frozenset(tokenize_text(title_a) + tokenize_text(body_a))
    set_b = frozenset(tokenize_text(title_b) + tokenize_text(body_b))
    return jaccard_similarity_from_sets(set_a, set_b)


class CompactDocNode:
    """紧凑常驻文档索引节点（使用 __slots__ 消除 __dict__ 开销，仅保留 140 字符摘要，不常驻大体积原始 body）。"""

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
        "body_tf",
        "body_positions",
        "vocab_set",
        "all_terms",
        "external_refs",
        "internal_refs",
        "effective_citation_count",
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
        quarantined: int,
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
        self.quarantined = int(quarantined)
        self.updated_at = int(updated_at)

        t_tokens = tokenize_text(title)
        b_tokens = tokenize_text(body)
        self.title_tf: dict[str, int] = {k: min(v, 5) for k, v in Counter(t_tokens).items()}
        self.body_tf: dict[str, int] = {k: min(v, 12) for k, v in Counter(b_tokens).items()}

        pos_acc: dict[str, list[int]] = {}
        for idx, tok in enumerate(b_tokens):
            pos_acc.setdefault(tok, []).append(idx)
        self.body_positions: dict[str, tuple[int, ...]] = {k: tuple(v) for k, v in pos_acc.items()}

        v_set = frozenset(self.title_tf.keys()) | frozenset(self.body_tf.keys())
        self.vocab_set: frozenset[str] = v_set
        self.all_terms: tuple[str, ...] = tuple(v_set)
        self.external_refs: set[str] = set()
        self.internal_refs: set[str] = set()
        self.effective_citation_count: int = 0

    @property
    def is_searchable(self) -> bool:
        return self.status == "ACTIVE" and self.quarantined == 0


class TenantDocIndex:
    """租户级增量倒排索引与内存双向引用图（reverse_dependents 实现 O(deg) 引用状态传播）。"""

    __slots__ = (
        "tenant_id",
        "lock",
        "docs",
        "inverted",
        "reverse_dependents",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.lock = threading.RLock()
        self.docs: dict[str, CompactDocNode] = {}
        self.inverted: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}

    def _is_ref_active(self, ref_doc_id: str) -> bool:
        node = self.docs.get(ref_doc_id)
        return node is not None and node.is_searchable

    def _recompute_node_citations(self, node: CompactDocNode) -> None:
        cnt = len(node.external_refs)
        for iref in node.internal_refs:
            if self._is_ref_active(iref):
                cnt += 1
        node.effective_citation_count = cnt

    def _attach_inverted(self, node: CompactDocNode) -> None:
        if not node.is_searchable:
            return
        did = node.doc_id
        for term in node.all_terms:
            bucket = self.inverted.get(term)
            if bucket is None:
                bucket = set()
                self.inverted[term] = bucket
            bucket.add(did)

    def _detach_inverted(self, node: CompactDocNode) -> None:
        did = node.doc_id
        for term in node.all_terms:
            bucket = self.inverted.get(term)
            if bucket is not None:
                bucket.discard(did)
                if not bucket:
                    self.inverted.pop(term, None)

    def _notify_dependents(self, source_doc_id: str) -> None:
        dependents = self.reverse_dependents.get(source_doc_id)
        if not dependents:
            return
        for dep_doc_id in dependents:
            dep_node = self.docs.get(dep_doc_id)
            if dep_node is not None:
                self._recompute_node_citations(dep_node)

    def build_from_db(self, db_path: str) -> None:
        conn = open_connection(db_path)
        try:
            d_rows = conn.execute(
                "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
                "risk_weight, custom_tag, title, body, status, quarantined, updated_at "
                "FROM compliance_docs WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchall()
            c_rows = conn.execute(
                "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchall()
        finally:
            conn.close()

        with self.lock:
            self.docs.clear()
            self.inverted.clear()
            self.reverse_dependents.clear()

            for r in d_rows:
                node = CompactDocNode(
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
                    quarantined=int(r["quarantined"]),
                    updated_at=int(r["updated_at"]),
                )
                self.docs[node.doc_id] = node
                self._attach_inverted(node)

            for r in c_rows:
                did = str(r["doc_id"])
                ref = str(r["cited_by_ref"] or "").strip()
                if not ref or ref == did:
                    continue
                node = self.docs.get(did)
                if node is None:
                    continue
                if ref.startswith("doc_"):
                    node.internal_refs.add(ref)
                    self.reverse_dependents.setdefault(ref, set()).add(did)
                else:
                    node.external_refs.add(ref)

            for node in self.docs.values():
                self._recompute_node_citations(node)

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
        added_citations: list[str],
    ) -> None:
        with self.lock:
            old_node = self.docs.get(doc_id)
            was_active = old_node.is_searchable if old_node is not None else False
            new_node = CompactDocNode(
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
            if old_node is not None:
                self._detach_inverted(old_node)
                new_node.external_refs = set(old_node.external_refs)
                new_node.internal_refs = set(old_node.internal_refs)

            for raw_ref in added_citations:
                ref = str(raw_ref or "").strip()
                if not ref or ref == doc_id:
                    continue
                if ref.startswith("doc_"):
                    new_node.internal_refs.add(ref)
                    self.reverse_dependents.setdefault(ref, set()).add(doc_id)
                else:
                    new_node.external_refs.add(ref)

            self.docs[doc_id] = new_node
            self._attach_inverted(new_node)
            self._recompute_node_citations(new_node)

            if was_active != new_node.is_searchable:
                self._notify_dependents(doc_id)

    def apply_status_change(
        self,
        doc_id: str,
        *,
        status: str | None = None,
        quarantined: int | None = None,
        updated_at: int | None = None,
    ) -> None:
        with self.lock:
            node = self.docs.get(doc_id)
            if node is None:
                return
            was_active = node.is_searchable
            if was_active:
                self._detach_inverted(node)
            if status is not None:
                node.status = status
            if quarantined is not None:
                node.quarantined = int(quarantined)
            if updated_at is not None:
                node.updated_at = int(updated_at)
            now_active = node.is_searchable
            if now_active:
                self._attach_inverted(node)
            if was_active != now_active:
                self._notify_dependents(doc_id)


_INDEX_GUARD = threading.Lock()
_TENANT_INDICES: dict[str, TenantDocIndex] = {}


def get_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    db_key = str(pathlib.Path(db_path).resolve())
    key = f"{db_key}::{tenant_id}"
    with _INDEX_GUARD:
        idx = _TENANT_INDICES.get(key)
        if idx is not None:
            return idx
    new_idx = TenantDocIndex(tenant_id)
    new_idx.build_from_db(db_key)
    with _INDEX_GUARD:
        existing = _TENANT_INDICES.get(key)
        if existing is not None:
            return existing
        if len(_TENANT_INDICES) > 128:
            _TENANT_INDICES.pop(next(iter(_TENANT_INDICES)), None)
        _TENANT_INDICES[key] = new_idx
        return new_idx
