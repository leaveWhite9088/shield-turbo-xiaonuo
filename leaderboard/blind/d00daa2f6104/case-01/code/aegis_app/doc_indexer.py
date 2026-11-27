# -*- coding: utf-8 -*-
"""紧凑单篇增量文档索引、词距算法与引用反向传播。"""
from __future__ import annotations

from array import array
from collections import Counter
from collections.abc import Sequence
import re
import threading
from typing import Any, Iterable

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN
from .db import open_connection
from .legacy_compat import canonicalize_regulation_code

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()
    return TOKEN_RE.findall(cleaned)


def _positions(tokens: Iterable[str]) -> dict[str, Sequence[int]]:
    mutable: dict[str, list[int]] = {}
    for idx, token in enumerate(tokens):
        mutable.setdefault(token, []).append(idx)
    # 位置使用 32 位紧凑数组，避免每个下标常驻一个 Python int 对象。
    return {term: array("I", pos) for term, pos in mutable.items()}


def compute_positions_proximity_bonus(
    body_positions: dict[str, Sequence[int]], query_terms: list[str]
) -> float:
    """有序位置表双指针求最小词距；任一词对距离为 1 时立即停止该对扫描。"""
    if len(query_terms) < 2 or not body_positions:
        return 0.0
    bonus = 0.0
    for term_a, term_b in zip(query_terms, query_terms[1:]):
        if term_a == term_b:
            continue
        pos_a = body_positions.get(term_a)
        pos_b = body_positions.get(term_b)
        if not pos_a or not pos_b:
            continue
        i = j = 0
        min_dist: int | None = None
        while i < len(pos_a) and j < len(pos_b):
            dist = abs(pos_a[i] - pos_b[j])
            if dist == 1:
                min_dist = 1
                break
            if dist and (min_dist is None or dist < min_dist):
                min_dist = dist
            if pos_a[i] < pos_b[j]:
                i += 1
            else:
                j += 1
        if min_dist is not None and min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    return compute_positions_proximity_bonus(_positions(body_tokens), query_terms)


def jaccard_similarity_sets(tokens_a: frozenset[str], tokens_b: frozenset[str]) -> float:
    if not tokens_a and not tokens_b:
        return 1.0
    len_a, len_b = len(tokens_a), len(tokens_b)
    if not len_a or not len_b:
        return 0.0
    if min(len_a, len_b) / max(len_a, len_b) < DEDUP_JACCARD_THRESHOLD:
        return 0.0
    small, large = (tokens_a, tokens_b) if len_a <= len_b else (tokens_b, tokens_a)
    intersection = sum(1 for token in small if token in large)
    return intersection / (len_a + len_b - intersection)


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    tokens_a = frozenset(tokenize_text(title_a) + tokenize_text(body_a))
    tokens_b = frozenset(tokenize_text(title_b) + tokenize_text(body_b))
    return jaccard_similarity_sets(tokens_a, tokens_b)


class DocNode:
    """检索所需紧凑快照；刻意不保存完整原始 body。"""

    __slots__ = (
        "doc_id", "category", "regulation_code", "canon_reg", "clearance_level",
        "risk_weight", "custom_tag", "title", "snippet", "updated_at", "status",
        "quarantined", "title_tf", "body_positions", "token_set", "citation_count",
    )

    def __init__(self, row: Any) -> None:
        self.doc_id = str(row["doc_id"])
        self.category = str(row["category"])
        self.regulation_code = str(row["regulation_code"])
        self.canon_reg = canonicalize_regulation_code(self.regulation_code)
        self.clearance_level = int(row["clearance_level"])
        self.risk_weight = int(row["risk_weight"])
        self.custom_tag = str(row["custom_tag"])
        self.title = str(row["title"])
        body = str(row["body"])
        self.snippet = body[:140]
        self.updated_at = int(row["updated_at"])
        self.status = str(row["status"])
        self.quarantined = int(row["quarantined"])
        self.title_tf = dict(Counter(tokenize_text(self.title)))
        self.body_positions = _positions(tokenize_text(body))
        self.token_set = frozenset(self.title_tf).union(self.body_positions)
        self.citation_count = 0

    def clone_metadata(self, **changes: Any) -> "DocNode":
        """状态翻转时复制节点外壳并共享不可变词项位置，避免读写竞争。"""
        other = object.__new__(DocNode)
        for name in self.__slots__:
            setattr(other, name, getattr(self, name))
        for name, value in changes.items():
            setattr(other, name, value)
        return other


_DOC_COLUMNS = (
    "doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
    "custom_tag, title, body, status, quarantined, updated_at"
)


class TenantDocumentIndex:
    """每租户独立索引；锁不跨租户，ACL 变化也不会使本索引失效。"""

    def __init__(self, db_path: str, tenant_id: str) -> None:
        self.db_path = str(db_path)
        self.tenant_id = tenant_id
        self.lock = threading.RLock()
        self.loaded = False
        self.epoch = 0
        self.docs: dict[str, DocNode] = {}
        self.term_docs: dict[str, set[str]] = {}
        self.citations: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}

    def ensure_loaded(self) -> None:
        if self.loaded:
            return
        conn = open_connection(self.db_path)
        try:
            cursor = conn.execute(
                f"SELECT {_DOC_COLUMNS} FROM compliance_docs WHERE tenant_id = ?",
                (self.tenant_id,),
            )
            for row in cursor:
                node = DocNode(row)
                self.docs[node.doc_id] = node
                self._add_postings(node)
            citation_cursor = conn.execute(
                "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                (self.tenant_id,),
            )
            for row in citation_cursor:
                target = str(row["doc_id"])
                ref = str(row["cited_by_ref"] or "").strip()
                if not ref or ref == target:
                    continue
                refs = self.citations.setdefault(target, set())
                if ref in refs:
                    continue
                refs.add(ref)
                if ref.startswith("doc_"):
                    self.reverse_dependents.setdefault(ref, set()).add(target)
        finally:
            conn.close()
        for target in self.citations:
            self._refresh_citation_count(target)
        self.loaded = True
        self.epoch += 1

    def _add_postings(self, node: DocNode) -> None:
        for term in node.token_set:
            self.term_docs.setdefault(term, set()).add(node.doc_id)

    def _remove_postings(self, node: DocNode) -> None:
        for term in node.token_set:
            postings = self.term_docs.get(term)
            if postings is not None:
                postings.discard(node.doc_id)
                if not postings:
                    del self.term_docs[term]

    def _valid_ref(self, target: str, ref: str) -> bool:
        if not ref or ref == target:
            return False
        if not ref.startswith("doc_"):
            return True
        source = self.docs.get(ref)
        return bool(
            source is not None
            and source.status == "ACTIVE"
            and source.quarantined == 0
        )

    def _refresh_citation_count(self, target: str) -> None:
        node = self.docs.get(target)
        if node is None:
            return
        count = sum(1 for ref in self.citations.get(target, ()) if self._valid_ref(target, ref))
        node.citation_count = count

    def _refresh_source_dependents(self, source_doc_id: str) -> None:
        # 仅访问引用该文档的目标节点：O(出度)，绝不重建整租户索引。
        for target in self.reverse_dependents.get(source_doc_id, ()):
            self._refresh_citation_count(target)

    def apply_upsert(self, row: Any, new_citations: Iterable[str] = ()) -> None:
        doc_id = str(row["doc_id"])
        previous = self.docs.get(doc_id)
        if previous is not None:
            self._remove_postings(previous)
        node = DocNode(row)
        self.docs[doc_id] = node
        self._add_postings(node)
        target = doc_id
        for raw_ref in new_citations:
            ref = str(raw_ref).strip()
            if not ref or ref == target:
                continue
            refs = self.citations.setdefault(target, set())
            if ref not in refs:
                refs.add(ref)
                if ref.startswith("doc_"):
                    self.reverse_dependents.setdefault(ref, set()).add(target)
        self._refresh_citation_count(target)
        # Upsert 可将旧 RETIRED 文档恢复 ACTIVE，须反向恢复其引用贡献。
        self._refresh_source_dependents(doc_id)
        self.epoch += 1

    def apply_state(
        self,
        doc_id: str,
        *,
        status: str | None = None,
        quarantined: int | None = None,
        updated_at: int | None = None,
    ) -> None:
        old = self.docs[doc_id]
        changes: dict[str, Any] = {}
        if status is not None:
            changes["status"] = status
        if quarantined is not None:
            changes["quarantined"] = quarantined
        if updated_at is not None:
            changes["updated_at"] = updated_at
        self.docs[doc_id] = old.clone_metadata(**changes)
        self._refresh_source_dependents(doc_id)
        self.epoch += 1

    def apply_acl_epoch_only(self) -> None:
        """保留接口以明确 ACL 与文档纪元解耦；本函数故意不清空索引。"""
        return


_INDEXES: dict[tuple[str, str], TenantDocumentIndex] = {}
_INDEXES_GUARD = threading.Lock()


def get_document_index(db_path: str, tenant_id: str) -> TenantDocumentIndex:
    key = (str(db_path), tenant_id)
    with _INDEXES_GUARD:
        index = _INDEXES.get(key)
        if index is None:
            index = TenantDocumentIndex(str(db_path), tenant_id)
            _INDEXES[key] = index
        return index
