# -*- coding: utf-8 -*-
"""紧凑单篇增量倒排、双向有效引用图及线性文本算法。"""
from __future__ import annotations

from array import array
from collections import Counter, OrderedDict
import threading
from typing import Any, Iterable

from .config import PROXIMITY_MAX_SPAN
from .db import open_connection
from .legacy_compat import canonicalize_regulation_code
from .runtime import db_key

import re

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}", re.ASCII)


def tokenize_text(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower()) if text else []


def compute_phrase_proximity_bonus(body_tokens: list[str] | tuple[str, ...], query_terms: list[str]) -> float:
    """一次正文扫描建立所需位置表，每个相邻词对双指针求最小距离，d=1 早停。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    wanted = set(query_terms)
    positions: dict[str, list[int]] = {term: [] for term in wanted}
    for index, token in enumerate(body_tokens):
        if token in wanted:
            positions[token].append(index)
    bonus = 0.0
    for left, right in zip(query_terms, query_terms[1:]):
        if left == right:
            continue
        pos_a = positions.get(left, ())
        pos_b = positions.get(right, ())
        if not pos_a or not pos_b:
            continue
        i = j = 0
        minimum: int | None = None
        while i < len(pos_a) and j < len(pos_b):
            distance = abs(pos_a[i] - pos_b[j])
            if distance and (minimum is None or distance < minimum):
                minimum = distance
                if minimum == 1:
                    break
            if pos_a[i] < pos_b[j]:
                i += 1
            else:
                j += 1
        if minimum is not None and minimum <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(minimum)
    return bonus


def jaccard_similarity_from_sets(tokens_a: frozenset[str], tokens_b: frozenset[str]) -> float:
    if not tokens_a and not tokens_b:
        return 1.0
    small, large = (tokens_a, tokens_b) if len(tokens_a) <= len(tokens_b) else (tokens_b, tokens_a)
    intersection = sum(1 for token in small if token in large)
    union = len(tokens_a) + len(tokens_b) - intersection
    return intersection / union if union else 0.0


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = frozenset(tokenize_text(title_a) + tokenize_text(body_a))
    set_b = frozenset(tokenize_text(title_b) + tokenize_text(body_b))
    return jaccard_similarity_from_sets(set_a, set_b)


class DocEntry:
    """检索节点不保存原始 body，仅保留 140 字节摘要和检索所需紧凑词项。"""

    __slots__ = (
        "doc_id", "category", "regulation_code", "canon_reg", "clearance_level",
        "risk_weight", "custom_tag", "title", "snippet", "updated_at", "status",
        "quarantined", "title_counts", "body_counts", "body_tokens", "token_set",
        "citation_count",
    )

    def __init__(self, row: Any, intern: Any) -> None:
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
        # 租户内字符串 -> uint32 词元 ID；正文序列以 array('I') 紧凑驻留。
        self.title_counts = Counter(intern(token) for token in tokenize_text(self.title))
        self.body_tokens = array("I", (intern(token) for token in tokenize_text(body)))
        self.body_counts = Counter(self.body_tokens)
        self.token_set = frozenset(self.title_counts) | frozenset(self.body_counts)
        self.citation_count = 0

    @property
    def searchable(self) -> bool:
        return self.status == "ACTIVE" and self.quarantined == 0


class TenantDocIndex:
    """每租户独立 RLock；单篇写入只触碰该词项 posting 与引用反向边。"""

    def __init__(self, db_path: str, tenant_id: str) -> None:
        self.db_path = db_path
        self.tenant_id = tenant_id
        self.lock = threading.RLock()
        self.entries: dict[str, DocEntry] = {}
        self.token_ids: dict[str, int] = {}
        self.token_names: dict[int, str] = {}
        self.token_refcounts: Counter[int] = Counter()
        self.next_token_id = 1
        self.postings: dict[int, dict[str, None]] = {}
        self.title_postings: dict[int, dict[str, None]] = {}
        self.citations: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}
        self.revision = 0
        self.loaded = False

    def ensure_loaded(self) -> None:
        with self.lock:
            if self.loaded:
                return
            conn = open_connection(self.db_path)
            try:
                cursor = conn.execute(
                    "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, custom_tag, "
                    "title, body, updated_at, status, quarantined FROM compliance_docs "
                    "WHERE tenant_id = ? ORDER BY doc_id ASC",
                    (self.tenant_id,),
                )
                for row in cursor:
                    self._install(DocEntry(row, self._intern))
                cites = conn.execute(
                    "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ? ORDER BY citation_id ASC",
                    (self.tenant_id,),
                )
                for row in cites:
                    self._add_citation(
                        str(row["doc_id"]), str(row["cited_by_ref"] or "").strip(), recount=False,
                    )
                for entry in self.entries.values():
                    entry.citation_count = self._count_citations(entry.doc_id)
            finally:
                conn.close()
            self.loaded = True

    def _intern(self, token: str) -> int:
        token_id = self.token_ids.get(token)
        if token_id is None:
            token_id = self.next_token_id
            if token_id > 0xFFFFFFFF:
                raise ValueError("Tenant token vocabulary exceeds compact index capacity")
            self.next_token_id += 1
            self.token_ids[token] = token_id
            self.token_names[token_id] = token
        return token_id

    def _index_terms(self, entry: DocEntry, remove: bool = False) -> None:
        for token in entry.body_counts:
            mapping = self.postings.get(token)
            if remove:
                if mapping is not None:
                    mapping.pop(entry.doc_id, None)
                    if not mapping:
                        self.postings.pop(token, None)
            else:
                self.postings.setdefault(token, {})[entry.doc_id] = None
        for token in entry.title_counts:
            mapping = self.title_postings.get(token)
            if remove:
                if mapping is not None:
                    mapping.pop(entry.doc_id, None)
                    if not mapping:
                        self.title_postings.pop(token, None)
            else:
                self.title_postings.setdefault(token, {})[entry.doc_id] = None

    def _install(self, entry: DocEntry) -> None:
        previous = self.entries.get(entry.doc_id)
        previous_terms = set(previous.body_counts) | set(previous.title_counts) if previous else set()
        current_terms = set(entry.body_counts) | set(entry.title_counts)
        if previous is not None:
            self._index_terms(previous, remove=True)
        for token_id in previous_terms - current_terms:
            self.token_refcounts[token_id] -= 1
            if self.token_refcounts[token_id] <= 0:
                del self.token_refcounts[token_id]
                name = self.token_names.pop(token_id)
                self.token_ids.pop(name, None)
        for token_id in current_terms - previous_terms:
            self.token_refcounts[token_id] += 1
        self.entries[entry.doc_id] = entry
        self._index_terms(entry)

    def _add_citation(self, target: str, reference: str, *, recount: bool = True) -> None:
        if not reference or reference == target:
            return
        refs = self.citations.setdefault(target, set())
        if reference in refs:
            return
        refs.add(reference)
        if reference.startswith("doc_"):
            self.reverse_dependents.setdefault(reference, set()).add(target)
        entry = self.entries.get(target)
        if recount and entry is not None:
            entry.citation_count = self._count_citations(target)

    def _count_citations(self, target: str) -> int:
        count = 0
        for reference in self.citations.get(target, ()):
            if reference.startswith("doc_"):
                source = self.entries.get(reference)
                if source is None or not source.searchable:
                    continue
            count += 1
        return count

    def _refresh_dependents(self, source_doc_id: str) -> None:
        for target in self.reverse_dependents.get(source_doc_id, ()):
            entry = self.entries.get(target)
            if entry is not None:
                entry.citation_count = self._count_citations(target)

    def upsert(self, row: Any, citations: Iterable[str] = ()) -> None:
        with self.lock:
            self.ensure_loaded()
            old_id = str(row["doc_id"])
            self._install(DocEntry(row, self._intern))
            for reference in citations:
                self._add_citation(old_id, str(reference).strip())
            # 新文档/状态翻转既影响自己的目标计数，也影响引用它的目标。
            entry = self.entries[old_id]
            entry.citation_count = self._count_citations(old_id)
            self._refresh_dependents(old_id)
            self.revision += 1

    def set_state(self, doc_id: str, *, status: str | None = None, quarantined: bool | None = None, updated_at: int) -> None:
        with self.lock:
            self.ensure_loaded()
            entry = self.entries.get(doc_id)
            if entry is None:
                return
            if status is not None:
                entry.status = status
            if quarantined is not None:
                entry.quarantined = int(quarantined)
            entry.updated_at = int(updated_at)
            self._refresh_dependents(doc_id)
            self.revision += 1

    def candidates(self, query_terms: list[str], category: str, tag_filter: str) -> list[DocEntry]:
        self.ensure_loaded()
        if query_terms:
            ids: dict[str, None] = {}
            for term in query_terms:
                token_id = self.token_ids.get(term, -1)
                ids.update(self.postings.get(token_id, {}))
                ids.update(self.title_postings.get(token_id, {}))
            source = (self.entries[doc_id] for doc_id in ids)
        else:
            source = iter(self.entries.values())
        return [
            entry for entry in source
            if entry.searchable
            and (not category or entry.category == category)
            and (not tag_filter or entry.custom_tag == tag_filter)
        ]


_INDEXES: OrderedDict[tuple[str, str], TenantDocIndex] = OrderedDict()
_INDEXES_LOCK = threading.RLock()


def get_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    key = (db_key(db_path), tenant_id)
    with _INDEXES_LOCK:
        index = _INDEXES.get(key)
        if index is None:
            index = TenantDocIndex(db_path, tenant_id)
            _INDEXES[key] = index
            if len(_INDEXES) > 64:
                _INDEXES.popitem(last=False)
        else:
            _INDEXES.move_to_end(key)
        return index
