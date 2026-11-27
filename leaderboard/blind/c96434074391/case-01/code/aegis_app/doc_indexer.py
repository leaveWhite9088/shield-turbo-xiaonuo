# -*- coding: utf-8 -*-
"""合规文本紧凑分词、双指针早停词距、集合比值剪枝去重与单篇增量倒排/双向引用索引引擎。"""
from __future__ import annotations

import re
from typing import Any

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN
from .db import DatabaseRuntime
from .legacy_compat import canonicalize_regulation_code

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def _min_distance_two_pointers(pos_a: tuple[int, ...] | list[int], pos_b: tuple[int, ...] | list[int]) -> int:
    """在两个严格递增位置序列上做 O(|A| + |B|) 双指针扫描，并在 min_dist == 1 时立即早停。"""
    la = len(pos_a)
    lb = len(pos_b)
    ia = 0
    ib = 0
    min_dist = PROXIMITY_MAX_SPAN + 1

    while ia < la and ib < lb:
        pa = pos_a[ia]
        pb = pos_b[ib]
        diff = pa - pb
        if diff < 0:
            d = -diff
            if d < min_dist:
                min_dist = d
                if min_dist == 1:
                    return 1
            ia += 1
        elif diff > 0:
            if diff < min_dist:
                min_dist = diff
                if min_dist == 1:
                    return 1
            ib += 1
        else:
            ia += 1
    return min_dist


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针线性扫描 + 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0

    needed = set(query_terms)
    pos_map: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        if tok in needed:
            pos_map.setdefault(tok, []).append(idx)

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
        min_dist = _min_distance_two_pointers(pos_a, pos_b)
        if 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_proximity_from_term_ids(
    body_pos_by_id: dict[int, tuple[int, ...]],
    query_term_ids: list[int | None],
) -> float:
    """直接基于预构建紧凑词项 ID 位置元组执行双指针邻近度加分。"""
    if len(query_term_ids) < 2 or not body_pos_by_id:
        return 0.0

    bonus = 0.0
    for idx in range(len(query_term_ids) - 1):
        ta = query_term_ids[idx]
        tb = query_term_ids[idx + 1]
        if ta is None or tb is None or ta == tb:
            continue
        pos_a = body_pos_by_id.get(ta)
        pos_b = body_pos_by_id.get(tb)
        if not pos_a or not pos_b:
            continue
        min_dist = _min_distance_two_pointers(pos_a, pos_b)
        if 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def is_jaccard_cluster_match(
    terms_a: frozenset[int],
    terms_b: frozenset[int],
    threshold: float = DEDUP_JACCARD_THRESHOLD,
) -> bool:
    """带集合大小比值上界剪枝（min_l / max_l < threshold）的快速 Jaccard 阈值判定。"""
    la = len(terms_a)
    lb = len(terms_b)
    if la == 0 and lb == 0:
        return 1.0 >= threshold
    if la == 0 or lb == 0:
        return False

    min_l, max_l = (la, lb) if la <= lb else (lb, la)
    if min_l / max_l < threshold:
        return False

    inter = len(terms_a & terms_b)
    union = la + lb - inter
    return union > 0 and (inter / union) >= threshold


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = set(tokenize_text(title_a))
    set_a.update(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b))
    set_b.update(tokenize_text(body_b))
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    inter = len(set_a & set_b)
    union = len(set_a) + len(set_b) - inter
    return inter / union if union > 0 else 0.0


class CompactDocNode:
    """紧凑常驻文档索引节点（使用 __slots__，剥离原始全文 body，仅保留 140 字符摘要与整数词项特征）。"""

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
        "status",
        "quarantined",
        "updated_at",
        "title_tf",
        "body_pos",
        "uniq_terms",
        "raw_citations",
        "ext_cite_count",
        "int_cite_sources",
        "valid_citation_count",
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
        snippet: str,
        status: str,
        quarantined: bool,
        updated_at: int,
        title_tf: dict[int, int],
        body_pos: dict[int, tuple[int, ...]],
        uniq_terms: frozenset[int],
    ) -> None:
        self.doc_id = doc_id
        self.category = category
        self.regulation_code = regulation_code
        self.canon_reg = canonicalize_regulation_code(regulation_code)
        self.clearance_level = clearance_level
        self.risk_weight = risk_weight
        self.custom_tag = custom_tag
        self.title = title
        self.snippet = snippet
        self.status = status
        self.quarantined = quarantined
        self.updated_at = updated_at
        self.title_tf = title_tf
        self.body_pos = body_pos
        self.uniq_terms = uniq_terms
        self.raw_citations: set[str] = set()
        self.ext_cite_count = 0
        self.int_cite_sources: set[str] = set()
        self.valid_citation_count = 0


class TenantDocIndex:
    """租户级紧凑单篇增量倒排索引与双向内部引用依赖图（独立 doc_epoch）。"""

    __slots__ = (
        "tenant_id",
        "doc_epoch",
        "_term_to_id",
        "_next_term_id",
        "docs",
        "active_searchable_ids",
        "inverted",
        "by_category",
        "by_tag",
        "reverse_dependents",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.doc_epoch = 1
        self._term_to_id: dict[str, int] = {}
        self._next_term_id = 1
        self.docs: dict[str, CompactDocNode] = {}
        self.active_searchable_ids: set[str] = set()
        self.inverted: dict[int, set[str]] = {}
        self.by_category: dict[str, set[str]] = {}
        self.by_tag: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}

    def intern_term(self, term: str) -> int:
        tid = self._term_to_id.get(term)
        if tid is None:
            tid = self._next_term_id
            self._next_term_id = tid + 1
            self._term_to_id[term] = tid
        return tid

    def lookup_term_id(self, term: str) -> int | None:
        return self._term_to_id.get(term)

    def _encode_text_features(
        self,
        title: str,
        body: str,
    ) -> tuple[dict[int, int], dict[int, tuple[int, ...]], frozenset[int]]:
        t_counts: dict[int, int] = {}
        for tok in tokenize_text(title):
            tid = self.intern_term(tok)
            prev = t_counts.get(tid, 0)
            if prev < 5:
                t_counts[tid] = prev + 1

        b_lists: dict[int, list[int]] = {}
        for pos, tok in enumerate(tokenize_text(body)):
            tid = self.intern_term(tok)
            lst = b_lists.get(tid)
            if lst is None:
                b_lists[tid] = [pos]
            else:
                lst.append(pos)

        b_pos = {tid: tuple(positions) for tid, positions in b_lists.items()}
        uniq = frozenset(t_counts.keys() | b_pos.keys())
        return t_counts, b_pos, uniq

    def _is_valid_internal_source(self, doc_id: str) -> bool:
        node = self.docs.get(doc_id)
        return node is not None and node.status == "ACTIVE" and not node.quarantined

    def _mount_searchable(self, node: CompactDocNode) -> None:
        did = node.doc_id
        self.active_searchable_ids.add(did)
        self.by_category.setdefault(node.category, set()).add(did)
        self.by_tag.setdefault(node.custom_tag, set()).add(did)
        for tid in node.uniq_terms:
            self.inverted.setdefault(tid, set()).add(did)

    def _unmount_searchable(self, node: CompactDocNode) -> None:
        did = node.doc_id
        self.active_searchable_ids.discard(did)
        cat_set = self.by_category.get(node.category)
        if cat_set is not None:
            cat_set.discard(did)
        tag_set = self.by_tag.get(node.custom_tag)
        if tag_set is not None:
            tag_set.discard(did)
        for tid in node.uniq_terms:
            post = self.inverted.get(tid)
            if post is not None:
                post.discard(did)

    def _attach_citation_ref(self, node: CompactDocNode, raw_ref: str) -> bool:
        """向节点增量挂载单条引用并注册 reverse_dependents，返回是否为首次新增引用。"""
        ref = raw_ref.strip()
        if not ref or ref == node.doc_id or ref in node.raw_citations:
            return False
        node.raw_citations.add(ref)
        if ref.startswith("doc_"):
            node.int_cite_sources.add(ref)
            self.reverse_dependents.setdefault(ref, set()).add(node.doc_id)
            if self._is_valid_internal_source(ref):
                node.valid_citation_count += 1
        else:
            node.ext_cite_count += 1
            node.valid_citation_count += 1
        return True

    def _propagate_source_validity_change(self, src_doc_id: str, was_valid: bool, now_valid: bool) -> None:
        """当内部文档源状态翻转时，沿 reverse_dependents 做 O(deg) 局部增量引用计数更新。"""
        if was_valid == now_valid:
            return
        delta = 1 if now_valid else -1
        for dep_doc_id in self.reverse_dependents.get(src_doc_id, ()):
            dep_node = self.docs.get(dep_doc_id)
            if dep_node is not None:
                dep_node.valid_citation_count += delta

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
        quarantined: bool,
        updated_at: int,
        citations: list[str],
    ) -> None:
        was_valid = self._is_valid_internal_source(doc_id)
        t_tf, b_pos, u_terms = self._encode_text_features(title, body)
        snippet = body[:140]

        existing = self.docs.get(doc_id)
        if existing is not None:
            if doc_id in self.active_searchable_ids:
                self._unmount_searchable(existing)
            existing.category = category
            existing.regulation_code = regulation_code
            existing.canon_reg = canonicalize_regulation_code(regulation_code)
            existing.clearance_level = clearance_level
            existing.risk_weight = risk_weight
            existing.custom_tag = custom_tag
            existing.title = title
            existing.snippet = snippet
            existing.status = "ACTIVE"
            existing.quarantined = quarantined
            existing.updated_at = updated_at
            existing.title_tf = t_tf
            existing.body_pos = b_pos
            existing.uniq_terms = u_terms
            target_node = existing
        else:
            target_node = CompactDocNode(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                snippet=snippet,
                status="ACTIVE",
                quarantined=quarantined,
                updated_at=updated_at,
                title_tf=t_tf,
                body_pos=b_pos,
                uniq_terms=u_terms,
            )
            self.docs[doc_id] = target_node

        for c_ref in citations:
            self._attach_citation_ref(target_node, c_ref)

        if target_node.status == "ACTIVE" and not target_node.quarantined:
            self._mount_searchable(target_node)

        now_valid = self._is_valid_internal_source(doc_id)
        self._propagate_source_validity_change(doc_id, was_valid, now_valid)
        self.doc_epoch += 1

    def apply_quarantine(self, doc_id: str, quarantined: bool, updated_at: int) -> None:
        node = self.docs.get(doc_id)
        if node is None:
            return
        was_valid = self._is_valid_internal_source(doc_id)
        if doc_id in self.active_searchable_ids and quarantined:
            self._unmount_searchable(node)
        node.quarantined = quarantined
        node.updated_at = updated_at
        now_valid = self._is_valid_internal_source(doc_id)
        if now_valid and doc_id not in self.active_searchable_ids:
            self._mount_searchable(node)
        self._propagate_source_validity_change(doc_id, was_valid, now_valid)
        self.doc_epoch += 1

    def apply_retire(self, doc_id: str, updated_at: int) -> None:
        node = self.docs.get(doc_id)
        if node is None:
            return
        was_valid = self._is_valid_internal_source(doc_id)
        if doc_id in self.active_searchable_ids:
            self._unmount_searchable(node)
        node.status = "RETIRED"
        node.updated_at = updated_at
        self._propagate_source_validity_change(doc_id, was_valid, False)
        self.doc_epoch += 1


def _load_tenant_doc_index(rt: DatabaseRuntime, tenant_id: str) -> TenantDocIndex:
    idx = TenantDocIndex(tenant_id)
    with rt.read_conn() as conn:
        doc_cur = conn.execute(
            "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, body, status, quarantined, updated_at "
            "FROM compliance_docs WHERE tenant_id = ?",
            (tenant_id,),
        )
        while True:
            batch = doc_cur.fetchmany(256)
            if not batch:
                break
            for r in batch:
                did = str(r["doc_id"])
                title = str(r["title"])
                body = str(r["body"])
                t_tf, b_pos, u_terms = idx._encode_text_features(title, body)
                node = CompactDocNode(
                    doc_id=did,
                    category=str(r["category"]),
                    regulation_code=str(r["regulation_code"]),
                    clearance_level=int(r["clearance_level"]),
                    risk_weight=int(r["risk_weight"]),
                    custom_tag=str(r["custom_tag"]),
                    title=title,
                    snippet=body[:140],
                    status=str(r["status"]),
                    quarantined=bool(int(r["quarantined"])),
                    updated_at=int(r["updated_at"]),
                    title_tf=t_tf,
                    body_pos=b_pos,
                    uniq_terms=u_terms,
                )
                idx.docs[did] = node
                if node.status == "ACTIVE" and not node.quarantined:
                    idx._mount_searchable(node)

        cite_cur = conn.execute(
            "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
            (tenant_id,),
        )
        while True:
            c_batch = cite_cur.fetchmany(512)
            if not c_batch:
                break
            for cr in c_batch:
                node = idx.docs.get(str(cr["doc_id"]))
                if node is not None:
                    idx._attach_citation_ref(node, str(cr["cited_by_ref"] or ""))
    return idx


def get_tenant_doc_index(rt: DatabaseRuntime, tenant_id: str) -> TenantDocIndex:
    cached = rt.doc_index_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.tenant_meta_lock(tenant_id):
        cached = rt.doc_index_cache.get(tenant_id)
        if cached is not None:
            return cached
        loaded = _load_tenant_doc_index(rt, tenant_id)
        rt.doc_index_cache.set(tenant_id, loaded)
        return loaded
