# -*- coding: utf-8 -*-
"""合规文档紧凑单篇增量倒排索引、内存双向引用传播图、双指针词距早停与剪枝去重引擎。"""
from __future__ import annotations

from array import array
from collections import Counter
import re
from typing import Any

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN
from .db import borrow_connection, get_db_hub
from .legacy_compat import canonicalize_regulation_code

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def compute_proximity_from_positions(
    body_pos: dict[str, Any],
    query_terms: list[str],
) -> float:
    """基于有序位置数组的双指针线性词距加分（min_dist == 1 立即早停）。"""
    n_terms = len(query_terms)
    if n_terms < 2 or not body_pos:
        return 0.0

    bonus = 0.0
    max_span = PROXIMITY_MAX_SPAN
    for idx in range(n_terms - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = body_pos.get(term_a)
        pos_b = body_pos.get(term_b)
        if not pos_a or not pos_b:
            continue

        ia = 0
        ib = 0
        na = len(pos_a)
        nb = len(pos_b)
        min_dist = max_span + 1
        while ia < na and ib < nb:
            pa = pos_a[ia]
            pb = pos_b[ib]
            if pa < pb:
                diff = pb - pa
                if diff < min_dist:
                    min_dist = diff
                    if min_dist == 1:
                        break
                ia += 1
            elif pb < pa:
                diff = pa - pb
                if diff < min_dist:
                    min_dist = diff
                    if min_dist == 1:
                        break
                ib += 1
            else:
                ia += 1

        if 1 <= min_dist <= max_span:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针 O(L) 实现）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    needed = set(query_terms)
    pos_map: dict[str, list[int]] = {}
    for i, tok in enumerate(body_tokens):
        if tok in needed:
            pos_map.setdefault(tok, []).append(i)
    return compute_proximity_from_positions(pos_map, query_terms)


def jaccard_similarity_from_sets(
    set_a: frozenset[str],
    len_a: int,
    set_b: frozenset[str],
    len_b: int,
    *,
    min_threshold: float = 0.0,
) -> float:
    """带集合大小比值剪枝（min_l / max_l < threshold）的紧凑词袋 Jaccard 计算。"""
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        return 0.0
    min_l = len_a if len_a < len_b else len_b
    max_l = len_b if len_a < len_b else len_a
    if min_threshold > 0.0 and (min_l / max_l) < min_threshold:
        return 0.0
    inter_cnt = len(set_a & set_b)
    union_cnt = len_a + len_b - inter_cnt
    if union_cnt <= 0:
        return 0.0
    return inter_cnt / union_cnt


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = frozenset(tokenize_text(title_a) + tokenize_text(body_a))
    set_b = frozenset(tokenize_text(title_b) + tokenize_text(body_b))
    return jaccard_similarity_from_sets(set_a, len(set_a), set_b, len(set_b))


class DocIndexNode:
    """紧凑常驻堆内存文档索引节点（__slots__，仅存 140 字符摘要，绝不常驻大体积原始 body）。"""

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
        "uniq_tokens",
        "uniq_len",
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
        title_tf: dict[str, int],
        body_pos: dict[str, Any],
        uniq_tokens: frozenset[str],
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
        self.uniq_tokens = uniq_tokens
        self.uniq_len = len(uniq_tokens)

    @property
    def is_searchable(self) -> bool:
        return self.status == "ACTIVE" and not self.quarantined

    def strip_retired_payload(self) -> None:
        self.title_tf = {}
        self.body_pos = {}
        self.uniq_tokens = frozenset()
        self.uniq_len = 0
        self.snippet = ""


class TenantDocIndex:
    """租户级单篇增量倒排索引与 O(deg) 双向引用有效计数传播图。"""

    __slots__ = (
        "tenant_id",
        "epoch",
        "_vocab",
        "nodes",
        "searchable_ids",
        "postings",
        "by_category",
        "by_tag",
        "external_refs",
        "internal_refs",
        "reverse_dependents",
        "active_ref_sources",
        "valid_citation_count",
    )

    def __init__(self, tenant_id: str, epoch: int) -> None:
        self.tenant_id = tenant_id
        self.epoch = epoch
        self._vocab: dict[str, str] = {}
        self.nodes: dict[str, DocIndexNode] = {}
        self.searchable_ids: set[str] = set()
        self.postings: dict[str, set[str]] = {}
        self.by_category: dict[str, set[str]] = {}
        self.by_tag: dict[str, set[str]] = {}
        self.external_refs: dict[str, set[str]] = {}
        self.internal_refs: dict[str, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}
        self.active_ref_sources: set[str] = set()
        self.valid_citation_count: dict[str, int] = {}

    def _intern(self, token: str) -> str:
        return self._vocab.setdefault(token, token)

    def _build_node(
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
    ) -> DocIndexNode:
        snippet = body[:140]
        if status != "ACTIVE":
            return DocIndexNode(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                snippet="",
                status=status,
                quarantined=quarantined,
                updated_at=updated_at,
                title_tf={},
                body_pos={},
                uniq_tokens=frozenset(),
            )

        intern = self._intern
        raw_t_tokens = tokenize_text(title)
        raw_b_tokens = tokenize_text(body)

        t_counts = Counter(raw_t_tokens)
        title_tf: dict[str, int] = {}
        uniq_set: set[str] = set()
        for tok, cnt in t_counts.items():
            itok = intern(tok)
            title_tf[itok] = cnt if cnt < 5 else 5
            uniq_set.add(itok)

        tmp_pos: dict[str, list[int]] = {}
        for idx, tok in enumerate(raw_b_tokens):
            itok = intern(tok)
            tmp_pos.setdefault(itok, []).append(idx)
            uniq_set.add(itok)

        arr_code = "H" if len(raw_b_tokens) < 65535 else "I"
        body_pos = {tok: array(arr_code, plist) for tok, plist in tmp_pos.items()}

        return DocIndexNode(
            doc_id=doc_id,
            category=category,
            regulation_code=regulation_code,
            clearance_level=clearance_level,
            risk_weight=risk_weight,
            custom_tag=custom_tag,
            title=title,
            snippet=snippet,
            status=status,
            quarantined=quarantined,
            updated_at=updated_at,
            title_tf=title_tf,
            body_pos=body_pos,
            uniq_tokens=frozenset(uniq_set),
        )

    def _mount_searchable(self, node: DocIndexNode) -> None:
        did = node.doc_id
        self.searchable_ids.add(did)
        self.by_category.setdefault(node.category, set()).add(did)
        self.by_tag.setdefault(node.custom_tag, set()).add(did)
        postings = self.postings
        for tok in node.uniq_tokens:
            postings.setdefault(tok, set()).add(did)

    def _unmount_searchable(self, node: DocIndexNode) -> None:
        did = node.doc_id
        self.searchable_ids.discard(did)
        cat_set = self.by_category.get(node.category)
        if cat_set is not None:
            cat_set.discard(did)
            if not cat_set:
                del self.by_category[node.category]
        tag_set = self.by_tag.get(node.custom_tag)
        if tag_set is not None:
            tag_set.discard(did)
            if not tag_set:
                del self.by_tag[node.custom_tag]
        postings = self.postings
        for tok in node.uniq_tokens:
            pset = postings.get(tok)
            if pset is not None:
                pset.discard(did)
                if not pset:
                    del postings[tok]

    def _update_ref_source_availability(self, doc_id: str, now_available: bool) -> None:
        """当本租户内部引用源状态（ACTIVE & not quarantined）翻转时，沿 reverse_dependents O(deg) 更新计数。"""
        if not doc_id.startswith("doc_"):
            return
        was_available = doc_id in self.active_ref_sources
        if was_available == now_available:
            return
        if now_available:
            self.active_ref_sources.add(doc_id)
            for dep_id in self.reverse_dependents.get(doc_id, ()):
                self.valid_citation_count[dep_id] = self.valid_citation_count.get(dep_id, 0) + 1
        else:
            self.active_ref_sources.discard(doc_id)
            for dep_id in self.reverse_dependents.get(doc_id, ()):
                self.valid_citation_count[dep_id] = self.valid_citation_count.get(dep_id, 0) - 1

    def _register_citations(self, doc_id: str, refs: list[str]) -> None:
        for raw_ref in refs:
            ref = str(raw_ref or "").strip()
            if not ref or ref == doc_id:
                continue
            if ref.startswith("doc_"):
                int_set = self.internal_refs.setdefault(doc_id, set())
                if ref not in int_set:
                    int_set.add(ref)
                    self.reverse_dependents.setdefault(ref, set()).add(doc_id)
                    if ref in self.active_ref_sources:
                        self.valid_citation_count[doc_id] = self.valid_citation_count.get(doc_id, 0) + 1
            else:
                ext_set = self.external_refs.setdefault(doc_id, set())
                if ref not in ext_set:
                    ext_set.add(ref)
                    self.valid_citation_count[doc_id] = self.valid_citation_count.get(doc_id, 0) + 1

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
        quarantined: bool,
        updated_at: int,
        new_citations: list[str],
        new_epoch: int,
    ) -> None:
        """单篇增量倒排更新与双向引用联动（零整表扫描，零整库索引推倒重建）。"""
        old_node = self.nodes.get(doc_id)
        if old_node is not None and old_node.is_searchable:
            self._unmount_searchable(old_node)

        new_node = self._build_node(
            doc_id=doc_id,
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
        self.nodes[doc_id] = new_node
        if new_node.is_searchable:
            self._mount_searchable(new_node)

        self._update_ref_source_availability(doc_id, new_node.is_searchable)
        if new_citations:
            self._register_citations(doc_id, new_citations)
        self.epoch = new_epoch

    def apply_quarantine(self, doc_id: str, quarantined: bool, updated_at: int, new_epoch: int) -> None:
        """单篇隔离/解封增量状态翻转（无需重读正文，无需重新分词）。"""
        node = self.nodes.get(doc_id)
        if node is not None:
            was_searchable = node.is_searchable
            node.quarantined = quarantined
            node.updated_at = updated_at
            now_searchable = node.is_searchable
            if was_searchable and not now_searchable:
                self._unmount_searchable(node)
            elif not was_searchable and now_searchable:
                self._mount_searchable(node)
            self._update_ref_source_availability(doc_id, now_searchable)
        self.epoch = new_epoch

    def apply_retire(self, doc_id: str, updated_at: int, new_epoch: int) -> None:
        """单篇退役下架增量摘除，并释放该节点词项载荷内存。"""
        node = self.nodes.get(doc_id)
        if node is not None:
            if node.is_searchable:
                self._unmount_searchable(node)
            node.status = "RETIRED"
            node.updated_at = updated_at
            node.strip_retired_payload()
            self._update_ref_source_availability(doc_id, False)
        self.epoch = new_epoch


def get_tenant_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    """获取租户级增量文档倒排索引；仅在首次挂载存量库或异常纪元失步时按游标流式构建一次。"""
    hub = get_db_hub(db_path)
    target_ep = hub.get_epochs(tenant_id).doc_epoch
    cached: TenantDocIndex | None = hub.doc_indices.get(tenant_id)
    if cached is not None and cached.epoch == target_ep:
        return cached

    with hub.tenant_doc_lock(tenant_id):
        target_ep = hub.get_epochs(tenant_id).doc_epoch
        cached = hub.doc_indices.get(tenant_id)
        if cached is not None and cached.epoch == target_ep:
            return cached

        idx = TenantDocIndex(tenant_id, target_ep)
        with borrow_connection(db_path) as conn:
            cur = conn.execute(
                "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
                "custom_tag, title, body, status, quarantined, updated_at "
                "FROM compliance_docs WHERE tenant_id = ?",
                (tenant_id,),
            )
            while True:
                batch = cur.fetchmany(256)
                if not batch:
                    break
                for r in batch:
                    did = str(r["doc_id"])
                    status = str(r["status"])
                    quarantined = int(r["quarantined"]) != 0
                    node = idx._build_node(
                        doc_id=did,
                        category=str(r["category"]),
                        regulation_code=str(r["regulation_code"]),
                        clearance_level=int(r["clearance_level"]),
                        risk_weight=int(r["risk_weight"]),
                        custom_tag=str(r["custom_tag"]),
                        title=str(r["title"]),
                        body=str(r["body"]) if status == "ACTIVE" else "",
                        status=status,
                        quarantined=quarantined,
                        updated_at=int(r["updated_at"]),
                    )
                    idx.nodes[did] = node
                    if node.is_searchable:
                        idx._mount_searchable(node)
                        if did.startswith("doc_"):
                            idx.active_ref_sources.add(did)

            cite_cur = conn.execute(
                "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                (tenant_id,),
            )
            while True:
                cbatch = cite_cur.fetchmany(512)
                if not cbatch:
                    break
                for cr in cbatch:
                    idx._register_citations(str(cr["doc_id"]), [str(cr["cited_by_ref"] or "")])

        hub.doc_indices.set(tenant_id, idx)
        return idx
