# -*- coding: utf-8 -*-
"""合规文本分词、双指针词距邻近度、紧凑单篇增量倒排索引与反向引用图模块。"""
from __future__ import annotations

from array import array
from collections import Counter
import re
from typing import Any, Sequence

from .config import PROXIMITY_MAX_SPAN
from .legacy_compat import canonicalize_regulation_code
from .runtime import GatewayRuntime, get_runtime

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_ASCII_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return [tok.lower() for tok in _ASCII_TOKEN_RE.findall(text)]


def compute_min_pair_distance(pos_a: Sequence[int], pos_b: Sequence[int]) -> int | None:
    """对两个单调递增位置序列执行 O(|Pa| + |Pb|) 双指针最小距离扫描，并在 min_dist == 1 时早停。"""
    na = len(pos_a)
    nb = len(pos_b)
    if na == 0 or nb == 0:
        return None
    i = 0
    j = 0
    min_dist = PROXIMITY_MAX_SPAN + 1
    while i < na and j < nb:
        pa = pos_a[i]
        pb = pos_b[j]
        if pa < pb:
            d = pb - pa
            i += 1
        elif pb < pa:
            d = pa - pb
            j += 1
        else:
            # d == 0 忽略（原规则要求 dist >= 1）
            i += 1
            continue
        if d < min_dist:
            min_dist = d
            if min_dist == 1:
                return 1
    return min_dist if min_dist <= PROXIMITY_MAX_SPAN else None


def compute_phrase_proximity_bonus_from_positions(
    body_pos: dict[int, array],
    query_term_ids: Sequence[int],
) -> float:
    """直接基于紧凑整数词项位置表计算相邻查询词最小跨度邻近度加分（零重新分词）。"""
    if len(query_term_ids) < 2 or not body_pos:
        return 0.0
    bonus = 0.0
    for idx in range(len(query_term_ids) - 1):
        tid_a = query_term_ids[idx]
        tid_b = query_term_ids[idx + 1]
        if tid_a < 0 or tid_b < 0 or tid_a == tid_b:
            continue
        pos_a = body_pos.get(tid_a)
        if not pos_a:
            continue
        pos_b = body_pos.get(tid_b)
        if not pos_b:
            continue
        min_dist = compute_min_pair_distance(pos_a, pos_b)
        if min_dist is not None:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针 O(L + sum|P|) + d==1 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    qset = set(query_terms)
    positions: dict[str, list[int]] = {}
    for pos, tok in enumerate(body_tokens):
        if tok in qset:
            positions.setdefault(tok, []).append(pos)

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
        min_dist = compute_min_pair_distance(pos_a, pos_b)
        if min_dist is not None:
            bonus += 2.4 / float(min_dist)
    return bonus


def jaccard_similarity_sets(
    set_a: frozenset[Any] | set[Any],
    set_b: frozenset[Any] | set[Any],
    *,
    threshold: float | None = None,
) -> float:
    """基于集合大小比值剪枝与 C 级集合求交计算 Jaccard 相似度。"""
    la = len(set_a)
    lb = len(set_b)
    if la == 0 and lb == 0:
        return 1.0
    if la == 0 or lb == 0:
        return 0.0
    if la <= lb:
        small, large, min_l, max_l = set_a, set_b, la, lb
    else:
        small, large, min_l, max_l = set_b, set_a, lb, la

    # 数学剪枝：Jaccard(A, B) <= min(|A|,|B|) / max(|A|,|B|)
    if threshold is not None and (min_l / max_l) < (threshold - 1e-12):
        return 0.0

    inter = len(small & large)
    union = la + lb - inter
    return inter / union if union > 0 else 0.0


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = set(tokenize_text(title_a))
    set_a.update(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b))
    set_b.update(tokenize_text(body_b))
    return jaccard_similarity_sets(set_a, set_b)


class _CompactDocNode:
    """__slots__ 紧凑文档索引节点：绝不常驻完整原始 body，仅保留 140 字摘要与整数词项位置数组。"""

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
        "token_ids",
        "ext_refs",
        "internal_refs",
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
        snippet: str,
        updated_at: int,
        title_tf: dict[int, int],
        body_pos: dict[int, array],
        token_ids: frozenset[int],
        ext_refs: set[str],
        internal_refs: set[str],
        citation_count: int,
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
        self.updated_at = updated_at
        self.title_tf = title_tf
        self.body_pos = body_pos
        self.token_ids = token_ids
        self.ext_refs = ext_refs
        self.internal_refs = internal_refs
        self.citation_count = citation_count


class TenantDocIndex:
    """租户隔离的紧凑单篇增量倒排索引 + 内存反向引用图（reverse_dependents）。"""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.term_to_id: dict[str, int] = {}
        self.nodes: dict[str, _CompactDocNode] = {}
        self.postings: dict[int, set[str]] = {}
        self.by_category: dict[str, set[str]] = {}
        self.by_tag: dict[str, set[str]] = {}
        self.active_docs: set[str] = set()
        # 严格本租户文档有效状态映射：doc_id -> (status == 'ACTIVE' and quarantined == 0)
        self.doc_valid_status: dict[str, bool] = {}
        # 反向引用图：src_doc_id (doc_*) -> set[引用了 src_doc_id 的本租户活跃 doc_id]
        self.reverse_dependents: dict[str, set[str]] = {}

    def _intern(self, term: str) -> int:
        tid = self.term_to_id.get(term)
        if tid is None:
            tid = len(self.term_to_id)
            self.term_to_id[term] = tid
        return tid

    def lookup_term_ids(self, terms: Sequence[str]) -> list[int]:
        tmap = self.term_to_id
        return [tmap.get(t, -1) for t in terms]

    def _build_node_tokens(
        self,
        title: str,
        body: str,
    ) -> tuple[dict[int, int], dict[int, array], frozenset[int]]:
        title_tf: dict[int, int] = {}
        for tok, cnt in Counter(tokenize_text(title)).items():
            title_tf[self._intern(tok)] = cnt

        raw_pos: dict[int, list[int]] = {}
        for pos, tok in enumerate(tokenize_text(body)):
            tid = self._intern(tok)
            lst = raw_pos.get(tid)
            if lst is None:
                raw_pos[tid] = [pos]
            else:
                lst.append(pos)

        body_pos: dict[int, array] = {tid: array("I", plist) for tid, plist in raw_pos.items()}
        all_ids = set(title_tf.keys())
        all_ids.update(body_pos.keys())
        return title_tf, body_pos, frozenset(all_ids)

    def _attach_node(self, node: _CompactDocNode) -> None:
        did = node.doc_id
        self.nodes[did] = node
        self.active_docs.add(did)
        self.by_category.setdefault(node.category, set()).add(did)
        self.by_tag.setdefault(node.custom_tag, set()).add(did)
        for tid in node.token_ids:
            p = self.postings.get(tid)
            if p is None:
                self.postings[tid] = {did}
            else:
                p.add(did)
        for src_id in node.internal_refs:
            deps = self.reverse_dependents.get(src_id)
            if deps is None:
                self.reverse_dependents[src_id] = {did}
            else:
                deps.add(did)

    def _detach_node(self, doc_id: str) -> _CompactDocNode | None:
        old = self.nodes.pop(doc_id, None)
        if old is None:
            return None
        self.active_docs.discard(doc_id)
        cat_set = self.by_category.get(old.category)
        if cat_set is not None:
            cat_set.discard(doc_id)
            if not cat_set:
                self.by_category.pop(old.category, None)
        tag_set = self.by_tag.get(old.custom_tag)
        if tag_set is not None:
            tag_set.discard(doc_id)
            if not tag_set:
                self.by_tag.pop(old.custom_tag, None)
        for tid in old.token_ids:
            p = self.postings.get(tid)
            if p is not None:
                p.discard(doc_id)
                if not p:
                    self.postings.pop(tid, None)
        for src_id in old.internal_refs:
            deps = self.reverse_dependents.get(src_id)
            if deps is not None:
                deps.discard(doc_id)
                if not deps:
                    self.reverse_dependents.pop(src_id, None)
        return old

    def _propagate_source_status_change(self, src_doc_id: str, was_valid: bool, now_valid: bool) -> None:
        """O(deg(src)) 反向引用图局部传播：仅更新直接引用了 src_doc_id 的本租户活跃文档 citation_count。"""
        if was_valid == now_valid:
            return
        delta = 1 if now_valid else -1
        deps = self.reverse_dependents.get(src_doc_id)
        if not deps:
            return
        for dep_id in deps:
            dep_node = self.nodes.get(dep_id)
            if dep_node is not None:
                dep_node.citation_count += delta

    def _split_refs(self, doc_id: str, raw_refs: Sequence[str]) -> tuple[set[str], set[str]]:
        ext_refs: set[str] = set()
        internal_refs: set[str] = set()
        for raw in raw_refs:
            ref = str(raw or "").strip()
            if not ref or ref == doc_id:
                continue
            if ref.startswith("doc_"):
                internal_refs.add(ref)
            else:
                ext_refs.add(ref)
        return ext_refs, internal_refs

    def _compute_valid_citations(self, ext_refs: set[str], internal_refs: set[str]) -> int:
        valid_internal = 0
        status_map = self.doc_valid_status
        for src_id in internal_refs:
            if status_map.get(src_id, False):
                valid_internal += 1
        return len(ext_refs) + valid_internal

    @classmethod
    def load(cls, rt: GatewayRuntime, tenant_id: str) -> "TenantDocIndex":
        idx = cls(tenant_id)
        with rt.read_conn() as conn:
            # 第一遍：极轻量读取所有本租户文档有效状态（不含 body）
            st_cur = conn.execute(
                "SELECT doc_id, status, quarantined FROM compliance_docs WHERE tenant_id = ?",
                (tenant_id,),
            )
            for r in st_cur:
                idx.doc_valid_status[str(r["doc_id"])] = (
                    str(r["status"]) == "ACTIVE" and int(r["quarantined"]) == 0
                )

            # 第二遍：预聚合本租户引用关系
            cites_by_doc: dict[str, tuple[set[str], set[str]]] = {}
            c_cur = conn.execute(
                "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                (tenant_id,),
            )
            while True:
                batch = c_cur.fetchmany(512)
                if not batch:
                    break
                for r in batch:
                    did = str(r["doc_id"])
                    if not idx.doc_valid_status.get(did, False):
                        continue
                    ref = str(r["cited_by_ref"] or "").strip()
                    if not ref or ref == did:
                        continue
                    pair = cites_by_doc.get(did)
                    if pair is None:
                        pair = (set(), set())
                        cites_by_doc[did] = pair
                    if ref.startswith("doc_"):
                        pair[1].add(ref)
                    else:
                        pair[0].add(ref)

            # 第三遍：流式读取活跃且未隔离文档，逐批分词后立即释放原始大 body
            d_cur = conn.execute(
                "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
                "custom_tag, title, body, updated_at "
                "FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
                (tenant_id,),
            )
            while True:
                rows = d_cur.fetchmany(256)
                if not rows:
                    break
                for r in rows:
                    did = str(r["doc_id"])
                    title = str(r["title"])
                    body = str(r["body"])
                    title_tf, body_pos, token_ids = idx._build_node_tokens(title, body)
                    ext_refs, internal_refs = cites_by_doc.pop(did, (set(), set()))
                    cite_cnt = idx._compute_valid_citations(ext_refs, internal_refs)
                    node = _CompactDocNode(
                        doc_id=did,
                        category=str(r["category"]),
                        regulation_code=str(r["regulation_code"]),
                        clearance_level=int(r["clearance_level"]),
                        risk_weight=int(r["risk_weight"]),
                        custom_tag=str(r["custom_tag"]),
                        title=title,
                        snippet=body[:140],
                        updated_at=int(r["updated_at"]),
                        title_tf=title_tf,
                        body_pos=body_pos,
                        token_ids=token_ids,
                        ext_refs=ext_refs,
                        internal_refs=internal_refs,
                        citation_count=cite_cnt,
                    )
                    idx._attach_node(node)
        return idx

    def apply_upsert(
        self,
        rt: GatewayRuntime,
        *,
        doc_id: str,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        body: str,
        quarantined: int,
        updated_at: int,
        new_citations: Sequence[str],
    ) -> None:
        """单篇增量更新倒排索引与双向引用图（O(|doc| + deg)，绝不重建整租户索引）。"""
        was_valid = self.doc_valid_status.get(doc_id, False)
        now_valid = quarantined == 0
        self.doc_valid_status[doc_id] = now_valid

        old_node = self._detach_node(doc_id)

        if now_valid:
            if old_node is not None:
                ext_refs = set(old_node.ext_refs)
                internal_refs = set(old_node.internal_refs)
            else:
                # 可能是从 RETIRED 复活的新文档，从 DB 读单篇历史 citations 保证引用不丢
                with rt.read_conn() as conn:
                    c_rows = conn.execute(
                        "SELECT cited_by_ref FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
                        (self.tenant_id, doc_id),
                    ).fetchall()
                ext_refs, internal_refs = self._split_refs(
                    doc_id, [str(r["cited_by_ref"]) for r in c_rows]
                )

            if new_citations:
                add_ext, add_int = self._split_refs(doc_id, new_citations)
                ext_refs.update(add_ext)
                internal_refs.update(add_int)

            title_tf, body_pos, token_ids = self._build_node_tokens(title, body)
            cite_cnt = self._compute_valid_citations(ext_refs, internal_refs)
            new_node = _CompactDocNode(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                snippet=body[:140],
                updated_at=updated_at,
                title_tf=title_tf,
                body_pos=body_pos,
                token_ids=token_ids,
                ext_refs=ext_refs,
                internal_refs=internal_refs,
                citation_count=cite_cnt,
            )
            self._attach_node(new_node)

        self._propagate_source_status_change(doc_id, was_valid, now_valid)

    def apply_status_change(
        self,
        rt: GatewayRuntime,
        *,
        doc_id: str,
        now_valid: bool,
        updated_at: int,
    ) -> None:
        """单篇退役/隔离/解封增量状态翻转 + O(deg) 反向引用传播。"""
        was_valid = self.doc_valid_status.get(doc_id, False)
        self.doc_valid_status[doc_id] = now_valid

        if not now_valid:
            self._detach_node(doc_id)
        else:
            existing = self.nodes.get(doc_id)
            if existing is not None:
                existing.updated_at = updated_at
            else:
                # 单篇解封上线：仅点查该篇文档与该篇引用记录，挂载回倒排表
                with rt.read_conn() as conn:
                    row = conn.execute(
                        "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
                        "custom_tag, title, body, status, quarantined, updated_at "
                        "FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                        (self.tenant_id, doc_id),
                    ).fetchone()
                    if row and str(row["status"]) == "ACTIVE" and int(row["quarantined"]) == 0:
                        c_rows = conn.execute(
                            "SELECT cited_by_ref FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
                            (self.tenant_id, doc_id),
                        ).fetchall()
                        ext_refs, internal_refs = self._split_refs(
                            doc_id, [str(r["cited_by_ref"]) for r in c_rows]
                        )
                        title = str(row["title"])
                        body = str(row["body"])
                        title_tf, body_pos, token_ids = self._build_node_tokens(title, body)
                        cite_cnt = self._compute_valid_citations(ext_refs, internal_refs)
                        node = _CompactDocNode(
                            doc_id=doc_id,
                            category=str(row["category"]),
                            regulation_code=str(row["regulation_code"]),
                            clearance_level=int(row["clearance_level"]),
                            risk_weight=int(row["risk_weight"]),
                            custom_tag=str(row["custom_tag"]),
                            title=title,
                            snippet=body[:140],
                            updated_at=int(row["updated_at"]),
                            title_tf=title_tf,
                            body_pos=body_pos,
                            token_ids=token_ids,
                            ext_refs=ext_refs,
                            internal_refs=internal_refs,
                            citation_count=cite_cnt,
                        )
                        self._attach_node(node)

        self._propagate_source_status_change(doc_id, was_valid, now_valid)


def get_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    rt = get_runtime(db_path)
    idx = rt.doc_indices.get(tenant_id)
    if idx is not None:
        return idx
    with rt.doc_lock(tenant_id):
        idx = rt.doc_indices.get(tenant_id)
        if idx is None:
            idx = TenantDocIndex.load(rt, tenant_id)
            rt.doc_indices[tenant_id] = idx
        return idx
