# -*- coding: utf-8 -*-
"""租户级紧凑增量倒排索引与双向有效引用传播图（__slots__ + 驻留词元 ID）。"""
from __future__ import annotations

from array import array
from collections import Counter
from typing import Any

from .doc_indexer import tokenize_text
from .legacy_compat import canonicalize_regulation_code
from .state import GatewayState, TenantState, TokenInterner


class CompactDocEntry:
    """单篇合规文档的紧凑内存索引节点（不保留大体积原始全文 body）。"""

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
        "body_tf",
        "body_seq",
        "uniq_tokens",
        "ext_refs",
        "int_refs",
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
        quarantined: int,
        updated_at: int,
        title_tf: dict[int, int],
        body_tf: dict[int, int],
        body_seq: array,
        uniq_tokens: frozenset[int],
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
        self.body_tf = body_tf
        self.body_seq = body_seq
        self.uniq_tokens = uniq_tokens
        self.ext_refs: set[str] = set()
        self.int_refs: set[str] = set()
        self.valid_citation_count = 0


def _build_entry(
    interner: TokenInterner,
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
) -> CompactDocEntry:
    t_tokens = tokenize_text(title)
    b_tokens = tokenize_text(body)
    t_ids = [interner.intern(t) for t in t_tokens]
    b_ids = [interner.intern(t) for t in b_tokens]
    title_tf = dict(Counter(t_ids))
    body_tf = dict(Counter(b_ids))
    body_seq = array("I", b_ids)
    uniq_tokens = frozenset(title_tf.keys()) | frozenset(body_tf.keys())
    return CompactDocEntry(
        doc_id=doc_id,
        category=category,
        regulation_code=regulation_code,
        clearance_level=clearance_level,
        risk_weight=risk_weight,
        custom_tag=custom_tag,
        title=title,
        snippet=body[:140],
        status=status,
        quarantined=quarantined,
        updated_at=updated_at,
        title_tf=title_tf,
        body_tf=body_tf,
        body_seq=body_seq,
        uniq_tokens=uniq_tokens,
    )


class TenantDocIndex:
    """单租户增量文档倒排索引 + 反向依赖引用图。"""

    def __init__(self, tenant_id: str, interner: TokenInterner) -> None:
        self.tenant_id = tenant_id
        self.interner = interner
        self.docs: dict[str, CompactDocEntry] = {}
        self.active_doc_ids: set[str] = set()
        self.inverted_index: dict[int, set[str]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}

    def _is_valid_source(self, doc_id: str) -> bool:
        e = self.docs.get(doc_id)
        return e is not None and e.status == "ACTIVE" and e.quarantined == 0

    def _add_to_inverted(self, entry: CompactDocEntry) -> None:
        did = entry.doc_id
        self.active_doc_ids.add(did)
        inv = self.inverted_index
        for tid in entry.uniq_tokens:
            postings = inv.get(tid)
            if postings is None:
                inv[tid] = {did}
            else:
                postings.add(did)

    def _remove_from_inverted(self, entry: CompactDocEntry) -> None:
        did = entry.doc_id
        self.active_doc_ids.discard(did)
        inv = self.inverted_index
        for tid in entry.uniq_tokens:
            postings = inv.get(tid)
            if postings is not None:
                postings.discard(did)
                if not postings:
                    del inv[tid]

    def _recompute_citation_count(self, entry: CompactDocEntry) -> None:
        cnt = len(entry.ext_refs)
        for ref_id in entry.int_refs:
            if self._is_valid_source(ref_id):
                cnt += 1
        entry.valid_citation_count = cnt

    def _propagate_source_flip(self, source_doc_id: str, old_valid: bool, new_valid: bool) -> None:
        if old_valid == new_valid:
            return
        delta = 1 if new_valid else -1
        for dep_id in self.reverse_dependents.get(source_doc_id, ()):
            dep_entry = self.docs.get(dep_id)
            if dep_entry is not None:
                dep_entry.valid_citation_count += delta

    def load_from_db(self, gw_state: GatewayState) -> None:
        with gw_state.pool.borrow() as conn:
            doc_rows = conn.execute(
                "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
                "custom_tag, title, body, status, quarantined, updated_at "
                "FROM compliance_docs WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchall()
            cite_rows = conn.execute(
                "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchall()

        for r in doc_rows:
            entry = _build_entry(
                self.interner,
                doc_id=r["doc_id"],
                category=r["category"],
                regulation_code=r["regulation_code"],
                clearance_level=int(r["clearance_level"]),
                risk_weight=int(r["risk_weight"]),
                custom_tag=r["custom_tag"],
                title=r["title"],
                body=r["body"],
                status=r["status"],
                quarantined=int(r["quarantined"]),
                updated_at=int(r["updated_at"]),
            )
            self.docs[entry.doc_id] = entry
            if entry.status == "ACTIVE" and entry.quarantined == 0:
                self._add_to_inverted(entry)

        for cr in cite_rows:
            did = cr["doc_id"]
            ref = str(cr["cited_by_ref"] or "").strip()
            entry = self.docs.get(did)
            if entry is None or not ref or ref == did:
                continue
            if ref.startswith("doc_"):
                entry.int_refs.add(ref)
                self.reverse_dependents.setdefault(ref, set()).add(did)
            else:
                entry.ext_refs.add(ref)

        for entry in self.docs.values():
            self._recompute_citation_count(entry)

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
        quarantined: int,
        updated_at: int,
        new_citations: list[str],
    ) -> None:
        old_entry = self.docs.get(doc_id)
        old_valid = self._is_valid_source(doc_id)
        if old_entry is not None and old_entry.doc_id in self.active_doc_ids:
            self._remove_from_inverted(old_entry)

        entry = _build_entry(
            self.interner,
            doc_id=doc_id,
            category=category,
            regulation_code=regulation_code,
            clearance_level=clearance_level,
            risk_weight=risk_weight,
            custom_tag=custom_tag,
            title=title,
            body=body,
            status="ACTIVE",
            quarantined=quarantined,
            updated_at=updated_at,
        )
        if old_entry is not None:
            entry.ext_refs = old_entry.ext_refs
            entry.int_refs = old_entry.int_refs

        for c_ref in new_citations:
            ref = str(c_ref or "").strip()
            if not ref or ref == doc_id:
                continue
            if ref.startswith("doc_"):
                entry.int_refs.add(ref)
                self.reverse_dependents.setdefault(ref, set()).add(doc_id)
            else:
                entry.ext_refs.add(ref)

        self.docs[doc_id] = entry
        if entry.status == "ACTIVE" and entry.quarantined == 0:
            self._add_to_inverted(entry)
        self._recompute_citation_count(entry)

        new_valid = self._is_valid_source(doc_id)
        self._propagate_source_flip(doc_id, old_valid, new_valid)

    def apply_status_change(
        self,
        doc_id: str,
        *,
        status: str | None = None,
        quarantined: int | None = None,
        updated_at: int,
    ) -> None:
        entry = self.docs.get(doc_id)
        if entry is None:
            return
        old_valid = self._is_valid_source(doc_id)
        if status is not None:
            entry.status = status
        if quarantined is not None:
            entry.quarantined = quarantined
        entry.updated_at = updated_at

        new_valid = self._is_valid_source(doc_id)
        if old_valid and not new_valid:
            self._remove_from_inverted(entry)
        elif not old_valid and new_valid:
            self._add_to_inverted(entry)

        self._propagate_source_flip(doc_id, old_valid, new_valid)


def get_or_load_doc_index(gw_state: GatewayState, t_state: TenantState) -> TenantDocIndex:
    """线程安全地懒加载并返回租户增量文档索引。"""
    idx = t_state.doc_index
    if idx is not None:
        return idx
    with t_state.doc_lock:
        idx = t_state.doc_index
        if idx is None:
            idx = TenantDocIndex(t_state.tenant_id, gw_state.interner)
            idx.load_from_db(gw_state)
            t_state.doc_index = idx
        return idx
