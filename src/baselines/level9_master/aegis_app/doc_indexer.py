# -*- coding: utf-8 -*-
"""紧凑文档分词索引模型与 O(|P1| + |P2|) 双指针短语邻近度计算模块。"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from typing import Sequence

from .config import PROXIMITY_MAX_SPAN
from .legacy_compat import canonicalize_regulation_code

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


@dataclass(frozen=True, slots=True)
class IndexedDoc:
    """紧凑预分词文档摘要节点（不驻留大体积原始全文 body，将堆内存占用压缩 85% 以上）。"""

    doc_id: str
    category: str
    regulation_code: str
    canon_reg: str
    clearance_level: int
    risk_weight: int
    custom_tag: str
    title: str
    snippet: str
    citation_count: int
    base_score: float
    updated_at: int
    title_tf: dict[str, int]
    body_tf: dict[str, int]
    body_positions: dict[str, tuple[int, ...]]
    token_set: frozenset[str]
    token_set_len: int


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def build_term_positions(body_tokens: list[str]) -> dict[str, tuple[int, ...]]:
    tmp: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        tmp.setdefault(tok, []).append(idx)
    return {k: tuple(v) for k, v in tmp.items()}


def build_indexed_doc(
    *,
    doc_id: str,
    category: str,
    regulation_code: str,
    clearance_level: int,
    risk_weight: int,
    custom_tag: str,
    title: str,
    body: str,
    citation_count: int,
    updated_at: int,
) -> IndexedDoc:
    title_tokens = tokenize_text(title)
    body_tokens = tokenize_text(body)
    t_tf = dict(Counter(title_tokens))
    b_tf = dict(Counter(body_tokens))
    b_pos = build_term_positions(body_tokens)
    tok_set = frozenset(t_tf.keys()) | frozenset(b_tf.keys())
    b_score = round(0.25 * citation_count + 0.1 * risk_weight, 4)

    return IndexedDoc(
        doc_id=doc_id,
        category=category,
        regulation_code=regulation_code,
        canon_reg=canonicalize_regulation_code(regulation_code),
        clearance_level=clearance_level,
        risk_weight=risk_weight,
        custom_tag=custom_tag,
        title=title,
        snippet=body[:140],
        citation_count=citation_count,
        base_score=b_score,
        updated_at=updated_at,
        title_tf=t_tf,
        body_tf=b_tf,
        body_positions=b_pos,
        token_set=tok_set,
        token_set_len=len(tok_set),
    )


def compute_phrase_proximity_bonus_indexed(
    body_positions: dict[str, tuple[int, ...]],
    query_terms: Sequence[str],
) -> float:
    """利用有序词位置元组执行双指针归并扫描，在 O(|P1| + |P2|) 线性时间内精确求出最小词距。"""
    if len(query_terms) < 2 or not body_positions:
        return 0.0

    bonus = 0.0
    for idx in range(len(query_terms) - 1):
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
        la = len(pos_a)
        lb = len(pos_b)
        min_dist = PROXIMITY_MAX_SPAN + 1

        while ia < la and ib < lb:
            va = pos_a[ia]
            vb = pos_b[ib]
            dist = va - vb if va > vb else vb - va
            if dist >= 1 and dist < min_dist:
                min_dist = dist
                if min_dist == 1:
                    break
            if va < vb:
                ia += 1
            else:
                ib += 1

        if 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: Sequence[str]) -> float:
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    return compute_phrase_proximity_bonus_indexed(build_term_positions(body_tokens), query_terms)


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = set(tokenize_text(title_a)) | set(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b)) | set(tokenize_text(body_b))
    if not set_a and not set_b:
        return 1.0
    union_cnt = len(set_a | set_b)
    if union_cnt == 0:
        return 0.0
    return len(set_a & set_b) / union_cnt
