# -*- coding: utf-8 -*-
"""合规文本分词、双指针相邻词距邻近度加分与集合剪枝相似度计算模块。"""
from __future__ import annotations

from array import array
import re
from typing import AbstractSet, Sequence

from .config import PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_NON_TOKEN_RE = re.compile(r"[^a-zA-Z0-9_]+")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    cleaned = _NON_TOKEN_RE.sub(" ", text).lower()
    return TOKEN_RE.findall(cleaned)


def _min_two_pointer_dist(pos_a: Sequence[int], pos_b: Sequence[int]) -> int | None:
    """在两个有序下标序列上执行 O(|pos_a| + |pos_b|) 双指针扫描，遇到距离 1 立即早停。"""
    ia = 0
    ib = 0
    na = len(pos_a)
    nb = len(pos_b)
    min_dist: int | None = None
    while ia < na and ib < nb:
        pa = pos_a[ia]
        pb = pos_b[ib]
        dist = pa - pb if pa >= pb else pb - pa
        if dist >= 1:
            if min_dist is None or dist < min_dist:
                min_dist = dist
                if min_dist == 1:
                    return 1
        if pa < pb:
            ia += 1
        else:
            ib += 1
    return min_dist


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针 + 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0

    wanted = set(query_terms)
    positions: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        if tok in wanted:
            positions.setdefault(tok, []).append(idx)

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
        min_dist = _min_two_pointer_dist(pos_a, pos_b)
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus_from_seq(
    body_seq: array,
    query_tids: list[int],
) -> float:
    """基于驻留词元 ID 紧凑数组的双指针邻近度加分。"""
    if len(query_tids) < 2 or not body_seq:
        return 0.0

    wanted = set(query_tids)
    positions: dict[int, list[int]] = {}
    for idx, tid in enumerate(body_seq):
        if tid in wanted:
            positions.setdefault(tid, []).append(idx)

    bonus = 0.0
    for idx in range(len(query_tids) - 1):
        ta = query_tids[idx]
        tb = query_tids[idx + 1]
        if ta == tb:
            continue
        pos_a = positions.get(ta)
        pos_b = positions.get(tb)
        if not pos_a or not pos_b:
            continue
        min_dist = _min_two_pointer_dist(pos_a, pos_b)
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def jaccard_similarity_from_sets(
    set_a: AbstractSet[int],
    set_b: AbstractSet[int],
    min_threshold: float = 0.0,
) -> float:
    """基于词元 ID 集合与大小比值剪枝的 O(min(|A|, |B|)) Jaccard 相似度计算。"""
    la = len(set_a)
    lb = len(set_b)
    if la == 0 and lb == 0:
        return 1.0
    if la == 0 or lb == 0:
        return 0.0
    min_l = la if la < lb else lb
    max_l = lb if la < lb else la
    if min_threshold > 0.0 and (min_l / max_l) < min_threshold:
        return 0.0
    smaller, larger = (set_a, set_b) if la <= lb else (set_b, set_a)
    inter_cnt = sum(1 for t in smaller if t in larger)
    union_cnt = la + lb - inter_cnt
    return inter_cnt / union_cnt if union_cnt > 0 else 0.0


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = set(tokenize_text(title_a)) | set(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b)) | set(tokenize_text(body_b))
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    inter_cnt = len(set_a & set_b)
    union_cnt = len(set_a) + len(set_b) - inter_cnt
    return inter_cnt / union_cnt if union_cnt > 0 else 0.0
