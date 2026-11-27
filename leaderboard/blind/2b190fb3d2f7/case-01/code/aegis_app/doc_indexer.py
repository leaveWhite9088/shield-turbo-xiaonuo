# -*- coding: utf-8 -*-
"""合规文本分词、双指针相邻查询词最小跨度邻近度加分与尺寸比剪枝词袋相似度模块。"""
from __future__ import annotations

import re
import sys

from .config import PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def build_body_positions(body_tokens: list[str]) -> dict[str, tuple[int, ...]]:
    """一次线性扫描构建词项到升序下标元组的紧凑位置映射（驻留字符串以压缩常驻堆内存）。"""
    pos_lists: dict[str, list[int]] = {}
    intern = sys.intern
    for idx, tok in enumerate(body_tokens):
        itok = intern(tok)
        lst = pos_lists.get(itok)
        if lst is None:
            pos_lists[itok] = [idx]
        else:
            lst.append(idx)
    return {k: tuple(v) for k, v in pos_lists.items()}


def compute_phrase_proximity_from_positions(
    body_pos: dict[str, tuple[int, ...]],
    query_terms: list[str],
) -> float:
    """基于预建升序位置表执行 O(|P_a| + |P_b|) 双指针扫描（min_dist == 1 立即早停）。"""
    qlen = len(query_terms)
    if qlen < 2 or not body_pos:
        return 0.0

    bonus = 0.0
    max_span = PROXIMITY_MAX_SPAN
    for idx in range(qlen - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = body_pos.get(term_a)
        if not pos_a:
            continue
        pos_b = body_pos.get(term_b)
        if not pos_b:
            continue

        i = 0
        j = 0
        la = len(pos_a)
        lb = len(pos_b)
        min_dist = max_span + 1

        while i < la and j < lb:
            pa = pos_a[i]
            pb = pos_b[j]
            d = pa - pb if pa >= pb else pb - pa
            if d >= 1 and d < min_dist:
                min_dist = d
                if min_dist == 1:
                    break
            if pa < pb:
                i += 1
            else:
                j += 1

        if 1 <= min_dist <= max_span:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（双指针 O(|P_a|+|P_b|) + min_dist==1 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    qset = set(query_terms)
    pos_lists: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        if tok in qset:
            lst = pos_lists.get(tok)
            if lst is None:
                pos_lists[tok] = [idx]
            else:
                lst.append(idx)
    if len(pos_lists) < 2:
        return 0.0
    pos_tuples = {k: tuple(v) for k, v in pos_lists.items()}
    return compute_phrase_proximity_from_positions(pos_tuples, query_terms)


def jaccard_similarity_sets(
    set_a: frozenset[str] | set[str],
    set_b: frozenset[str] | set[str],
    *,
    min_threshold: float = 0.0,
) -> float:
    """基于集合大小比值剪枝的精确 Jaccard 相似度计算。"""
    la = len(set_a)
    lb = len(set_b)
    if la == 0 and lb == 0:
        return 1.0
    if la == 0 or lb == 0:
        return 0.0

    if la <= lb:
        small, big, min_l, max_l = set_a, set_b, la, lb
    else:
        small, big, min_l, max_l = set_b, set_a, lb, la

    # 尺寸比值上界剪枝：Jaccard <= min_l / max_l
    if min_threshold > 0.0 and (min_l / max_l) < min_threshold:
        return 0.0

    inter = 0
    for tok in small:
        if tok in big:
            inter += 1
    union = la + lb - inter
    if union == 0:
        return 0.0
    return inter / union


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = set(tokenize_text(title_a))
    set_a.update(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b))
    set_b.update(tokenize_text(body_b))
    return jaccard_similarity_sets(set_a, set_b)
