# -*- coding: utf-8 -*-
"""合规文本分词、相邻查询词最小跨度邻近度加分与词袋相似度计算模块。

性能契约：
- 邻近度由"枚举全部位置对" O(P_a * P_b) 降维为"双指针归并扫描" O(P_a + P_b)，
  并在 min_dist == 1 时提前短路（不可能更小）；
- Jaccard 由 list 线性成员判断 O(U_a * U_b) 降维为 frozenset 交并 O(U_a + U_b)；
  两者输出与原版逐位一致。
"""
from __future__ import annotations

import re
from bisect import bisect_left
from typing import Mapping, Sequence

from .config import PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()
    return [tok for tok in TOKEN_RE.findall(cleaned) if len(tok) >= 2]


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """兼容入口：对原始正文词序列计算相邻查询词对的最小距离邻近度加分。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    positions: dict[str, list[int]] = {}
    for i, tok in enumerate(body_tokens):
        positions.setdefault(tok, []).append(i)
    return compute_phrase_proximity_bonus_from_positions(positions, query_terms)


def _min_token_distance(pos_a: Sequence[int], pos_b: Sequence[int]) -> int | None:
    """双指针扫描两个升序位置序列，返回最小绝对差；相等距离 0（同 token 不可能共位）按原版语义排除为 >=1。"""
    i = 0
    j = 0
    best: int | None = None
    la = len(pos_a)
    lb = len(pos_b)
    while i < la and j < lb:
        a = pos_a[i]
        b = pos_b[j]
        if a == b:
            # 同一下标不可能对应两个不同 token；此分支仅防御重复调用，向右推进较小者
            if i + 1 < la and (j + 1 >= lb or pos_a[i + 1] <= pos_b[j + 1]):
                i += 1
            else:
                j += 1
            continue
        dist = a - b if a > b else b - a
        if best is None or dist < best:
            best = dist
            if best == 1:
                return 1  # 早停：1 已是除 0 外的最小可能值
        if a < b:
            i += 1
        else:
            j += 1
    return best


def compute_phrase_proximity_bonus_from_positions(
    body_positions: Mapping[str, Sequence[int]],
    query_terms: list[str],
) -> float:
    """基于预建倒排位置表计算相邻查询词对邻近度加分（与原版输出逐位一致）。

    规则：对每个相邻词对 (q_m, q_{m+1})（q_m != q_{m+1}），取两词在正文中的
    最小绝对下标差 d；若 1 <= d <= PROXIMITY_MAX_SPAN(6)，累加 2.4 / d。
    """
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

        min_dist = _min_token_distance(pos_a, pos_b)
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    """兼容入口：基于原始文本的词袋 Jaccard 相似度。"""
    uniq_a = frozenset(tokenize_text(title_a) + tokenize_text(body_a))
    uniq_b = frozenset(tokenize_text(title_b) + tokenize_text(body_b))
    return jaccard_similarity_from_sets(uniq_a, uniq_b)


def jaccard_similarity_from_sets(uniq_a: frozenset[str], uniq_b: frozenset[str]) -> float:
    """集合版词袋 Jaccard 相似度（与原版 list 去重实现输出一致）。"""
    if not uniq_a and not uniq_b:
        return 1.0
    inter_cnt = len(uniq_a & uniq_b)
    union_cnt = len(uniq_a) + len(uniq_b) - inter_cnt
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt


def min_len_ratio_prunable(len_a: int, len_b: int, threshold: float) -> bool:
    """集合大小比值剪枝：Jaccard <= min/max，若 min/max < threshold 则不可能达标。

    双空集相似度恒为 1.0（与原版一致），不可剪枝。
    """
    if len_a == 0 and len_b == 0:
        return False
    if len_a == 0 or len_b == 0:
        return True  # 单侧空集：交集为 0，Jaccard = 0 < threshold，可安全剪枝
    smaller = len_a if len_a <= len_b else len_b
    larger = len_b if len_a <= len_b else len_a
    return (smaller / larger) < threshold
