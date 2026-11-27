# -*- coding: utf-8 -*-
"""合规文本分词、相邻查询词最小跨度邻近度加分与词袋相似度计算模块。

复杂度降维（输出与原版逐 token / 逐分值一致）：
- tokenize_text 单遍正则扫描（非法字符天然充当分隔符，等价于原版
  「re.sub 清洗 + findall」双遍结果）；
- compute_phrase_proximity_bonus 由 O(|pos_a| × |pos_b|) 笛卡尔配对降为
  「一次 O(N) 位置索引构建 + 有序位置表双指针线性归并」，并在 min_dist == 1
  处早停（1 为可能的最小距离，早停不改变结果）；
- jaccard_similarity_from_texts 由 O(NA × NB) 列表成员扫描降为 C 级集合
  交并运算，并加 min/max 集合大小比值上界剪枝（Jaccard ≤ min/max 恒成立，
  比值低于折叠阈值时真值必然低于阈值，返回 0.0 与精确值在阈值比较上决策等价）。
"""
from __future__ import annotations

import re

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def _min_token_distance(pos_a: list[int], pos_b: list[int]) -> int | None:
    """双指针归并求两有序位置表之间的最小绝对差（找到 1 即早停）。"""
    i = 0
    j = 0
    len_a = len(pos_a)
    len_b = len(pos_b)
    best: int | None = None
    while i < len_a and j < len_b:
        a = pos_a[i]
        b = pos_b[j]
        dist = a - b if a >= b else b - a
        if best is None or dist < best:
            best = dist
            if best <= 1:
                return best
        if a < b:
            i += 1
        else:
            j += 1
    return best


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分。

    规则：若去重查询词序列包含至少 2 个词项 (q_0, q_1, ..., q_{k-1})，
    对每个相邻词对 (q_m, q_{m+1})，找出它们在 body_tokens 中出现下标的最小绝对差 d = min |i - j|；
    若 1 <= d <= PROXIMITY_MAX_SPAN(6)，则累加 2.4 / d。
    """
    if len(query_terms) < 2 or not body_tokens:
        return 0.0

    # 一次 O(len(body_tokens)) 构建「词项 -> 有序出现位置表」索引。
    pos_map: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        lst = pos_map.get(tok)
        if lst is None:
            pos_map[tok] = [idx]
        else:
            lst.append(idx)

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

        min_dist = _min_token_distance(pos_a, pos_b)
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    set_a = set(tokenize_text(title_a)) | set(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b)) | set(tokenize_text(body_b))

    len_a = len(set_a)
    len_b = len(set_b)
    if len_a == 0 and len_b == 0:
        return 1.0
    if len_a == 0 or len_b == 0:
        inter_cnt = 0
        union_cnt = len_a + len_b
    else:
        # 上界剪枝：Jaccard ≤ min/max 恒成立；比值低于折叠阈值时真值必然更低，
        # 对全部「sim >= DEDUP_JACCARD_THRESHOLD」比较决策等价，直接返回 0.0。
        smaller, larger = (len_a, len_b) if len_a <= len_b else (len_b, len_a)
        if smaller / larger < DEDUP_JACCARD_THRESHOLD:
            return 0.0
        inter_cnt = len(set_a & set_b)
        union_cnt = len_a + len_b - inter_cnt

    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt
