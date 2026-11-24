# -*- coding: utf-8 -*-
"""合规文本分词、相邻查询词最小跨度邻近度加分与词袋相似度计算模块。"""
from __future__ import annotations

import re

from .config import PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()
    return [tok for tok in TOKEN_RE.findall(cleaned) if len(tok) >= 2]


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分。

    规则：若去重查询词序列包含至少 2 个词项 (q_0, q_1, ..., q_{k-1})，
    对每个相邻词对 (q_m, q_{m+1})，找出它们在 body_tokens 中出现下标的最小绝对差 d = min |i - j|；
    若 1 <= d <= PROXIMITY_MAX_SPAN(6)，则累加 2.4 / d。
    """
    if len(query_terms) < 2 or not body_tokens:
        return 0.0

    bonus = 0.0
    for idx in range(len(query_terms) - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = [i for i, tok in enumerate(body_tokens) if tok == term_a]
        pos_b = [j for j, tok in enumerate(body_tokens) if tok == term_b]
        if not pos_a or not pos_b:
            continue

        min_dist: int | None = None
        for i in pos_a:
            for j in pos_b:
                dist = abs(i - j)
                if dist >= 1 and (min_dist is None or dist < min_dist):
                    min_dist = dist
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    tokens_a = tokenize_text(title_a) + tokenize_text(body_a)
    tokens_b = tokenize_text(title_b) + tokenize_text(body_b)
    uniq_a: list[str] = []
    for t in tokens_a:
        if t not in uniq_a:
            uniq_a.append(t)
    uniq_b: list[str] = []
    for t in tokens_b:
        if t not in uniq_b:
            uniq_b.append(t)
    if not uniq_a and not uniq_b:
        return 1.0
    inter_cnt = sum(1 for t in uniq_a if t in uniq_b)
    union_cnt = len(uniq_a) + sum(1 for t in uniq_b if t not in uniq_a)
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt
