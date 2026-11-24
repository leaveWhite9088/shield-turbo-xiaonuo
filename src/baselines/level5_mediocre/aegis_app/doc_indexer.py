# -*- coding: utf-8 -*-
"""合规文本分词与邻近度打分（5级平庸样本：未建立位置倒排表，仍逐对嵌套扫描下标距离）。"""
from __future__ import annotations

import re

from .config import PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
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
    set_a = set(tokenize_text(title_a) + tokenize_text(body_a))
    set_b = set(tokenize_text(title_b) + tokenize_text(body_b))
    if not set_a and not set_b:
        return 1.0
    union_cnt = len(set_a | set_b)
    if union_cnt == 0:
        return 0.0
    return len(set_a & set_b) / union_cnt
