# -*- coding: utf-8 -*-
"""合规文本分词、相邻查询词最小跨度邻近度加分与词袋相似度计算模块。

本模块承担三项 **复杂度降维** 改造（与原版逐对比对实现等价，输出分毫不差）：

1. **分词**：原实现先 ``re.sub`` 清洗整串（产生一份等长副本）再正则扫描；
   现改为直接在规范化小写串上单次扫描，词元集合完全一致。

2. **邻近度**：原实现对每一对相邻查询词做「出现位置笛卡尔积」比对，
   复杂度 O(P·N²)。现改为「位置表 + 双指针归并」，复杂度 O(P·N)，
   且当最小跨度已抵达理论下界 1 时立即早停。

3. **Jaccard**：原实现用「有序去重列表 + 线性成员判定」构造集合，
   复杂度 O(N²)。现改为原生集合运算，复杂度 O(N)；
   并提供「集合大小比值剪枝」——由 Jaccard ≤ min(|A|,|B|)/max(|A|,|B|)
   可知，当该比值已低于阈值时两簇 **数学上不可能** 合并，可安全跳过。
"""
from __future__ import annotations

import re
from typing import Iterable

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    """把文本切分为规范化词元序列（与历史实现完全等价）。"""
    if not text:
        return []
    return TOKEN_RE.findall(text.lower())


def build_token_positions(tokens: Iterable[str]) -> dict[str, list[int]]:
    """一次性构建「词元 -> 升序出现下标」位置表，供双指针邻近度扫描复用。"""
    positions: dict[str, list[int]] = {}
    for idx, tok in enumerate(tokens):
        bucket = positions.get(tok)
        if bucket is None:
            positions[tok] = [idx]
        else:
            bucket.append(idx)
    return positions


def _min_token_distance(pos_a: list[int], pos_b: list[int]) -> int | None:
    """两个升序位置表之间的最小下标距离（双指针归并，O(n+m)）。"""
    i = 0
    j = 0
    best: int | None = None
    len_a = len(pos_a)
    len_b = len(pos_b)
    while i < len_a and j < len_b:
        a = pos_a[i]
        b = pos_b[j]
        dist = a - b
        if dist == 0:
            # 理论上不同词元不会同位；防御性跳过并推进。
            i += 1
            continue
        if dist < 0:
            dist = -dist
        if best is None or dist < best:
            best = dist
            if best == 1:
                # 理论下界：跨度 1 已是最小可能值，立即早停。
                return 1
        if a < b:
            i += 1
        else:
            j += 1
    return best


def compute_proximity_bonus_from_positions(
    positions: dict[str, list[int]],
    query_terms: list[str],
) -> float:
    """基于位置表计算相邻查询词对的最小跨度邻近度加分。"""
    if len(query_terms) < 2 or not positions:
        return 0.0

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
        min_dist = _min_token_distance(pos_a, pos_b)
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分。

    规则：若去重查询词序列包含至少 2 个词项 (q_0, q_1, ..., q_{k-1})，
    对每个相邻词对 (q_m, q_{m+1})，找出它们在 body_tokens 中出现下标的最小绝对差 d = min |i - j|；
    若 1 <= d <= PROXIMITY_MAX_SPAN(6)，则累加 2.4 / d。
    """
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    return compute_proximity_bonus_from_positions(
        build_token_positions(body_tokens), query_terms
    )


def jaccard_from_token_sets(set_a: set[str], set_b: set[str]) -> float:
    """基于词元集合计算 Jaccard 相似度（与历史列表实现逐位等价）。"""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    inter = len(set_a & set_b)
    union = len(set_a) + len(set_b) - inter
    if union == 0:
        return 0.0
    return inter / union


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    """基于文本计算 Jaccard 相似度（保留历史对外签名）。"""
    set_a = set(tokenize_text(title_a)) | set(tokenize_text(body_a))
    set_b = set(tokenize_text(title_b)) | set(tokenize_text(body_b))
    return jaccard_from_token_sets(set_a, set_b)


def jaccard_may_exceed_threshold(
    size_a: int,
    size_b: int,
    threshold: float = DEDUP_JACCARD_THRESHOLD,
) -> bool:
    """集合大小比值剪枝：Jaccard <= min(|A|,|B|) / max(|A|,|B|)。

    当该上界已低于阈值时，两簇 **数学上不可能** 达到合并条件，可安全跳过，
    将近似去重的比较次数从 O(N²) 降为 O(N·k)（k 为规模相近的簇数）。
    """
    if size_a <= 0 or size_b <= 0:
        return False
    smaller = size_a if size_a < size_b else size_b
    larger = size_b if size_a < size_b else size_a
    return (smaller / larger) >= threshold
