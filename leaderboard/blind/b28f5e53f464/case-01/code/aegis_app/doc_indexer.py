# -*- coding: utf-8 -*-
"""合规文本分词、相邻查询词双指针邻近度加分与剪枝词袋相似度计算模块。"""
from __future__ import annotations

from array import array
import re

from .config import DEDUP_JACCARD_THRESHOLD, PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-zA-Z0-9_]{2,}")


def tokenize_text(text: str) -> list[str]:
    if not text:
        return []
    return [tok.lower() for tok in TOKEN_RE.findall(text)]


def _min_two_pointer_dist(pos_a: list[int], pos_b: list[int]) -> int | None:
    """在两个有序位置序列上用双指针求最小非零距离，命中距离 1 时立即早停。"""
    la = len(pos_a)
    lb = len(pos_b)
    if la == 0 or lb == 0:
        return None
    p = 0
    q = 0
    min_dist = PROXIMITY_MAX_SPAN + 1
    while p < la and q < lb:
        i = pos_a[p]
        j = pos_b[q]
        dist = i - j if i > j else j - i
        if 1 <= dist < min_dist:
            min_dist = dist
            if min_dist == 1:
                return 1
        if i < j:
            p += 1
        else:
            q += 1
    return min_dist if min_dist <= PROXIMITY_MAX_SPAN else None


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """计算相邻查询词对在正文词序列中的最小距离邻近度加分（单趟扫描 + 双指针 + d==1 早停）。

    规则：若去重查询词序列包含至少 2 个词项 (q_0, q_1, ..., q_{k-1})，
    对每个相邻词对 (q_m, q_{m+1})，找出它们在 body_tokens 中出现下标的最小绝对差 d = min |i - j|；
    若 1 <= d <= PROXIMITY_MAX_SPAN(6)，则累加 2.4 / d。
    """
    if len(query_terms) < 2 or not body_tokens:
        return 0.0

    q_set = set(query_terms)
    pos_map: dict[str, list[int]] = {}
    for idx, tok in enumerate(body_tokens):
        if tok in q_set:
            lst = pos_map.get(tok)
            if lst is None:
                pos_map[tok] = [idx]
            else:
                lst.append(idx)

    if len(pos_map) < 2:
        return 0.0

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
        min_dist = _min_two_pointer_dist(pos_a, pos_b)
        if min_dist is not None:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_from_ids(
    body_token_ids: array,
    query_term_ids: list[int],
) -> float:
    """针对紧凑整数词 ID 序列计算相邻查询词对最小距离加分。"""
    if len(query_term_ids) < 2 or not body_token_ids:
        return 0.0

    q_set = {tid for tid in query_term_ids if tid >= 0}
    if len(q_set) < 2:
        return 0.0

    pos_map: dict[int, list[int]] = {}
    for idx, tid in enumerate(body_token_ids):
        if tid in q_set:
            lst = pos_map.get(tid)
            if lst is None:
                pos_map[tid] = [idx]
            else:
                lst.append(idx)

    if len(pos_map) < 2:
        return 0.0

    bonus = 0.0
    for idx in range(len(query_term_ids) - 1):
        ta = query_term_ids[idx]
        tb = query_term_ids[idx + 1]
        if ta < 0 or tb < 0 or ta == tb:
            continue
        pos_a = pos_map.get(ta)
        pos_b = pos_map.get(tb)
        if not pos_a or not pos_b:
            continue
        min_dist = _min_two_pointer_dist(pos_a, pos_b)
        if min_dist is not None:
            bonus += 2.4 / float(min_dist)
    return bonus


def jaccard_from_sorted_ids(ids_a: array, ids_b: array, threshold: float = DEDUP_JACCARD_THRESHOLD) -> float:
    """带集合大小比值剪枝的有序整数数组双指针 Jaccard 相似度计算。"""
    la = len(ids_a)
    lb = len(ids_b)
    if la == 0 and lb == 0:
        return 1.0
    if la == 0 or lb == 0:
        return 0.0
    min_l = la if la < lb else lb
    max_l = lb if la < lb else la
    # 上界剪枝：min_l / max_l < threshold 时交并比必然低于阈值
    if (min_l / max_l) < threshold:
        return 0.0

    p = 0
    q = 0
    inter_cnt = 0
    while p < la and q < lb:
        va = ids_a[p]
        vb = ids_b[q]
        if va == vb:
            inter_cnt += 1
            p += 1
            q += 1
        elif va < vb:
            p += 1
        else:
            q += 1

    union_cnt = la + lb - inter_cnt
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    uniq_a = set(tokenize_text(title_a))
    uniq_a.update(tokenize_text(body_a))
    uniq_b = set(tokenize_text(title_b))
    uniq_b.update(tokenize_text(body_b))
    la = len(uniq_a)
    lb = len(uniq_b)
    if la == 0 and lb == 0:
        return 1.0
    if la == 0 or lb == 0:
        return 0.0
    min_l = la if la < lb else lb
    max_l = lb if la < lb else la
    if (min_l / max_l) < DEDUP_JACCARD_THRESHOLD:
        return 0.0
    inter_cnt = len(uniq_a & uniq_b)
    union_cnt = la + lb - inter_cnt
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt
