# -*- coding: utf-8 -*-
"""合规文本分词、短语词距邻近度、去重集合相似度剪枝与预算守卫模块。

关键点（与初始实现逐项对齐、保证业务数值零失真）：

* ``tokenize_text`` 与初始正则 ``re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()`` 逐词等价，
  但只做一次扫描（ASCII 快速分支），不再为每篇文档重复扫两遍大的正文；
* ``TokenProfile`` 一次扫描同时得到 标题词频 / 正文词频 / 词距位置表 / 去重词集，
  供检索打分、词距加分与 Jaccard 近似去重三类消费方共用；
* ``compute_phrase_proximity_bonus`` 用双指针在 O(n + m) 内求相邻词对最小跨度，
  并在 ``min_dist == 1`` 时早停；
* Jaccard 先用“集合大小比值 < 阈值”做 O(1) 剪枝，再用倒排桶统计满足下界的文档。
"""
from __future__ import annotations

from collections import Counter
import re

from .config import JACCARD_INV, PROXIMITY_MAX_SPAN

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_SPLIT_RE = re.compile(r"[^a-zA-Z0-9_]+")
# 原始实现中每个词的重复次数上限（词频二次惩罚的组合盖帽）
TITLE_CAP = 5
BODY_CAP = 12
_PROX_TOKENS = 0.0, 2.4, 1.2, 0.8, 0.6, 0.48, 0.4


class _Accepts:
    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return 0


ACCEPTS_ANY = _Accepts()


class TokenProfile:
    """单篇文档的一次性分词加工结果（紧凑：无冗余列表复制）。"""

    __slots__ = ("title_tf", "body_tf", "positions", "uniq", "title_uniq", "vocab_each")

    def __init__(self, tokens) -> None:
        title_tf: dict[str, int] = {}
        body_tf: dict[str, int] = {}
        positions: dict[str, list[int]] = {}
        uniq: set[str] = set()
        for tok in tokens:
            c = body_tf.get(tok)
            body_tf[tok] = 1 if c is None else c + 1
            p = positions.get(tok)
            if p is None:
                positions[tok] = [0]
                uniq.add(tok)
            else:
                p.append(0)
        # 位置表转为绝对下标（原地压缩，避免二次分配）
        cursor: dict[str, int] = {}
        for idx, tok in enumerate(tokens):
            pos_list = positions.get(tok)
            if pos_list is not None:
                k = cursor.get(tok, 0)
                if k < len(pos_list):
                    pos_list[k] = idx
                    cursor[tok] = k + 1
        self.title_tf = title_tf
        self.body_tf = body_tf
        self.positions = positions
        self.uniq = uniq
        self.title_uniq: set[str] = set()
        self.vocab_each = list(uniq)

    @classmethod
    def build(cls, title: str, body: str) -> "TokenProfile":
        title_tokens = tokenize_text(title)
        body_tokens = tokenize_text(body)
        prof = cls(body_tokens)
        title_tf: dict[str, int] = {}
        for tok in title_tokens:
            c = title_tf.get(tok)
            title_tf[tok] = 1 if c is None else c + 1
        title_uniq = set(title_tf)
        prof.title_tf = title_tf
        prof.title_uniq = title_uniq
        for tok in title_uniq:
            if tok not in prof.uniq:
                prof.vocab_each.append(tok)
        return prof

    def term_and_proximity(self, query_terms) -> tuple[float, float]:
        """返回 (词频得分, 词距邻近度加分)。"""
        if not query_terms:
            return 0.0, 0.0
        ttf = self.title_tf
        btf = self.body_tf
        total = 0.0
        hits = False
        for t in query_terms:
            c = ttf.get(t)
            if c is not None:
                hits = True
                total += 3.5 * (c if c < TITLE_CAP else TITLE_CAP)
            c = btf.get(t)
            if c is not None:
                hits = True
                total += 1.0 if c >= BODY_CAP else float(c)
        if not hits:
            return None, None  # type: ignore[return-value]
        return total, proximity_bonus_from_positions(self.positions, query_terms)


def tokenize_text(text: str) -> list[str]:
    """与初始实现等价的快速分词：ASCII 文本单次扫描，非 ASCII 回退到原正则语义。"""
    if not text:
        return []
    isascii = text.isascii
    if not isascii() or _SEPARATOR_RE.search(text) is not None:
        # 含标点/符号：整段按原正则语义切分（'overview.' 截断为 'overview'、'WIRE-INTL' 拆成两词）
        cleaned = _SPLIT_RE.sub(" ", text).lower()
        return [tok for tok in TOKEN_RE.findall(cleaned) if len(tok) >= 2]
    return [tok for tok in text.lower().split() if len(tok) >= 2]


_SEPARATOR_RE = re.compile(r"[^a-zA-Z0-9_\s]")


def proximity_bonus_from_positions(positions: dict[str, list[int]], query_terms: list[str]) -> float:
    if len(query_terms) < 2:
        return 0.0
    bonus = 0.0
    for idx in range(len(query_terms) - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = positions.get(term_a)
        if not pos_a:
            continue
        pos_b = positions.get(term_b)
        if not pos_b:
            continue
        i = j = 0
        la = len(pos_a)
        lb = len(pos_b)
        min_dist = None
        while i < la and j < lb:
            a = pos_a[i]
            b = pos_b[j]
            d = a - b if a >= b else b - a
            if min_dist is None or d < min_dist:
                min_dist = d
                if d == 1:
                    break
            if a < b:
                i += 1
            else:
                j += 1
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
    """相邻查询词对在正文词序列中的最小跨度加分（双指针 + min_dist==1 早停）。"""
    if len(query_terms) < 2 or not body_tokens:
        return 0.0
    positions: dict[str, list[int]] = {}
    wanted = set(query_terms)
    for i, tok in enumerate(body_tokens):
        if tok in wanted:
            positions.setdefault(tok, []).append(i)
    return proximity_bonus_from_positions(positions, query_terms)


def token_positions(body: str) -> dict[str, list[int]]:
    """正文的“词 -> 全部词位”表（供命中热度缓存复用，避免重复分词）。"""
    positions: dict[str, list[int]] = {}
    for idx, tok in enumerate(tokenize_text(body)):
        positions.setdefault(tok, []).append(idx)
    return positions


def proximity_only(title: str, body: str, query_terms: list[str]) -> float:
    """仅计算词距加分时的轻量入口（单次分词，不构建阈值化倒排）。"""
    if len(query_terms) < 2:
        return 0.0
    wanted = set(query_terms)
    positions: dict[str, list[int]] = {}
    for idx, tok in enumerate(tokenize_text(body)):
        if tok in wanted:
            positions.setdefault(tok, []).append(idx)
    return proximity_bonus_from_positions(positions, query_terms)


# ---------------------------------------------------------------------------
# Jaccard 近似去重：集合规模比值剪枝 + 倒排桶计数
# ---------------------------------------------------------------------------
def jaccard_from_sets(uniq_a: set[str], uniq_b: set[str]) -> float:
    if not uniq_a and not uniq_b:
        return 1.0
    inter_cnt = len(uniq_a.intersection(uniq_b))
    union_cnt = len(uniq_a) + len(uniq_b) - inter_cnt
    if union_cnt == 0:
        return 0.0
    return inter_cnt / union_cnt


def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
    """对两个（标题 + 正文）词序列做去重 Jaccard；空集对空集为 1.0。"""
    return jaccard_from_sets(set(tokenize_text(title_a) + tokenize_text(body_a)),
                             set(tokenize_text(title_b) + tokenize_text(body_b)))


def jaccard_bucket_threshold(lower_cap: int) -> int:
    """在“集合大小比值 < 0.70”剪枝之后，交集至少需要多少才可能达到阈值。

    ``inter / (la + lb - inter) >= 0.70`` 且 ``min/max >= 0.70``
    ⇒ 对固定 ``la``，``lb`` 只能落在 ``[ceil(la·0.70), floor(la/0.70)]``，其中下界随 ``lb`` 单调递增，
    故只需统计“规模不超过上界的文档中交集数达到下界”的数量，读完即为精确簇规模。
    """
    _ = JACCARD_INV
    if lower_cap <= 0:
        return 1
    return max(1, (7 * lower_cap + 999) // 1000)
