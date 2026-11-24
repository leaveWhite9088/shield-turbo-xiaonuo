# -*- coding: utf-8 -*-
"""24 小时滑动窗口中位数计算（5级平庸样本：改用内置排序但未做流式增量维护）。"""
from __future__ import annotations


def compute_exact_median_cents(amounts: list[int]) -> int:
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)
