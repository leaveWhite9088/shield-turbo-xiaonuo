# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与动态金额中位数计算模块。"""
from __future__ import annotations


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。

    复杂度降维：以 Timsort O(N log N) 取代原版 O(N^2) 冒泡交换排序，
    输出与原版逐元素完全一致（奇数取正中元素，偶数取中间两数整数均值）。
    """
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)
