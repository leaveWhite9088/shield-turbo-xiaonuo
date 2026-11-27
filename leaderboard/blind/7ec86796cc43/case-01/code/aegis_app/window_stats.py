# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与动态金额中位数计算模块。"""
from __future__ import annotations


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。

    原实现使用交换排序，复杂度 O(n²)；现改为一次排序后取中位，
    复杂度 O(n log n)，且输出与原版 **逐位一致**（含偶数长度时的整数除法语义）。
    """
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)
