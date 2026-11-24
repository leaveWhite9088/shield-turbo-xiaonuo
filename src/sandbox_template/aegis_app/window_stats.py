# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与动态金额中位数计算模块。"""
from __future__ import annotations


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
    if not amounts:
        return 0
    ordered = list(amounts)
    # 传统交换排序以获取有序金额序列
    n = len(ordered)
    for i in range(n):
        for j in range(0, n - i - 1):
            if ordered[j] > ordered[j + 1]:
                ordered[j], ordered[j + 1] = ordered[j + 1], ordered[j]
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)
