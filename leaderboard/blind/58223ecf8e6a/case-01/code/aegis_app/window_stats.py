# -*- coding: utf-8 -*-
"""24 小时账户滑窗与双堆懒删除精确中位数（O(log W) 增删）。"""
from __future__ import annotations

from collections import Counter, deque
import heapq
from typing import Any


def compute_exact_median_cents(amounts: list[int]) -> int:
    if not amounts:
        return 0
    ordered = sorted(amounts)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return int(ordered[middle])
    return int((ordered[middle - 1] + ordered[middle]) // 2)


class LazyMedian:
    """small 为最大堆（负值），large 为最小堆；尺寸只统计未删除元素。"""

    __slots__ = ("small", "large", "delayed", "small_size", "large_size")

    def __init__(self) -> None:
        self.small: list[int] = []
        self.large: list[int] = []
        self.delayed: Counter[int] = Counter()
        self.small_size = 0
        self.large_size = 0

    def _prune(self) -> None:
        while self.small and self.delayed.get(-self.small[0], 0):
            value = -heapq.heappop(self.small)
            self.delayed[value] -= 1
            if not self.delayed[value]:
                del self.delayed[value]
        while self.large and self.delayed.get(self.large[0], 0):
            value = heapq.heappop(self.large)
            self.delayed[value] -= 1
            if not self.delayed[value]:
                del self.delayed[value]

    def _balance(self) -> None:
        self._prune()
        if self.small_size > self.large_size + 1:
            value = -heapq.heappop(self.small)
            self.small_size -= 1
            heapq.heappush(self.large, value)
            self.large_size += 1
        elif self.small_size < self.large_size:
            value = heapq.heappop(self.large)
            self.large_size -= 1
            heapq.heappush(self.small, -value)
            self.small_size += 1
        self._prune()

    def add(self, value: int) -> None:
        self._prune()
        if self.small and value <= -self.small[0]:
            heapq.heappush(self.small, -value)
            self.small_size += 1
        else:
            heapq.heappush(self.large, value)
            self.large_size += 1
        self._balance()

    def discard(self, value: int) -> None:
        self._prune()
        if self.small and value <= -self.small[0]:
            self.small_size -= 1
        else:
            self.large_size -= 1
        if self.small_size < 0 or self.large_size < 0:
            raise RuntimeError("median multiset underflow")
        self.delayed[value] += 1
        self._balance()

    def median(self) -> int:
        self._prune()
        total = self.small_size + self.large_size
        if total <= 0:
            return 0
        if total % 2:
            return int(-self.small[0])
        return int((-self.small[0] + self.large[0]) // 2)


class AccountWindow:
    """单账户双端队列 + Counter 扇出 + LazyMedian，支持精确过期。"""

    __slots__ = ("records", "median", "counterparties", "amount_cents")

    def __init__(self) -> None:
        self.records: deque[tuple[int, int, str]] = deque()
        self.median = LazyMedian()
        self.counterparties: Counter[str] = Counter()
        self.amount_cents = 0

    def add(self, record: Any) -> None:
        ts = int(record["ts"])
        amount = int(record["amount_cents"])
        counterparty = str(record["counterparty_id"])
        self.records.append((ts, amount, counterparty))
        self.median.add(amount)
        self.counterparties[counterparty] += 1
        self.amount_cents += amount

    def expire(self, start_ts: int) -> None:
        while self.records and self.records[0][0] < start_ts:
            _, amount, counterparty = self.records.popleft()
            self.median.discard(amount)
            self.amount_cents -= amount
            self.counterparties[counterparty] -= 1
            if not self.counterparties[counterparty]:
                del self.counterparties[counterparty]

    def stats_with(self, amount: int, counterparty: str) -> tuple[int, int, int, int]:
        count = len(self.records) + 1
        total = self.amount_cents + amount
        unique = len(self.counterparties) + (1 if self.counterparties.get(counterparty, 0) == 0 else 0)
        self.median.add(amount)
        median = self.median.median()
        self.median.discard(amount)
        return count, total, unique, median
