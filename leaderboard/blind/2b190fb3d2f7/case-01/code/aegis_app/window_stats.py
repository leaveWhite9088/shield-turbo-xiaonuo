# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与 O(log W) 双堆动态中位数计算模块。"""
from __future__ import annotations

from collections import deque
import heapq

from .config import SLIDING_WINDOW_SECONDS


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
    n = len(amounts)
    if n == 0:
        return 0
    ordered = sorted(amounts)
    mid = n // 2
    if n & 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)


class DualHeapMedian:
    """基于大顶堆 + 小顶堆 + 惰性删除的 O(log W) 精确动态中位数结构。

    不变式：
    - low（大顶堆，存负值）与 high（小顶堆，存正值）满足：
      low_size == high_size 或 low_size == high_size + 1；
    - 经 prune 后，-low[0] <= high[0]。
    """

    __slots__ = ("_low", "_high", "_delayed", "_low_size", "_high_size")

    def __init__(self) -> None:
        self._low: list[int] = []
        self._high: list[int] = []
        self._delayed: dict[int, int] = {}
        self._low_size: int = 0
        self._high_size: int = 0

    def _prune_low(self) -> None:
        low = self._low
        delayed = self._delayed
        while low:
            val = -low[0]
            cnt = delayed.get(val, 0)
            if cnt > 0:
                heapq.heappop(low)
                if cnt == 1:
                    del delayed[val]
                else:
                    delayed[val] = cnt - 1
            else:
                break

    def _prune_high(self) -> None:
        high = self._high
        delayed = self._delayed
        while high:
            val = high[0]
            cnt = delayed.get(val, 0)
            if cnt > 0:
                heapq.heappop(high)
                if cnt == 1:
                    del delayed[val]
                else:
                    delayed[val] = cnt - 1
            else:
                break

    def _rebalance(self) -> None:
        if self._low_size > self._high_size + 1:
            self._prune_low()
            val = -heapq.heappop(self._low)
            self._low_size -= 1
            heapq.heappush(self._high, val)
            self._high_size += 1
            self._prune_low()
        elif self._low_size < self._high_size:
            self._prune_high()
            val = heapq.heappop(self._high)
            self._high_size -= 1
            heapq.heappush(self._low, -val)
            self._low_size += 1
            self._prune_high()

    def add(self, val: int) -> None:
        if self._low_size == 0:
            heapq.heappush(self._low, -val)
            self._low_size += 1
            return
        self._prune_low()
        if val <= -self._low[0]:
            heapq.heappush(self._low, -val)
            self._low_size += 1
        else:
            heapq.heappush(self._high, val)
            self._high_size += 1
        self._rebalance()

    def remove(self, val: int) -> None:
        self._prune_low()
        in_low = bool(self._low) and val <= -self._low[0]
        self._delayed[val] = self._delayed.get(val, 0) + 1
        if in_low:
            self._low_size -= 1
            if self._low and val == -self._low[0]:
                self._prune_low()
        else:
            self._high_size -= 1
            if self._high and val == self._high[0]:
                self._prune_high()
        self._rebalance()

    def median(self) -> int:
        total = self._low_size + self._high_size
        if total == 0:
            return 0
        self._prune_low()
        if total & 1:
            return int(-self._low[0])
        self._prune_high()
        return int((-self._low[0] + self._high[0]) // 2)


class AccountSlidingWindow:
    """单账户 24 小时单调滑动窗口（支持乱序时间戳检测与回退）。"""

    __slots__ = ("entries", "max_ts", "total_amount", "cp_counts", "median_tracker")

    def __init__(self) -> None:
        self.entries: deque[tuple[int, int, str]] = deque()
        self.max_ts: int = -1
        self.total_amount: int = 0
        self.cp_counts: dict[str, int] = {}
        self.median_tracker = DualHeapMedian()

    def add_monotonic(self, ts: int, amount_cents: int, counterparty_id: str) -> tuple[int, int, int, int]:
        """在 ts >= max_ts 的单调路径上增量淘汰过期条目并插入当前交易，返回四维统计。"""
        win_start = ts - SLIDING_WINDOW_SECONDS
        entries = self.entries
        cp_counts = self.cp_counts
        tracker = self.median_tracker

        while entries and entries[0][0] < win_start:
            _, old_amt, old_cp = entries.popleft()
            self.total_amount -= old_amt
            tracker.remove(old_amt)
            c = cp_counts[old_cp]
            if c <= 1:
                del cp_counts[old_cp]
            else:
                cp_counts[old_cp] = c - 1

        entries.append((ts, amount_cents, counterparty_id))
        if ts > self.max_ts:
            self.max_ts = ts
        self.total_amount += amount_cents
        cp_counts[counterparty_id] = cp_counts.get(counterparty_id, 0) + 1
        tracker.add(amount_cents)

        return len(entries), self.total_amount, len(cp_counts), tracker.median()

    def insert_out_of_order(self, ts: int, amount_cents: int, counterparty_id: str) -> None:
        """若乱序交易仍落在 [max_ts - 86400, max_ts] 活跃窗口内，同步补入当前单调窗口保持一致。"""
        if self.max_ts < 0:
            self.add_monotonic(ts, amount_cents, counterparty_id)
            return
        if ts < self.max_ts - SLIDING_WINDOW_SECONDS:
            return
        # 保持 entries 按 ts 有序以便后续单调淘汰准确
        lst = list(self.entries)
        lst.append((ts, amount_cents, counterparty_id))
        lst.sort(key=lambda x: x[0])
        self.entries = deque(lst)
        self.total_amount += amount_cents
        self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
        self.median_tracker.add(amount_cents)
