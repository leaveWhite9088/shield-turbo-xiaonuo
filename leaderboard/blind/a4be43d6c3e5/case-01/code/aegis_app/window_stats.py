# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与动态金额中位数计算模块（双堆 O(log W) + 乱序精确回退）。"""
from __future__ import annotations

import bisect
from collections import Counter, deque
import heapq

from .config import SLIDING_WINDOW_SECONDS


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)


class _TwoHeapMedian:
    """支持 O(log W) 插入、懒惰删除与 O(1) 精确中位数查询的双堆维护器。"""

    __slots__ = (
        "_low",
        "_high",
        "_low_active",
        "_high_active",
        "_delayed_low",
        "_delayed_high",
        "low_size",
        "high_size",
    )

    def __init__(self) -> None:
        self._low: list[int] = []
        self._high: list[int] = []
        self._low_active: Counter[int] = Counter()
        self._high_active: Counter[int] = Counter()
        self._delayed_low: Counter[int] = Counter()
        self._delayed_high: Counter[int] = Counter()
        self.low_size = 0
        self.high_size = 0

    def _prune_low(self) -> None:
        while self._low:
            top = -self._low[0]
            if self._delayed_low[top] > 0:
                self._delayed_low[top] -= 1
                heapq.heappop(self._low)
            else:
                break

    def _prune_high(self) -> None:
        while self._high:
            top = self._high[0]
            if self._delayed_high[top] > 0:
                self._delayed_high[top] -= 1
                heapq.heappop(self._high)
            else:
                break

    def _rebalance(self) -> None:
        self._prune_low()
        self._prune_high()
        if self.low_size > self.high_size + 1:
            val = -heapq.heappop(self._low)
            self._low_active[val] -= 1
            self.low_size -= 1
            heapq.heappush(self._high, val)
            self._high_active[val] += 1
            self.high_size += 1
            self._prune_low()
        elif self.high_size > self.low_size:
            val = heapq.heappop(self._high)
            self._high_active[val] -= 1
            self.high_size -= 1
            heapq.heappush(self._low, -val)
            self._low_active[val] += 1
            self.low_size += 1
            self._prune_high()

    def add(self, val: int) -> None:
        self._prune_low()
        if self.low_size == 0 or val <= -self._low[0]:
            heapq.heappush(self._low, -val)
            self._low_active[val] += 1
            self.low_size += 1
        else:
            heapq.heappush(self._high, val)
            self._high_active[val] += 1
            self.high_size += 1
        self._rebalance()

    def remove(self, val: int) -> None:
        if self._low_active[val] > 0:
            self._low_active[val] -= 1
            self.low_size -= 1
            self._delayed_low[val] += 1
        else:
            self._high_active[val] -= 1
            self.high_size -= 1
            self._delayed_high[val] += 1
        self._rebalance()

    def median(self) -> int:
        self._prune_low()
        self._prune_high()
        if self.low_size == 0:
            return 0
        if self.low_size > self.high_size:
            return int(-self._low[0])
        return int((-self._low[0] + self._high[0]) // 2)


class AccountWindowTracker:
    """单账户 24 小时滑动窗口状态，支持单调流 O(log W) 维护、乱序精确回退与事务撤销。"""

    __slots__ = (
        "records",
        "_seq",
        "_mono_valid",
        "_last_ts",
        "_active_q",
        "_win_amount",
        "_cp_counts",
        "_median",
    )

    def __init__(self, initial_records: list[tuple[int, int, str]] | None = None) -> None:
        self.records: list[tuple[int, int, int, str]] = []
        self._seq = 0
        self._mono_valid = False
        self._last_ts = 0
        self._active_q: deque[tuple[int, int, int, str]] = deque()
        self._win_amount = 0
        self._cp_counts: Counter[str] = Counter()
        self._median = _TwoHeapMedian()
        if initial_records:
            for ts, amt, cp in sorted(initial_records, key=lambda x: x[0]):
                self._seq += 1
                self.records.append((ts, self._seq, amt, cp))

    def _rebuild_mono(self, ts: int) -> None:
        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(self.records, (win_start, -1, 0, ""))
        hi = bisect.bisect_right(self.records, (ts, 1 << 62, 0, ""))
        self._active_q = deque()
        self._win_amount = 0
        self._cp_counts = Counter()
        self._median = _TwoHeapMedian()
        for rec in self.records[lo:hi]:
            self._active_q.append(rec)
            self._win_amount += rec[2]
            self._cp_counts[rec[3]] += 1
            self._median.add(rec[2])
        self._last_ts = ts
        self._mono_valid = True

    def push_and_query(self, ts: int, amount_cents: int, counterparty_id: str) -> tuple[int, int, int, int, tuple[int, int, int, str]]:
        """插入当前交易并返回 (win_tx_count, win_amount_cents, win_unique_cps, win_median_cents, undo_token)。"""
        self._seq += 1
        rec = (ts, self._seq, amount_cents, counterparty_id)

        if not self.records or ts >= self.records[-1][0]:
            self.records.append(rec)
            if not self._mono_valid:
                self._rebuild_mono(ts)
            else:
                win_start = ts - SLIDING_WINDOW_SECONDS
                while self._active_q and self._active_q[0][0] < win_start:
                    old = self._active_q.popleft()
                    self._win_amount -= old[2]
                    old_cp = old[3]
                    self._cp_counts[old_cp] -= 1
                    if self._cp_counts[old_cp] <= 0:
                        del self._cp_counts[old_cp]
                    self._median.remove(old[2])
                self._active_q.append(rec)
                self._win_amount += amount_cents
                self._cp_counts[counterparty_id] += 1
                self._median.add(amount_cents)
                self._last_ts = ts
            return (
                len(self._active_q),
                self._win_amount,
                len(self._cp_counts),
                self._median.median(),
                rec,
            )

        # 乱序时间戳精确回退：插入有序列表并对 [ts - 86400, ts] 切片精确计算
        bisect.insort(self.records, rec)
        self._mono_valid = False
        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(self.records, (win_start, -1, 0, ""))
        hi = bisect.bisect_right(self.records, (ts, 1 << 62, 0, ""))
        window_slice = self.records[lo:hi]
        amounts = [r[2] for r in window_slice]
        cps = {r[3] for r in window_slice}
        return (
            len(window_slice),
            sum(amounts),
            len(cps),
            compute_exact_median_cents(amounts),
            rec,
        )

    def rollback_records(self, undo_recs: list[tuple[int, int, int, str]]) -> None:
        if not undo_recs:
            return
        undo_set = set(undo_recs)
        self.records = [r for r in self.records if r not in undo_set]
        self._mono_valid = False
