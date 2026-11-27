# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计：双堆惰性删除 O(log W) 动态中位数与乱序时间戳精确回退。"""
from __future__ import annotations

import bisect
import heapq

from .config import SLIDING_WINDOW_SECONDS


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
    n = len(amounts)
    if n == 0:
        return 0
    ordered = sorted(amounts)
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)


class SlidingMedianTracker:
    """双堆（大顶堆 low + 小顶堆 high）+ 惰性删除维护 O(log W) 滑动窗口精确中位数。"""

    __slots__ = ("low", "high", "delayed", "low_size", "high_size")

    def __init__(self) -> None:
        self.low: list[int] = []  # 存 -val，模拟大顶堆
        self.high: list[int] = []  # 存 val，小顶堆
        self.delayed: dict[int, int] = {}
        self.low_size: int = 0
        self.high_size: int = 0

    def _prune_low(self) -> None:
        low = self.low
        delayed = self.delayed
        while low:
            top = -low[0]
            cnt = delayed.get(top, 0)
            if cnt > 0:
                if cnt == 1:
                    del delayed[top]
                else:
                    delayed[top] = cnt - 1
                heapq.heappop(low)
            else:
                break

    def _prune_high(self) -> None:
        high = self.high
        delayed = self.delayed
        while high:
            top = high[0]
            cnt = delayed.get(top, 0)
            if cnt > 0:
                if cnt == 1:
                    del delayed[top]
                else:
                    delayed[top] = cnt - 1
                heapq.heappop(high)
            else:
                break

    def _rebalance(self) -> None:
        if self.low_size > self.high_size + 1:
            self._prune_low()
            val = -heapq.heappop(self.low)
            heapq.heappush(self.high, val)
            self.low_size -= 1
            self.high_size += 1
            self._prune_low()
        elif self.low_size < self.high_size:
            self._prune_high()
            val = heapq.heappop(self.high)
            heapq.heappush(self.low, -val)
            self.high_size -= 1
            self.low_size += 1
            self._prune_high()

    def add(self, val: int) -> None:
        self._prune_low()
        if not self.low or val <= -self.low[0]:
            heapq.heappush(self.low, -val)
            self.low_size += 1
        else:
            heapq.heappush(self.high, val)
            self.high_size += 1
        self._rebalance()

    def remove(self, val: int) -> None:
        self._prune_low()
        self._prune_high()
        self.delayed[val] = self.delayed.get(val, 0) + 1
        if self.low and val <= -self.low[0]:
            self.low_size -= 1
            if val == -self.low[0]:
                self._prune_low()
        else:
            self.high_size -= 1
            if self.high and val == self.high[0]:
                self._prune_high()
        self._rebalance()

    def median(self) -> int:
        total = self.low_size + self.high_size
        if total == 0:
            return 0
        self._prune_low()
        if total & 1:
            return -self.low[0]
        self._prune_high()
        return (-self.low[0] + self.high[0]) // 2

    def clear(self) -> None:
        self.low.clear()
        self.high.clear()
        self.delayed.clear()
        self.low_size = 0
        self.high_size = 0


class AccountSlidingWindow:
    """单账户 24 小时四维滑动窗口：单调时间戳 O(log W) 快路径 + 乱序时间戳精确回退。"""

    __slots__ = (
        "ts_list",
        "entries",
        "max_ts",
        "left_idx",
        "win_sum",
        "cp_counts",
        "median_tracker",
    )

    def __init__(self) -> None:
        self.ts_list: list[int] = []
        self.entries: list[tuple[int, int, str]] = []  # (ts, amount_cents, counterparty_id)
        self.max_ts: int = -1
        self.left_idx: int = 0
        self.win_sum: int = 0
        self.cp_counts: dict[str, int] = {}
        self.median_tracker = SlidingMedianTracker()

    def load_sorted_entries(self, sorted_entries: list[tuple[int, int, str]]) -> None:
        self.entries = list(sorted_entries)
        self.ts_list = [e[0] for e in self.entries]
        self.rebuild_fast_state()

    def rebuild_fast_state(self) -> None:
        self.median_tracker.clear()
        self.cp_counts.clear()
        self.win_sum = 0
        if not self.entries:
            self.max_ts = -1
            self.left_idx = 0
            return
        self.max_ts = self.ts_list[-1]
        win_start = self.max_ts - SLIDING_WINDOW_SECONDS
        self.left_idx = bisect.bisect_left(self.ts_list, win_start)
        for i in range(self.left_idx, len(self.entries)):
            _, amt, cp = self.entries[i]
            self.win_sum += amt
            self.cp_counts[cp] = self.cp_counts.get(cp, 0) + 1
            self.median_tracker.add(amt)

    def query_and_push(
        self,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
    ) -> tuple[int, int, int, int]:
        """计算当前交易纳入 [ts - 86400, ts] 后的四维窗口指标，并将其增量入窗。"""
        win_start = ts - SLIDING_WINDOW_SECONDS

        if ts >= self.max_ts:
            # 单调递增快路径：均摊 O(log W)
            self.max_ts = ts
            ts_list = self.ts_list
            entries = self.entries
            n_cur = len(entries)
            while self.left_idx < n_cur and ts_list[self.left_idx] < win_start:
                _, old_amt, old_cp = entries[self.left_idx]
                self.win_sum -= old_amt
                c_left = self.cp_counts.get(old_cp, 0) - 1
                if c_left <= 0:
                    self.cp_counts.pop(old_cp, None)
                else:
                    self.cp_counts[old_cp] = c_left
                self.median_tracker.remove(old_amt)
                self.left_idx += 1

            ts_list.append(ts)
            entries.append((ts, amount_cents, counterparty_id))
            self.win_sum += amount_cents
            self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
            self.median_tracker.add(amount_cents)

            win_cnt = len(entries) - self.left_idx
            return win_cnt, self.win_sum, len(self.cp_counts), self.median_tracker.median()

        # 乱序时间戳精确回退路径：二分定位历史切片 [ts - 86400, ts]，确保与全表扫描 100% 零失真
        lo = bisect.bisect_left(self.ts_list, win_start)
        hi = bisect.bisect_right(self.ts_list, ts)
        amounts: list[int] = [amount_cents]
        win_sum = amount_cents
        cps: set[str] = {counterparty_id}
        for i in range(lo, hi):
            _, h_amt, h_cp = self.entries[i]
            amounts.append(h_amt)
            win_sum += h_amt
            cps.add(h_cp)
        win_cnt = len(amounts)
        win_med = compute_exact_median_cents(amounts)

        # 按 ts 有序插入历史并同步维护单调快路径状态
        insert_pos = hi
        self.ts_list.insert(insert_pos, ts)
        self.entries.insert(insert_pos, (ts, amount_cents, counterparty_id))
        if insert_pos <= self.left_idx:
            if ts >= self.max_ts - SLIDING_WINDOW_SECONDS:
                self.win_sum += amount_cents
                self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
                self.median_tracker.add(amount_cents)
            else:
                self.left_idx += 1
        else:
            # 位于 [left_idx + 1 .. end]，必然在当前 [max_ts - 86400, max_ts] 内
            self.win_sum += amount_cents
            self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
            self.median_tracker.add(amount_cents)

        return win_cnt, win_sum, len(cps), win_med

    def rollback_entries(self, added_entries: list[tuple[int, int, str]]) -> None:
        """批次异常回滚时精确移除本批次加入的所有记录并重建快路径状态。"""
        for entry in reversed(added_entries):
            e_ts = entry[0]
            lo = bisect.bisect_left(self.ts_list, e_ts)
            hi = bisect.bisect_right(self.ts_list, e_ts)
            for idx in range(hi - 1, lo - 1, -1):
                if self.entries[idx] == entry:
                    del self.entries[idx]
                    del self.ts_list[idx]
                    break
        self.rebuild_fast_state()
