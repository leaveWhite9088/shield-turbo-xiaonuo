# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与动态金额中位数（O(log W) 有序表 + 双端单调队列 + 乱序回退）计算模块。"""
from __future__ import annotations

import bisect
from collections import deque

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


class AccountWindowTracker:
    """单账户滑动时间窗状态器：支持单调时间下 O(log W) 增量维护与乱序时间戳下的精确二分回退。"""

    __slots__ = (
        "records",
        "max_ts",
        "win_queue",
        "win_sorted_amounts",
        "win_sum",
        "win_cp_counts",
    )

    def __init__(self) -> None:
        self.records: list[tuple[int, int, str]] = []
        self.max_ts: int = -1
        self.win_queue: deque[tuple[int, int, str]] = deque()
        self.win_sorted_amounts: list[int] = []
        self.win_sum: int = 0
        self.win_cp_counts: dict[str, int] = {}

    def load_sorted_records(self, sorted_recs: list[tuple[int, int, str]]) -> None:
        self.records = list(sorted_recs)
        self.max_ts = self.records[-1][0] if self.records else -1
        self.win_queue.clear()
        self.win_sorted_amounts.clear()
        self.win_sum = 0
        self.win_cp_counts.clear()
        if self.records:
            cutoff = self.max_ts - SLIDING_WINDOW_SECONDS
            start_idx = bisect.bisect_left(self.records, (cutoff, -1, ""))
            for rec in self.records[start_idx:]:
                r_ts, r_amt, r_cp = rec
                self.win_queue.append(rec)
                bisect.insort(self.win_sorted_amounts, r_amt)
                self.win_sum += r_amt
                self.win_cp_counts[r_cp] = self.win_cp_counts.get(r_cp, 0) + 1

    def _evict_before(self, win_start: int) -> None:
        while self.win_queue and self.win_queue[0][0] < win_start:
            _, old_amt, old_cp = self.win_queue.popleft()
            self.win_sum -= old_amt
            idx = bisect.bisect_left(self.win_sorted_amounts, old_amt)
            if idx < len(self.win_sorted_amounts) and self.win_sorted_amounts[idx] == old_amt:
                self.win_sorted_amounts.pop(idx)
            cnt = self.win_cp_counts.get(old_cp, 0)
            if cnt <= 1:
                self.win_cp_counts.pop(old_cp, None)
            else:
                self.win_cp_counts[old_cp] = cnt - 1

    def evaluate_and_record(
        self,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
    ) -> tuple[int, int, int, int]:
        """评估含当前交易在内的 [ts - 86400, ts] 四维窗口指标，并将当前交易记入账户历史。"""
        win_start = ts - SLIDING_WINDOW_SECONDS

        if ts >= self.max_ts:
            self._evict_before(win_start)
            rec = (ts, amount_cents, counterparty_id)
            self.records.append(rec)
            self.max_ts = ts
            self.win_queue.append(rec)
            bisect.insort(self.win_sorted_amounts, amount_cents)
            self.win_sum += amount_cents
            self.win_cp_counts[counterparty_id] = self.win_cp_counts.get(counterparty_id, 0) + 1

            n = len(self.win_sorted_amounts)
            mid = n // 2
            if n % 2 == 1:
                med = self.win_sorted_amounts[mid]
            else:
                med = (self.win_sorted_amounts[mid - 1] + self.win_sorted_amounts[mid]) // 2
            return n, self.win_sum, len(self.win_cp_counts), int(med)

        # 乱序时间戳精确回退路径：利用有序 records 二分切片计算 [win_start, ts]
        lo = bisect.bisect_left(self.records, (win_start, -1, ""))
        hi = bisect.bisect_right(self.records, (ts, 1 << 63, "\uffff"))
        amt_list = [amount_cents]
        total_amt = amount_cents
        cps = {counterparty_id}
        for i in range(lo, hi):
            r_ts, r_amt, r_cp = self.records[i]
            if win_start <= r_ts <= ts:
                amt_list.append(r_amt)
                total_amt += r_amt
                cps.add(r_cp)

        rec = (ts, amount_cents, counterparty_id)
        bisect.insort(self.records, rec)
        if ts >= self.max_ts - SLIDING_WINDOW_SECONDS:
            self.win_queue.append(rec)
            bisect.insort(self.win_sorted_amounts, amount_cents)
            self.win_sum += amount_cents
            self.win_cp_counts[counterparty_id] = self.win_cp_counts.get(counterparty_id, 0) + 1

        med = compute_exact_median_cents(amt_list)
        return len(amt_list), total_amt, len(cps), int(med)
