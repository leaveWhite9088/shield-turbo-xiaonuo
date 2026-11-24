# -*- coding: utf-8 -*-
"""高性能滑动窗口四维统计器：基于单调双端队列与二分有序表的 O(log W) 精确动态中位数维护。"""
from __future__ import annotations

import bisect
from collections import deque


def compute_exact_median_cents(amounts: list[int]) -> int:
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)


class SlidingAccountWindow:
    """维护单账户在批次推进过程中的滑动窗口，支持单调时间戳 O(log W) 更新与乱序回退精确求值。"""

    __slots__ = ("raw_records", "events", "sorted_amts", "sum_amts", "cp_counts", "last_ts", "monotonic")

    def __init__(self, initial_records: list[tuple[int, int, str]]) -> None:
        initial_records.sort(key=lambda x: x[0])
        self.raw_records: list[tuple[int, int, str]] = list(initial_records)
        self.events: deque[tuple[int, int, str]] = deque(initial_records)
        self.sorted_amts: list[int] = sorted(r[1] for r in initial_records)
        self.sum_amts: int = sum(r[1] for r in initial_records)
        self.cp_counts: dict[str, int] = {}
        for _, _, cp in initial_records:
            self.cp_counts[cp] = self.cp_counts.get(cp, 0) + 1
        self.last_ts: int = initial_records[-1][0] if initial_records else -1
        self.monotonic: bool = True

    def eval_and_record(
        self,
        *,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
        window_seconds: int,
    ) -> tuple[int, int, int, int]:
        """计算包含当前交易在内的四项窗口统计量，并将当前交易追加进状态窗口。"""
        win_start = ts - window_seconds
        if self.monotonic and ts >= self.last_ts:
            while self.events and self.events[0][0] < win_start:
                _, old_amt, old_cp = self.events.popleft()
                self.sum_amts -= old_amt
                pos = bisect.bisect_left(self.sorted_amts, old_amt)
                self.sorted_amts.pop(pos)
                rem_c = self.cp_counts[old_cp] - 1
                if rem_c <= 0:
                    del self.cp_counts[old_cp]
                else:
                    self.cp_counts[old_cp] = rem_c

            self.events.append((ts, amount_cents, counterparty_id))
            self.raw_records.append((ts, amount_cents, counterparty_id))
            self.sum_amts += amount_cents
            bisect.insort(self.sorted_amts, amount_cents)
            self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
            self.last_ts = ts

            n = len(self.sorted_amts)
            mid = n // 2
            if n % 2 == 1:
                median_val = self.sorted_amts[mid]
            else:
                median_val = (self.sorted_amts[mid - 1] + self.sorted_amts[mid]) // 2
            return n, self.sum_amts, len(self.cp_counts), median_val

        # 若批次内出现乱序倒退时间戳，自动切换精确区间切片以保证 100% 语义守恒
        self.monotonic = False
        self.raw_records.append((ts, amount_cents, counterparty_id))
        win_amts: list[int] = []
        cp_set: set[str] = set()
        total_amt = 0
        for r_ts, r_amt, r_cp in self.raw_records:
            if win_start <= r_ts <= ts:
                win_amts.append(r_amt)
                total_amt += r_amt
                cp_set.add(r_cp)
        return len(win_amts), total_amt, len(cp_set), compute_exact_median_cents(win_amts)
