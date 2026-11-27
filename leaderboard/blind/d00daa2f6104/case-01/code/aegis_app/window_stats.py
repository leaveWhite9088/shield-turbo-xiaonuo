# -*- coding: utf-8 -*-
"""24 小时滑窗：双堆 O(log W) 中位数、单调增量与乱序精确回退。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right, insort
from collections import Counter
import heapq
from typing import Iterable

from .config import SLIDING_WINDOW_SECONDS


def compute_exact_median_cents(amounts: list[int]) -> int:
    if not amounts:
        return 0
    ordered = sorted(amounts)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return int(ordered[middle])
    return int((ordered[middle - 1] + ordered[middle]) // 2)


class WindowEntry:
    __slots__ = ("ts", "seq", "amount", "counterparty")

    def __init__(self, ts: int, seq: int, amount: int, counterparty: str) -> None:
        self.ts = ts
        self.seq = seq
        self.amount = amount
        self.counterparty = counterparty

    def sort_key(self) -> tuple[int, int]:
        return self.ts, self.seq


class SlidingAccountWindow:
    """单账户历史 + 当前窗口；所有结构均只属于一个批次，可整体丢弃回滚。"""

    def __init__(self, history: Iterable[tuple[int, int, str]]) -> None:
        self.entries: list[WindowEntry] = []
        self._next_seq = 0
        for ts, amount, counterparty in history:
            self._next_seq += 1
            self.entries.append(WindowEntry(int(ts), self._next_seq, int(amount), str(counterparty)))
        self.entries.sort(key=lambda entry: entry.sort_key())
        self._keys = [entry.sort_key() for entry in self.entries]
        self._valid = False
        self._last_ts = 0
        self._processed: set[int] = set()
        self._active: dict[int, WindowEntry] = {}
        self._expiry: list[tuple[int, int]] = []
        self._low: list[int] = []
        self._high: list[int] = []
        self._low_size = 0
        self._high_size = 0
        self._delayed: Counter[int] = Counter()
        self._cp_counts: Counter[str] = Counter()
        self._total = 0

    def _reset(self) -> None:
        self._processed.clear()
        self._active.clear()
        self._expiry.clear()
        self._low.clear()
        self._high.clear()
        self._low_size = self._high_size = 0
        self._delayed.clear()
        self._cp_counts.clear()
        self._total = 0

    def _prune(self) -> None:
        while self._low:
            amount = -self._low[0]
            if not self._delayed[amount]:
                break
            heapq.heappop(self._low)
            self._delayed[amount] -= 1
            if not self._delayed[amount]:
                del self._delayed[amount]
        while self._high:
            amount = self._high[0]
            if not self._delayed[amount]:
                break
            heapq.heappop(self._high)
            self._delayed[amount] -= 1
            if not self._delayed[amount]:
                del self._delayed[amount]

    def _rebalance(self) -> None:
        self._prune()
        if self._low_size > self._high_size + 1:
            amount = -heapq.heappop(self._low)
            self._low_size -= 1
            heapq.heappush(self._high, amount)
            self._high_size += 1
        elif self._low_size < self._high_size:
            amount = heapq.heappop(self._high)
            self._high_size -= 1
            heapq.heappush(self._low, -amount)
            self._low_size += 1
        self._prune()

    def _add_amount(self, amount: int) -> None:
        self._prune()
        if self._low and amount <= -self._low[0]:
            heapq.heappush(self._low, -amount)
            self._low_size += 1
        else:
            heapq.heappush(self._high, amount)
            self._high_size += 1
        self._rebalance()

    def _remove_amount(self, amount: int) -> None:
        self._prune()
        self._delayed[amount] += 1
        if self._low and amount <= -self._low[0]:
            self._low_size -= 1
        else:
            self._high_size -= 1
        self._rebalance()

    def _activate(self, entry: WindowEntry) -> None:
        self._processed.add(entry.seq)
        self._active[entry.seq] = entry
        heapq.heappush(self._expiry, entry.sort_key())
        self._add_amount(entry.amount)
        self._cp_counts[entry.counterparty] += 1
        self._total += entry.amount

    def _expire(self, window_start: int) -> None:
        while self._expiry and self._expiry[0][0] < window_start:
            _, seq = heapq.heappop(self._expiry)
            entry = self._active.pop(seq, None)
            if entry is None:
                continue
            self._remove_amount(entry.amount)
            self._total -= entry.amount
            self._cp_counts[entry.counterparty] -= 1
            if not self._cp_counts[entry.counterparty]:
                del self._cp_counts[entry.counterparty]

    def _rebuild(self, ts: int) -> None:
        self._reset()
        start = ts - SLIDING_WINDOW_SECONDS
        left = bisect_left(self._keys, (start, -1))
        right = bisect_right(self._keys, (ts, self._next_seq + 1))
        for entry in self.entries[:left]:
            if entry.ts <= ts:
                self._processed.add(entry.seq)
        for entry in self.entries[left:right]:
            self._activate(entry)
        self._last_ts = ts
        self._valid = True

    def _advance(self, ts: int) -> None:
        # 将上次时间之后持久化或本批新插入的所有边纳入，而非只加当前一笔。
        index = bisect_left(self._keys, (self._last_ts, -1))
        while index < len(self.entries) and self.entries[index].ts <= ts:
            entry = self.entries[index]
            if entry.seq not in self._processed:
                self._activate(entry)
            index += 1
        self._expire(ts - SLIDING_WINDOW_SECONDS)
        self._last_ts = ts

    def evaluate(self, ts: int, amount: int, counterparty: str) -> tuple[int, int, int, int]:
        self._next_seq += 1
        current = WindowEntry(ts, self._next_seq, amount, counterparty)
        insertion = bisect_right(self._keys, current.sort_key())
        self.entries.insert(insertion, current)
        self._keys.insert(insertion, current.sort_key())
        out_of_order = self._valid and ts < self._last_ts
        if not self._valid or out_of_order:
            self._rebuild(ts)
        else:
            self._advance(ts)
        self._prune()
        if self._low and self._high:
            if len(self._active) % 2:
                median = -self._low[0]
            else:
                median = (-self._low[0] + self._high[0]) // 2
        elif self._low:
            median = -self._low[0]
        elif self._high:
            median = self._high[0]
        else:
            median = 0
        result = (len(self._active), self._total, len(self._cp_counts), int(median))
        if out_of_order:
            # 防止后续时间前进时漏掉此次乱序插入对主窗口的影响。
            self._valid = False
        return result
