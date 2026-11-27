# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与基于双堆惰性删除的 O(log W) 动态中位数引擎。"""
from __future__ import annotations

from bisect import bisect_right
from collections import deque
import heapq
from typing import Any

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


class DualHeapMedian:
    """支持 O(log W) 插入/惰性删除与 O(1) 精确中位数查询的对顶堆结构。"""

    __slots__ = ("low", "high", "delayed", "low_size", "high_size")

    def __init__(self) -> None:
        self.low: list[int] = []   # max-heap (store -val)
        self.high: list[int] = []  # min-heap (store val)
        self.delayed: dict[int, int] = {}
        self.low_size: int = 0
        self.high_size: int = 0

    def _prune_low(self) -> None:
        while self.low:
            val = -self.low[0]
            cnt = self.delayed.get(val, 0)
            if cnt <= 0:
                break
            if cnt == 1:
                del self.delayed[val]
            else:
                self.delayed[val] = cnt - 1
            heapq.heappop(self.low)

    def _prune_high(self) -> None:
        while self.high:
            val = self.high[0]
            cnt = self.delayed.get(val, 0)
            if cnt <= 0:
                break
            if cnt == 1:
                del self.delayed[val]
            else:
                self.delayed[val] = cnt - 1
            heapq.heappop(self.high)

    def _rebalance(self) -> None:
        if self.low_size > self.high_size + 1:
            self._prune_low()
            val = -heapq.heappop(self.low)
            self.low_size -= 1
            heapq.heappush(self.high, val)
            self.high_size += 1
            self._prune_low()
        elif self.low_size < self.high_size:
            self._prune_high()
            val = heapq.heappop(self.high)
            self.high_size -= 1
            heapq.heappush(self.low, -val)
            self.low_size += 1
            self._prune_high()

    def add(self, val: int) -> None:
        self._prune_low()
        if self.low_size == 0 or val <= -self.low[0]:
            heapq.heappush(self.low, -val)
            self.low_size += 1
        else:
            heapq.heappush(self.high, val)
            self.high_size += 1
        self._rebalance()

    def remove(self, val: int) -> None:
        self._prune_low()
        if self.low_size > 0 and val <= -self.low[0]:
            self.low_size -= 1
            self.delayed[val] = self.delayed.get(val, 0) + 1
            self._prune_low()
        else:
            self.high_size -= 1
            self.delayed[val] = self.delayed.get(val, 0) + 1
            self._prune_high()
        self._rebalance()

    def median(self) -> int:
        total = self.low_size + self.high_size
        if total == 0:
            return 0
        self._prune_low()
        if self.low_size > self.high_size:
            return int(-self.low[0])
        self._prune_high()
        return int((-self.low[0] + self.high[0]) // 2)


class AccountWindowState:
    """单账户 24 小时滑动窗口动态统计状态（支持单调 O(log W) 快路径与乱序精确回退）。"""

    __slots__ = ("dq", "total_amount", "cp_counts", "median_heap", "max_ts", "initialized")

    def __init__(self) -> None:
        self.dq: deque[tuple[int, int, str]] = deque()
        self.total_amount: int = 0
        self.cp_counts: dict[str, int] = {}
        self.median_heap: DualHeapMedian = DualHeapMedian()
        self.max_ts: int = 0
        self.initialized: bool = False

    def load_rows(self, rows: list[tuple[int, int, str]]) -> None:
        """从按 ts 升序排列的 (ts, amount_cents, counterparty_id) 初始化窗口状态。"""
        self.dq.clear()
        self.total_amount = 0
        self.cp_counts.clear()
        self.median_heap = DualHeapMedian()
        self.max_ts = 0

        if rows:
            latest_ts = rows[-1][0]
            cutoff = latest_ts - SLIDING_WINDOW_SECONDS
            self.max_ts = latest_ts
            for r_ts, r_amt, r_cp in rows:
                if r_ts >= cutoff:
                    self.dq.append((r_ts, r_amt, r_cp))
                    self.total_amount += r_amt
                    self.cp_counts[r_cp] = self.cp_counts.get(r_cp, 0) + 1
                    self.median_heap.add(r_amt)
        self.initialized = True

    def _push_item(self, ts: int, amount_cents: int, counterparty_id: str) -> None:
        self.dq.append((ts, amount_cents, counterparty_id))
        self.total_amount += amount_cents
        self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
        self.median_heap.add(amount_cents)

    def _pop_left_item(self) -> tuple[int, int, str]:
        item = self.dq.popleft()
        _, amt, cp = item
        self.total_amount -= amt
        cnt = self.cp_counts[cp]
        if cnt <= 1:
            del self.cp_counts[cp]
        else:
            self.cp_counts[cp] = cnt - 1
        self.median_heap.remove(amt)
        return item

    def _pop_right_item(self) -> tuple[int, int, str]:
        item = self.dq.pop()
        _, amt, cp = item
        self.total_amount -= amt
        cnt = self.cp_counts[cp]
        if cnt <= 1:
            del self.cp_counts[cp]
        else:
            self.cp_counts[cp] = cnt - 1
        self.median_heap.remove(amt)
        return item

    def push_monotonic(
        self,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
        undo_log: dict[str, Any],
    ) -> tuple[int, int, int, int]:
        """单调递增时间戳 O(log W) 窗口推进并记录可逆撤销日志。"""
        if "prev_max_ts" not in undo_log:
            undo_log["prev_max_ts"] = self.max_ts
            undo_log["evicted"] = []
            undo_log["appended"] = 0
            undo_log["dirty_ooo"] = False

        win_start = ts - SLIDING_WINDOW_SECONDS
        while self.dq and self.dq[0][0] < win_start:
            undo_log["evicted"].append(self._pop_left_item())

        self._push_item(ts, amount_cents, counterparty_id)
        undo_log["appended"] += 1
        if ts > self.max_ts:
            self.max_ts = ts

        return (
            len(self.dq),
            self.total_amount,
            len(self.cp_counts),
            self.median_heap.median(),
        )

    def insert_out_of_order(
        self,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
        undo_log: dict[str, Any],
    ) -> None:
        """在乱序时间戳提交路径中维护 dq 有序性与统计一致性。"""
        if "prev_max_ts" not in undo_log:
            undo_log["prev_max_ts"] = self.max_ts
            undo_log["evicted"] = []
            undo_log["appended"] = 0
        undo_log["dirty_ooo"] = True

        # 若该乱序交易处于当前 max_ts 的 24 小时窗内，按 ts 有序插入 dq
        if ts >= self.max_ts - SLIDING_WINDOW_SECONDS:
            items = list(self.dq)
            keys = [x[0] for x in items]
            pos = bisect_right(keys, ts)
            items.insert(pos, (ts, amount_cents, counterparty_id))
            self.dq = deque(items)
            self.total_amount += amount_cents
            self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
            self.median_heap.add(amount_cents)

    def rollback(self, undo_log: dict[str, Any]) -> None:
        """在批次失败时精确回滚本账户窗口状态。"""
        if undo_log.get("dirty_ooo"):
            # 发生乱序插入且批次失败时，置为未初始化以便下次从已提交数据库重建
            self.initialized = False
            self.dq.clear()
            self.total_amount = 0
            self.cp_counts.clear()
            self.median_heap = DualHeapMedian()
            self.max_ts = 0
            return

        for _ in range(int(undo_log.get("appended", 0))):
            self._pop_right_item()

        for ts_ev, amt_ev, cp_ev in reversed(undo_log.get("evicted", [])):
            self.dq.appendleft((ts_ev, amt_ev, cp_ev))
            self.total_amount += amt_ev
            self.cp_counts[cp_ev] = self.cp_counts.get(cp_ev, 0) + 1
            self.median_heap.add(amt_ev)

        self.max_ts = int(undo_log.get("prev_max_ts", self.max_ts))
