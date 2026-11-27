# -*- coding: utf-8 -*-
"""24 小时滑动窗口 O(log W) 双堆动态精确中位数、乱序时间戳精确定位与原子回滚引擎。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter
import heapq


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n // 2
    if n & 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)


class DualHeapWindow:
    """对顶双堆 + 惰性删除维护滑动窗口精确动态中位数（单次增删均摊 O(log W)，含墓碑水位压缩）。"""

    __slots__ = ("_low", "_high", "_del_low", "_del_high", "low_size", "high_size", "tombstones")

    def __init__(self) -> None:
        self._low: list[int] = []  # 最大堆（存负值），维护较小的一半 ceil(N/2)
        self._high: list[int] = []  # 最小堆（存正值），维护较大的一半 floor(N/2)
        self._del_low: Counter[int] = Counter()
        self._del_high: Counter[int] = Counter()
        self.low_size = 0
        self.high_size = 0
        self.tombstones = 0

    @property
    def size(self) -> int:
        return self.low_size + self.high_size

    def clear(self) -> None:
        self._low.clear()
        self._high.clear()
        self._del_low.clear()
        self._del_high.clear()
        self.low_size = 0
        self.high_size = 0
        self.tombstones = 0

    def rebuild_from(self, values: list[int]) -> None:
        self.clear()
        if not values:
            return
        ordered = sorted(values)
        n = len(ordered)
        split = (n + 1) // 2
        self._low = [-x for x in ordered[:split]]
        heapq.heapify(self._low)
        self._high = ordered[split:]
        heapq.heapify(self._high)
        self.low_size = split
        self.high_size = n - split

    def _prune_low(self) -> None:
        low = self._low
        del_low = self._del_low
        while low:
            top = -low[0]
            cnt = del_low.get(top, 0)
            if cnt <= 0:
                break
            heapq.heappop(low)
            if cnt == 1:
                del del_low[top]
            else:
                del_low[top] = cnt - 1
            self.tombstones -= 1

    def _prune_high(self) -> None:
        high = self._high
        del_high = self._del_high
        while high:
            top = high[0]
            cnt = del_high.get(top, 0)
            if cnt <= 0:
                break
            heapq.heappop(high)
            if cnt == 1:
                del del_high[top]
            else:
                del_high[top] = cnt - 1
            self.tombstones -= 1

    def _rebalance(self) -> None:
        self._prune_low()
        self._prune_high()
        while self.low_size > self.high_size + 1:
            val = -heapq.heappop(self._low)
            self.low_size -= 1
            heapq.heappush(self._high, val)
            self.high_size += 1
            self._prune_low()
        while self.low_size < self.high_size:
            val = heapq.heappop(self._high)
            self.high_size -= 1
            heapq.heappush(self._low, -val)
            self.low_size += 1
            self._prune_high()

    def add(self, value: int) -> None:
        self._prune_low()
        self._prune_high()
        if self.low_size == 0 or value <= -self._low[0]:
            heapq.heappush(self._low, -value)
            self.low_size += 1
        else:
            heapq.heappush(self._high, value)
            self.high_size += 1
        self._rebalance()

    def remove(self, value: int) -> None:
        self._prune_low()
        self._prune_high()
        if self.low_size > 0 and value <= -self._low[0]:
            self._del_low[value] += 1
            self.low_size -= 1
            self.tombstones += 1
            if value == -self._low[0]:
                self._prune_low()
        else:
            self._del_high[value] += 1
            self.high_size -= 1
            self.tombstones += 1
            if self._high and value == self._high[0]:
                self._prune_high()
        self._rebalance()

    def median(self) -> int:
        total = self.low_size + self.high_size
        if total == 0:
            return 0
        self._prune_low()
        if total & 1:
            return -self._low[0]
        self._prune_high()
        return (-self._low[0] + self._high[0]) // 2


class AccountWindowTracker:
    """单账户滑动时间窗追踪器：兼容单调流式 O(log W) 推进、乱序时间戳精确回退及批次异常回滚。"""

    __slots__ = ("ts_list", "amt_list", "cp_list", "left", "right", "win_sum", "cp_counts", "heaps")

    def __init__(self) -> None:
        self.ts_list: list[int] = []
        self.amt_list: list[int] = []
        self.cp_list: list[str] = []
        self.left = 0
        self.right = 0
        self.win_sum = 0
        self.cp_counts: dict[str, int] = {}
        self.heaps = DualHeapWindow()

    def load_sorted_initial(self, rows: list[tuple[int, int, str]]) -> None:
        for ts, amt, cp in rows:
            self.ts_list.append(ts)
            self.amt_list.append(amt)
            self.cp_list.append(cp)

    def _include_item(self, amt: int, cp: str) -> None:
        self.win_sum += amt
        self.cp_counts[cp] = self.cp_counts.get(cp, 0) + 1
        self.heaps.add(amt)

    def _exclude_item(self, amt: int, cp: str) -> None:
        self.win_sum -= amt
        cnt = self.cp_counts.get(cp, 0)
        if cnt <= 1:
            self.cp_counts.pop(cp, None)
        else:
            self.cp_counts[cp] = cnt - 1
        self.heaps.remove(amt)

    def _reposition(self, win_start: int, win_end: int) -> None:
        ts_arr = self.ts_list
        if not ts_arr:
            return
        t_left = bisect_left(ts_arr, win_start)
        t_right = bisect_right(ts_arr, win_end)

        cur_l = self.left
        cur_r = self.right
        # 若新旧窗口完全不重叠，直接重建活跃区间并顺便清空惰性墓碑
        if cur_l == cur_r or t_left == t_right or max(cur_l, t_left) >= min(cur_r, t_right):
            self.heaps.clear()
            self.win_sum = 0
            self.cp_counts.clear()
            self.left = t_left
            self.right = t_right
            amts = self.amt_list
            cps = self.cp_list
            if t_right > t_left:
                sub_amts = amts[t_left:t_right]
                self.win_sum = sum(sub_amts)
                for idx in range(t_left, t_right):
                    c = cps[idx]
                    self.cp_counts[c] = self.cp_counts.get(c, 0) + 1
                self.heaps.rebuild_from(sub_amts)
            return

        amts = self.amt_list
        cps = self.cp_list
        if t_right > cur_r:
            for idx in range(cur_r, t_right):
                self._include_item(amts[idx], cps[idx])
        elif t_right < cur_r:
            for idx in range(t_right, cur_r):
                self._exclude_item(amts[idx], cps[idx])
        self.right = t_right

        if t_left > cur_l:
            for idx in range(cur_l, t_left):
                self._exclude_item(amts[idx], cps[idx])
        elif t_left < cur_l:
            for idx in range(t_left, cur_l):
                self._include_item(amts[idx], cps[idx])
        self.left = t_left

        # 控制惰性墓碑占空比，保证堆体积严格 O(W)
        act_sz = self.heaps.size
        if self.heaps.tombstones > act_sz * 2 + 64:
            self.heaps.rebuild_from(amts[self.left : self.right])

    def insert_and_measure(
        self,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
        window_seconds: int,
    ) -> tuple[int, int, int, int, int]:
        """定位 [ts - window_seconds, ts]，插入当前交易并返回 (ins_pos, count, sum, unique_cps, median)。"""
        self._reposition(ts - window_seconds, ts)
        ins_pos = self.right
        if ins_pos == len(self.ts_list):
            self.ts_list.append(ts)
            self.amt_list.append(amount_cents)
            self.cp_list.append(counterparty_id)
        else:
            self.ts_list.insert(ins_pos, ts)
            self.amt_list.insert(ins_pos, amount_cents)
            self.cp_list.insert(ins_pos, counterparty_id)

        self.right += 1
        self._include_item(amount_cents, counterparty_id)

        return (
            ins_pos,
            self.right - self.left,
            self.win_sum,
            len(self.cp_counts),
            self.heaps.median(),
        )

    def undo_insert(self, ins_pos: int) -> None:
        """按逆序撤销一次 insert_and_measure，恢复零污染内存状态。"""
        amt = self.amt_list[ins_pos]
        cp = self.cp_list[ins_pos]
        if self.left <= ins_pos < self.right:
            self._exclude_item(amt, cp)
            self.right -= 1
        elif ins_pos < self.left:
            self.left -= 1
            self.right -= 1

        self.ts_list.pop(ins_pos)
        self.amt_list.pop(ins_pos)
        self.cp_list.pop(ins_pos)
