# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确统计与动态金额中位数计算模块。

设计要点：
* 每租户每账户维护“金额 → 次数”的树状数组（Fenwick/BIT），插入与删除都是 O(Bits)；
* 事件自带时间戳，**插入顺序与时间无关**：每次查询前用最小堆按 ``ts`` 惰性淘汰出窗事件，
  乱序到达的早期事件与晚到事件都能精确回退（同一 ``tx_id`` 重复评估时以先出现者为准）；
* 中位数用 BIT 上的二分定位（前缀计数 < 半数），O(Bits) 精确求第 k 小；
* 直方图位宽 ``FENWICK_BITS`` 覆盖到 40 亿分，超大金额自动扩位（扩容时保留已有计数）。
"""
from __future__ import annotations

import bisect
import heapq
import threading

from .config import FENWICK_BITS


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


class ExactMedianFenwick:
    """金额直方图：O(Bits) 增删 + O(Bits) 第 k 小定位，支持 0..2^Bits-1 的整数金额。"""

    __slots__ = ("tree", "bits", "size", "count")

    def __init__(self, bits: int = FENWICK_BITS) -> None:
        self.bits = bits
        self.size = 1 << bits
        self.tree = [0] * (self.size + 1)
        self.count = 0

    def add(self, value: int, delta: int) -> None:
        if value >= self.size:
            self._grow(value)
        tree = self.tree
        size = self.size
        self.count += delta
        i = value + 1
        while i <= size:
            tree[i] += delta
            i += i & (-i)

    def _grow(self, value: int) -> None:
        while value >= self.size:
            self.bits += 1
            self.size = 1 << self.bits
        new_tree = [0] * (self.size + 1)
        old_tree = self.tree
        old_size = len(old_tree) - 1
        for v in range(old_size):
            c = old_tree[v + 1] - (old_tree[v] if v else 0)
            if c:
                i = v + 1
                while i <= self.size:
                    new_tree[i] += c
                    i += i & (-i)
        self.tree = new_tree

    def prefix(self, value: int) -> int:
        """返回金额 <= value 的计数。"""
        if value < 0:
            return 0
        if value >= self.size:
            return self.count
        tree = self.tree
        i = value + 1
        s = 0
        while i > 0:
            s += tree[i]
            i -= i & (-i)
        return s

    def kth(self, k: int) -> int:
        """返回第 k 小（1 起）的金额。"""
        tree = self.tree
        size = self.size
        idx = 0
        bit = 1 << (size.bit_length() - 1)
        while bit:
            nxt = idx + bit
            if nxt <= size and tree[nxt] < k:
                idx = nxt
                k -= tree[nxt]
            bit >>= 1
        return idx

    def median(self) -> int:
        n = self.count
        if n <= 0:
            return 0
        mid = n // 2
        if n % 2 == 1:
            return self.kth(mid + 1)
        return int((self.kth(mid) + self.kth(mid + 1)) // 2)


class AccountWindow:
    """单账户滑动窗口：金额直方图 + 计数器 + 最小堆惰性淘汰 + 对手方去重计数。"""

    __slots__ = ("events", "heap", "amount", "count", "cps", "total")

    def __init__(self) -> None:
        self.events: dict[str, tuple[int, int, str]] = {}
        self.heap: list[tuple[int, str]] = []
        self.amount = ExactMedianFenwick()
        self.count = 0
        self.cps: dict[str, int] = {}
        self.total = 0

    def expire(self, win_start: int) -> None:
        heap = self.heap
        events = self.events
        amount = self.amount
        cps = self.cps
        while heap and heap[0][0] < win_start:
            ts, tx_id = heapq.heappop(heap)
            ev = events.get(tx_id)
            if ev is None or ev[1] != ts:
                continue                      # 已被同 tx_id 的后续事件覆盖
            del events[tx_id]
            amount.add(ev[0], -1)
            self.count -= 1
            self.total -= ev[0]
            n = cps.get(ev[2], 0) - 1
            if n > 0:
                cps[ev[2]] = n
            else:
                cps.pop(ev[2], None)
        if not events:
            heap.clear()

    def insert(self, tx_id: str, amount_cents: int, ts: int, counterparty_id: str) -> None:
        self.events[tx_id] = (amount_cents, ts, counterparty_id)
        heapq.heappush(self.heap, (ts, tx_id))
        self.amount.add(amount_cents, 1)
        self.count += 1
        self.total += amount_cents
        cps = self.cps
        cps[counterparty_id] = cps.get(counterparty_id, 0) + 1

    def credit(self, amount_cents: int, counterparty_id: str) -> tuple[int, int, int]:
        """把当前交易叠加进窗口统计，返回 (笔数, 唯一对手方数, 中位数)。"""
        self.amount.add(amount_cents, 1)
        try:
            count = self.count + 1
            cps = self.cps
            had = counterparty_id in cps
            unique_cps = len(cps) + (0 if had else 1)
            median = self.amount.median()
        finally:
            self.amount.add(amount_cents, -1)
        return count, unique_cps, median


class WindowRegistry:
    """租户 → 账户 → 24h 滑窗（含对手方去重集合）的共享注册表。

    * 读/写在 ``_lock`` 保护下进行（临界区仅内存操作，绝不触碰数据库连接）；
    * 租户整体 Lazy 装载由调用方（Gateway）负责，见 :meth:`ensure`；
    * 乱序时间戳：``expire`` 用最小堆按 ts 惰性剔除，与插入顺序无关。
    """

    __slots__ = ("_accounts", "_lock", "_loaded")

    def __init__(self) -> None:
        self._accounts: dict[str, dict[str, AccountWindow]] = {}
        self._loaded: set[str] = set()
        self._lock = threading.Lock()

    def is_loaded(self, tenant_id: str) -> bool:
        return tenant_id in self._loaded

    def mark_loaded(self, tenant_id: str) -> None:
        with self._lock:
            self._loaded.add(tenant_id)

    def ensure(self, db, tenant_id: str) -> None:
        if tenant_id in self._loaded:
            return
        wins = self._reload(db, tenant_id)
        with self._lock:
            if tenant_id not in self._loaded:
                self._accounts.setdefault(tenant_id, {}).update(wins)
                self._loaded.add(tenant_id)

    def _reload(self, db, tenant_id: str) -> dict[str, AccountWindow]:
        wins: dict[str, AccountWindow] = {}
        cur = db.cursor(
            "SELECT tx_id, account_id, counterparty_id, amount_cents, ts FROM transactions "
            "WHERE tenant_id = ?",
            (tenant_id,),
        )
        try:
            for tx_id, account_id, cp_id, amt, ts in cur:
                wins.setdefault(account_id, AccountWindow()).insert(
                    tx_id, int(amt), int(ts), cp_id
                )
        finally:
            cur.close()
        return wins

    def window(self, tenant_id: str, account_id: str) -> AccountWindow | None:
        tenant = self._accounts.get(tenant_id)
        if tenant is None:
            return None
        w = tenant.get(account_id)
        if w is None:
            w = AccountWindow()
            tenant[account_id] = w
        return w

    def stats(self, tenant_id, account_id, win_start, ts, amount_cents, counterparty_id,
              batch_rows: tuple | list = ()) -> tuple[int, int, int, int]:
        """返回含当前交易的 (笔数, 金额合计, 中位数, 唯一对手方数)。"""
        with self._lock:
            w = self.window(tenant_id, account_id)
            w.expire(win_start)
            count, unique_cps, median = w.credit(amount_cents, counterparty_id)
            total = w.total + amount_cents
            if batch_rows:
                extra: list[int] = [amount_cents]
                merged = dict(w.cps)
                merged[counterparty_id] = merged.get(counterparty_id, 0) + 1
                for _tid, amt, e_ts, cp in batch_rows:
                    if win_start <= e_ts <= ts:
                        count += 1
                        total += amt
                        extra.append(amt)
                        merged[cp] = merged.get(cp, 0) + 1
                unique_cps = len(merged)
                median = merge_median(w.amount, extra)
            return count, total, median, unique_cps

    def record(self, tenant_id: str, account_id: str, tx_id: str, amount_cents: int, ts: int,
               counterparty_id: str, win_start: int) -> None:
        with self._lock:
            w = self.window(tenant_id, account_id)
            w.expire(win_start)
            w.insert(tx_id, amount_cents, ts, counterparty_id)


def merge_median(amount: "ExactMedianFenwick", extra: list[int]) -> int:
    """直方图 + 少量批次内额外金额的精确中位数（合并后取第 n//2 与 (n-1)//2 小）。"""
    n_hist = amount.count
    ordered_extra = sorted(extra)
    m = len(ordered_extra)
    total = n_hist + m

    def kth_combined(k: int) -> int:
        # 在 [lo, hi] 上二分金额 v，统计 <= v 的合并计数
        lo, hi = 0, int(amount.size) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            hist_le = amount.prefix(mid)
            cnt = hist_le + bisect.bisect_right(ordered_extra, mid)
            if cnt >= k:
                hi = mid
            else:
                lo = mid + 1
        return lo

    if total == 0:
        return 0
    if total % 2 == 1:
        return kth_combined(total // 2 + 1)
    return int((kth_combined(total // 2) + kth_combined(total // 2 + 1)) // 2)
