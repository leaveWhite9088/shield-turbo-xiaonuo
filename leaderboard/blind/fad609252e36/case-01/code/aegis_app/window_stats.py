# -*- coding: utf-8 -*-
"""24 小时滑动窗口 O(log W) 动态统计、精确中位数维护、乱序时间戳回退与原子回滚引擎。"""
from __future__ import annotations

import bisect
from collections import deque
from typing import Any, Callable

from .config import SLIDING_WINDOW_SECONDS
from .db import normalize_db_key, open_connection, register_reset_callback


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
    """单账户 24 小时滑动窗口追踪器（单调流 O(log W) 增量维护 + 乱序时间戳精确二分切片 + 原子撤销）。"""

    __slots__ = (
        "all_events",
        "max_ts",
        "win_deque",
        "win_sum",
        "cp_counts",
        "sorted_amounts",
    )

    def __init__(self) -> None:
        # 按 ts 升序排列的完整事件列表: (ts, amount_cents, counterparty_id)
        self.all_events: list[tuple[int, int, str]] = []
        self.max_ts: int = -1
        # 对应最新 max_ts 窗口 [max_ts - 86400, max_ts] 的增量结构
        self.win_deque: deque[tuple[int, int, str]] = deque()
        self.win_sum: int = 0
        self.cp_counts: dict[str, int] = {}
        self.sorted_amounts: list[int] = []

    def _rebuild_active_window_for_max_ts(self) -> None:
        self.win_deque.clear()
        self.win_sum = 0
        self.cp_counts.clear()
        self.sorted_amounts.clear()
        if not self.all_events:
            self.max_ts = -1
            return
        self.max_ts = self.all_events[-1][0]
        win_start = self.max_ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(self.all_events, (win_start, -1, ""))
        for idx in range(lo, len(self.all_events)):
            ev = self.all_events[idx]
            _, amt, cp = ev
            self.win_deque.append(ev)
            self.win_sum += amt
            self.cp_counts[cp] = self.cp_counts.get(cp, 0) + 1
            self.sorted_amounts.append(amt)
        self.sorted_amounts.sort()

    def stage_and_query(
        self,
        ts: int,
        amount_cents: int,
        counterparty_id: str,
        undo_log: list[Callable[[], None]],
    ) -> tuple[int, int, int, int]:
        """将当前交易纳入账户滑动窗口并返回 (win_tx_count, win_amount_cents, win_unique_cps, win_median_cents)，同时登记原子回滚动作。"""
        new_ev = (int(ts), int(amount_cents), str(counterparty_id))

        if ts >= self.max_ts:
            prev_max_ts = self.max_ts
            win_start = ts - SLIDING_WINDOW_SECONDS
            evicted: list[tuple[int, int, str]] = []

            while self.win_deque and self.win_deque[0][0] < win_start:
                old_ev = self.win_deque.popleft()
                evicted.append(old_ev)
                _, o_amt, o_cp = old_ev
                self.win_sum -= o_amt
                cnt = self.cp_counts.get(o_cp, 0)
                if cnt <= 1:
                    self.cp_counts.pop(o_cp, None)
                else:
                    self.cp_counts[o_cp] = cnt - 1
                pos = bisect.bisect_left(self.sorted_amounts, o_amt)
                self.sorted_amounts.pop(pos)

            self.max_ts = ts
            self.all_events.append(new_ev)
            self.win_deque.append(new_ev)
            self.win_sum += amount_cents
            self.cp_counts[counterparty_id] = self.cp_counts.get(counterparty_id, 0) + 1
            bisect.insort(self.sorted_amounts, amount_cents)

            def _undo_monotonic() -> None:
                self.all_events.pop()
                self.win_deque.pop()
                self.win_sum -= amount_cents
                c = self.cp_counts.get(counterparty_id, 0)
                if c <= 1:
                    self.cp_counts.pop(counterparty_id, None)
                else:
                    self.cp_counts[counterparty_id] = c - 1
                idx_amt = bisect.bisect_left(self.sorted_amounts, amount_cents)
                self.sorted_amounts.pop(idx_amt)

                for rev_ev in reversed(evicted):
                    _, r_amt, r_cp = rev_ev
                    self.win_deque.appendleft(rev_ev)
                    self.win_sum += r_amt
                    self.cp_counts[r_cp] = self.cp_counts.get(r_cp, 0) + 1
                    bisect.insort(self.sorted_amounts, r_amt)
                self.max_ts = prev_max_ts

            undo_log.append(_undo_monotonic)

            n = len(self.win_deque)
            mid = n // 2
            if n % 2 == 1:
                median = self.sorted_amounts[mid]
            else:
                median = (self.sorted_amounts[mid - 1] + self.sorted_amounts[mid]) // 2
            return n, self.win_sum, len(self.cp_counts), int(median)

        # 乱序时间戳（ts < max_ts）精确二分回退路径
        ins_idx = bisect.bisect_right(self.all_events, new_ev)
        self.all_events.insert(ins_idx, new_ev)
        self._rebuild_active_window_for_max_ts()

        def _undo_out_of_order() -> None:
            self.all_events.pop(ins_idx)
            self._rebuild_active_window_for_max_ts()

        undo_log.append(_undo_out_of_order)

        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(self.all_events, (win_start, -1, ""))
        hi = bisect.bisect_right(self.all_events, (ts, 1 << 62, "\uffff"))
        w_count = 0
        w_sum = 0
        w_cps: set[str] = set()
        w_amts: list[int] = []
        for idx in range(lo, hi):
            _, e_amt, e_cp = self.all_events[idx]
            w_count += 1
            w_sum += e_amt
            w_cps.add(e_cp)
            w_amts.append(e_amt)
        return w_count, w_sum, len(w_cps), compute_exact_median_cents(w_amts)


class TenantWindowState:
    """租户级多账户滑动窗口内存状态管理器。"""

    __slots__ = ("tenant_id", "accounts")

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.accounts: dict[str, AccountWindowTracker] = {}

    def get_or_create_account(self, account_id: str) -> AccountWindowTracker:
        tr = self.accounts.get(account_id)
        if tr is None:
            tr = AccountWindowTracker()
            self.accounts[account_id] = tr
        return tr


_MAX_TENANT_WINDOWS = 128
_TENANT_WINDOWS: dict[tuple[str, str], TenantWindowState] = {}


def _reset_tenant_windows(db_key: str) -> None:
    for k in [k for k in _TENANT_WINDOWS if k[0] == db_key]:
        _TENANT_WINDOWS.pop(k, None)


register_reset_callback(_reset_tenant_windows)


def get_or_load_tenant_window_state(db_path: str, tenant_id: str) -> TenantWindowState:
    """获取或从 SQLite 一次性初始化租户的滑动窗口状态（后续批次全内存 O(log W) 增量维护）。"""
    db_key = normalize_db_key(db_path)
    cache_key = (db_key, tenant_id)
    state = _TENANT_WINDOWS.get(cache_key)
    if state is not None:
        return state

    state = TenantWindowState(tenant_id)
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT account_id, counterparty_id, amount_cents, ts "
            "FROM transactions WHERE tenant_id = ? ORDER BY ts ASC, rowid ASC",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    for r in rows:
        acct = str(r["account_id"])
        cp = str(r["counterparty_id"])
        amt = int(r["amount_cents"])
        ts = int(r["ts"])
        tr = state.get_or_create_account(acct)
        tr.all_events.append((ts, amt, cp))

    for tr in state.accounts.values():
        tr._rebuild_active_window_for_max_ts()

    if len(_TENANT_WINDOWS) >= _MAX_TENANT_WINDOWS and cache_key not in _TENANT_WINDOWS:
        _TENANT_WINDOWS.pop(next(iter(_TENANT_WINDOWS)), None)
    _TENANT_WINDOWS[cache_key] = state
    return state
