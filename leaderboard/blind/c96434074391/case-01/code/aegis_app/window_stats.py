# -*- coding: utf-8 -*-
"""24 小时滑动窗口精确四维统计、O(log W) 对顶双堆动态中位数、乱序时间戳精确回退与批次回滚引擎。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import deque
import heapq
from typing import Any

from .config import SLIDING_WINDOW_SECONDS
from .db import DatabaseRuntime


def compute_exact_median_cents(amounts: list[int]) -> int:
    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
    if not amounts:
        return 0
    ordered = sorted(amounts)
    n = len(ordered)
    mid = n >> 1
    if n & 1:
        return int(ordered[mid])
    return int((ordered[mid - 1] + ordered[mid]) // 2)


class DualHeapMedian:
    """支持延迟删除的对顶双堆（O(log W) 插入与过期驱逐，O(1) 精确中位数读取）。"""

    __slots__ = ("lower", "upper", "lower_size", "upper_size", "delayed_lower", "delayed_upper")

    def __init__(self) -> None:
        self.lower: list[int] = []  # 最大堆（存相反数 -x）
        self.upper: list[int] = []  # 最小堆（存 x）
        self.lower_size = 0
        self.upper_size = 0
        self.delayed_lower: dict[int, int] = {}
        self.delayed_upper: dict[int, int] = {}

    def clear(self) -> None:
        self.lower.clear()
        self.upper.clear()
        self.lower_size = 0
        self.upper_size = 0
        self.delayed_lower.clear()
        self.delayed_upper.clear()

    def _prune_lower(self) -> None:
        dl = self.delayed_lower
        lw = self.lower
        while lw:
            top = -lw[0]
            cnt = dl.get(top, 0)
            if cnt <= 0:
                break
            heapq.heappop(lw)
            if cnt == 1:
                del dl[top]
            else:
                dl[top] = cnt - 1

    def _prune_upper(self) -> None:
        du = self.delayed_upper
        up = self.upper
        while up:
            top = up[0]
            cnt = du.get(top, 0)
            if cnt <= 0:
                break
            heapq.heappop(up)
            if cnt == 1:
                del du[top]
            else:
                du[top] = cnt - 1

    def _rebalance(self) -> None:
        self._prune_lower()
        self._prune_upper()
        while self.lower_size > self.upper_size + 1:
            self._prune_lower()
            val = -heapq.heappop(self.lower)
            self.lower_size -= 1
            heapq.heappush(self.upper, val)
            self.upper_size += 1
        while self.lower_size < self.upper_size:
            self._prune_upper()
            val = heapq.heappop(self.upper)
            self.upper_size -= 1
            heapq.heappush(self.lower, -val)
            self.lower_size += 1
        self._prune_lower()
        self._prune_upper()

    def insert(self, val: int) -> None:
        self._prune_lower()
        if not self.lower or val <= -self.lower[0]:
            heapq.heappush(self.lower, -val)
            self.lower_size += 1
        else:
            heapq.heappush(self.upper, val)
            self.upper_size += 1
        self._rebalance()

    def remove(self, val: int) -> None:
        self._prune_lower()
        self._prune_upper()
        if self.lower:
            l_top = -self.lower[0]
            if val < l_top:
                self.delayed_lower[val] = self.delayed_lower.get(val, 0) + 1
                self.lower_size -= 1
            elif val > l_top:
                if self.upper and val == self.upper[0]:
                    heapq.heappop(self.upper)
                    self.upper_size -= 1
                else:
                    self.delayed_upper[val] = self.delayed_upper.get(val, 0) + 1
                    self.upper_size -= 1
            else:
                heapq.heappop(self.lower)
                self.lower_size -= 1
        elif self.upper:
            if val == self.upper[0]:
                heapq.heappop(self.upper)
                self.upper_size -= 1
            else:
                self.delayed_upper[val] = self.delayed_upper.get(val, 0) + 1
                self.upper_size -= 1
        self._rebalance()

    def median(self) -> int:
        total = self.lower_size + self.upper_size
        if total <= 0:
            return 0
        self._prune_lower()
        if total & 1:
            return int(-self.lower[0])
        self._prune_upper()
        return int((-self.lower[0] + self.upper[0]) // 2)


class AccountWindowState:
    """单账户滑动窗口状态（单调流走 O(log W) 对顶双堆，乱序时间戳走有序切片精确回退）。"""

    __slots__ = (
        "hist_ts",
        "hist_amt",
        "hist_cp",
        "max_ts",
        "hot_ready",
        "win_deque",
        "win_sum",
        "cp_counts",
        "median_heap",
    )

    def __init__(self) -> None:
        self.hist_ts: list[int] = []
        self.hist_amt: list[int] = []
        self.hist_cp: list[str] = []
        self.max_ts = -1
        self.hot_ready = True
        self.win_deque: deque[tuple[int, int, str]] = deque()
        self.win_sum = 0
        self.cp_counts: dict[str, int] = {}
        self.median_heap = DualHeapMedian()

    def clone_snapshot(self) -> tuple[list[int], list[int], list[str]]:
        return (list(self.hist_ts), list(self.hist_amt), list(self.hist_cp))

    def restore_from_snapshot(self, snap: tuple[list[int], list[int], list[str]]) -> None:
        self.hist_ts, self.hist_amt, self.hist_cp = snap
        self.max_ts = self.hist_ts[-1] if self.hist_ts else -1
        self.hot_ready = False
        self.win_deque.clear()
        self.win_sum = 0
        self.cp_counts.clear()
        self.median_heap.clear()

    def rebuild_hot_window(self, anchor_ts: int) -> None:
        self.win_deque.clear()
        self.win_sum = 0
        self.cp_counts.clear()
        self.median_heap.clear()
        win_start = anchor_ts - SLIDING_WINDOW_SECONDS
        start_idx = bisect_left(self.hist_ts, win_start)
        for idx in range(start_idx, len(self.hist_ts)):
            t_val = self.hist_ts[idx]
            a_val = self.hist_amt[idx]
            c_val = self.hist_cp[idx]
            self.win_deque.append((t_val, a_val, c_val))
            self.win_sum += a_val
            self.cp_counts[c_val] = self.cp_counts.get(c_val, 0) + 1
            self.median_heap.insert(a_val)
        self.hot_ready = True


class WindowBatchUndo:
    """单批次滑动窗口原子回滚记录。"""

    __slots__ = ("monotonic_ops", "full_snapshots", "created_accounts")

    def __init__(self) -> None:
        # 逆序记录单调操作: (account_id, prev_max_ts, popped_front_list)
        self.monotonic_ops: list[tuple[str, int, list[tuple[int, int, str]]]] = []
        # 触发乱序插入的账户完整快照: account_id -> (hist_ts, hist_amt, hist_cp)
        self.full_snapshots: dict[str, tuple[list[int], list[int], list[str]]] = {}
        self.created_accounts: set[str] = set()


class TenantWindowManager:
    """租户级多账户 24 小时动态滑动窗口管理器。"""

    __slots__ = ("tenant_id", "accounts")

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.accounts: dict[str, AccountWindowState] = {}

    def evaluate_and_record(
        self,
        account_id: str,
        counterparty_id: str,
        amount_cents: int,
        ts: int,
        undo: WindowBatchUndo,
    ) -> tuple[int, int, int, int]:
        state = self.accounts.get(account_id)
        if state is None:
            state = AccountWindowState()
            self.accounts[account_id] = state
            undo.created_accounts.add(account_id)

        # 若该账户在本批已进入快照回退模式，或本次出现乱序时间戳 ts < state.max_ts
        if account_id in undo.full_snapshots or ts < state.max_ts:
            if account_id not in undo.full_snapshots and account_id not in undo.created_accounts:
                # 先把本批此前在该账户上的单调操作逆向还原以提取批前干净快照，再重放或直接基于当前操作
                pass
            if account_id not in undo.full_snapshots:
                # 若本批此前已有该账户的单调操作，先将其从 monotonic_ops 中剥离或直接在此之前快照
                # 为保证 100% 精确，若此前本批已有 monotonic_ops 触碰该账户，先逆向还原得到批前快照再重放本批先序笔
                prior_ops = [op for op in undo.monotonic_ops if op[0] == account_id]
                if prior_ops:
                    replayed_items: list[tuple[int, int, str]] = []
                    for _, prev_max, popped_front in reversed(prior_ops):
                        t_p, a_p, c_p = state.win_deque.pop()
                        replayed_items.append((t_p, a_p, c_p))
                        state.hist_ts.pop()
                        state.hist_amt.pop()
                        state.hist_cp.pop()
                        state.win_sum -= a_p
                        rem_c = state.cp_counts[c_p] - 1
                        if rem_c <= 0:
                            del state.cp_counts[c_p]
                        else:
                            state.cp_counts[c_p] = rem_c
                        state.median_heap.remove(a_p)
                        for pt, pa, pc in reversed(popped_front):
                            state.win_deque.appendleft((pt, pa, pc))
                            state.win_sum += pa
                            state.cp_counts[pc] = state.cp_counts.get(pc, 0) + 1
                            state.median_heap.insert(pa)
                        state.max_ts = prev_max
                    undo.monotonic_ops = [op for op in undo.monotonic_ops if op[0] != account_id]
                    undo.full_snapshots[account_id] = state.clone_snapshot()
                    for rt_ts, rt_amt, rt_cp in reversed(replayed_items):
                        pos = bisect_right(state.hist_ts, rt_ts)
                        state.hist_ts.insert(pos, rt_ts)
                        state.hist_amt.insert(pos, rt_amt)
                        state.hist_cp.insert(pos, rt_cp)
                        if rt_ts > state.max_ts:
                            state.max_ts = rt_ts
                    state.hot_ready = False
                else:
                    undo.full_snapshots[account_id] = state.clone_snapshot()

            # 精确区间切片路径 [ts - 86400, ts]
            win_start = ts - SLIDING_WINDOW_SECONDS
            lo = bisect_left(state.hist_ts, win_start)
            hi = bisect_right(state.hist_ts, ts)
            slice_amts = state.hist_amt[lo:hi]
            slice_amts.append(amount_cents)
            uniq_cps = set(state.hist_cp[lo:hi])
            uniq_cps.add(counterparty_id)

            win_cnt = len(slice_amts)
            win_sum = sum(slice_amts)
            win_ucp = len(uniq_cps)
            win_med = compute_exact_median_cents(slice_amts)

            ins_pos = bisect_right(state.hist_ts, ts)
            state.hist_ts.insert(ins_pos, ts)
            state.hist_amt.insert(ins_pos, amount_cents)
            state.hist_cp.insert(ins_pos, counterparty_id)
            if ts > state.max_ts:
                state.max_ts = ts
            state.hot_ready = False
            return win_cnt, win_sum, win_ucp, win_med

        # 单调热路径：ts >= state.max_ts，O(log W) 对顶双堆推进
        if not state.hot_ready:
            state.rebuild_hot_window(ts)

        prev_max_ts = state.max_ts
        win_start = ts - SLIDING_WINDOW_SECONDS
        popped: list[tuple[int, int, str]] = []
        dq = state.win_deque
        while dq and dq[0][0] < win_start:
            old_ts, old_amt, old_cp = dq.popleft()
            popped.append((old_ts, old_amt, old_cp))
            state.win_sum -= old_amt
            c_rem = state.cp_counts[old_cp] - 1
            if c_rem <= 0:
                del state.cp_counts[old_cp]
            else:
                state.cp_counts[old_cp] = c_rem
            state.median_heap.remove(old_amt)

        dq.append((ts, amount_cents, counterparty_id))
        state.win_sum += amount_cents
        state.cp_counts[counterparty_id] = state.cp_counts.get(counterparty_id, 0) + 1
        state.median_heap.insert(amount_cents)

        state.hist_ts.append(ts)
        state.hist_amt.append(amount_cents)
        state.hist_cp.append(counterparty_id)
        state.max_ts = ts

        undo.monotonic_ops.append((account_id, prev_max_ts, popped))

        return (
            len(dq),
            state.win_sum,
            len(state.cp_counts),
            state.median_heap.median(),
        )

    def rollback(self, undo: WindowBatchUndo) -> None:
        """将内存滑动窗口 100% 原子回退至批处理开始前的精确状态。"""
        for acct_id, prev_max, popped_front in reversed(undo.monotonic_ops):
            state = self.accounts.get(acct_id)
            if state is None:
                continue
            _, a_p, c_p = state.win_deque.pop()
            state.hist_ts.pop()
            state.hist_amt.pop()
            state.hist_cp.pop()
            state.win_sum -= a_p
            rem_c = state.cp_counts[c_p] - 1
            if rem_c <= 0:
                del state.cp_counts[c_p]
            else:
                state.cp_counts[c_p] = rem_c
            state.median_heap.remove(a_p)
            for pt, pa, pc in reversed(popped_front):
                state.win_deque.appendleft((pt, pa, pc))
                state.win_sum += pa
                state.cp_counts[pc] = state.cp_counts.get(pc, 0) + 1
                state.median_heap.insert(pa)
            state.max_ts = prev_max

        for acct_id, snap in undo.full_snapshots.items():
            if acct_id in undo.created_accounts:
                continue
            state = self.accounts.get(acct_id)
            if state is not None:
                state.restore_from_snapshot(snap)

        for acct_id in undo.created_accounts:
            self.accounts.pop(acct_id, None)


def _load_tenant_window_manager(rt: DatabaseRuntime, tenant_id: str) -> TenantWindowManager:
    mgr = TenantWindowManager(tenant_id)
    with rt.read_conn() as conn:
        cur = conn.execute(
            "SELECT account_id, counterparty_id, amount_cents, ts "
            "FROM transactions WHERE tenant_id = ? ORDER BY account_id ASC, ts ASC",
            (tenant_id,),
        )
        while True:
            rows = cur.fetchmany(1024)
            if not rows:
                break
            for r in rows:
                acct = str(r["account_id"])
                cp = str(r["counterparty_id"])
                amt = int(r["amount_cents"])
                ts = int(r["ts"])
                st = mgr.accounts.get(acct)
                if st is None:
                    st = AccountWindowState()
                    st.hot_ready = False
                    mgr.accounts[acct] = st
                st.hist_ts.append(ts)
                st.hist_amt.append(amt)
                st.hist_cp.append(cp)
                if ts > st.max_ts:
                    st.max_ts = ts
    return mgr


def get_tenant_window_manager(rt: DatabaseRuntime, tenant_id: str) -> TenantWindowManager:
    cached = rt.window_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.tenant_meta_lock(tenant_id):
        cached = rt.window_cache.get(tenant_id)
        if cached is not None:
            return cached
        loaded = _load_tenant_window_manager(rt, tenant_id)
        rt.window_cache.set(tenant_id, loaded)
        return loaded
