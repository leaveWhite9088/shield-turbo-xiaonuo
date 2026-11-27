# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph）与名单管理模块。

图连通与传染跳数定义：
- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条双向资金关联边；
- 当前正在评估的交易自身的边 (tx.account_id, tx.counterparty_id) 同步计入当前图；
- 设活跃受制裁实体集合为 S（sanctioned_entities 表中 active=1 的 entity_id）：
  * 若 tx.account_id in S 或 tx.counterparty_id in S（即本次交易两端直接命中制裁名单），则传染跳数 hop = 1；
  * 否则计算 tx.account_id 与 tx.counterparty_id 到集合 S 中任意实体的最短无向边路径长度 d_min：
    传染跳数 hop = d_min + 1（例如 tx.counterparty_id 曾与受制裁实体直接交易过，即 d_min = 1，则本次交易 hop = 2；
    若隔一层中间跳板账户，d_min = 2，则本次交易 hop = 3）；
  * 若 hop > 3 或不可达，记为 0（无三跳内制裁传染）。
"""
from __future__ import annotations

import bisect
from collections import deque
import pathlib
import threading
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import bump_domain_epoch, get_domain_epoch, open_connection
from .window_stats import AccountWindowTracker


class TenantTxEngine:
    """租户级内存滑动窗口与三跳受制裁资金传染图引擎（支持乱序时间戳与批次失败原子快照回滚）。"""

    __slots__ = (
        "tenant_id",
        "lock",
        "sanction_epoch",
        "sanctioned_set",
        "accounts",
        "edge_records",
        "max_edge_ts",
        "edge_queue",
        "adj_latest_ts",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.lock = threading.RLock()
        self.sanction_epoch: int = -1
        self.sanctioned_set: set[str] = set()
        self.accounts: dict[str, AccountWindowTracker] = {}
        self.edge_records: list[tuple[int, str, str]] = []
        self.max_edge_ts: int = -1
        self.edge_queue: deque[tuple[int, str, str]] = deque()
        self.adj_latest_ts: dict[str, dict[str, int]] = {}

    def sync_sanctions(self, db_path: str) -> set[str]:
        cur_ep = get_domain_epoch(db_path, self.tenant_id, "sanction")
        if self.sanction_epoch == cur_ep:
            return self.sanctioned_set
        conn = open_connection(db_path)
        try:
            s_rows = conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (self.tenant_id,),
            ).fetchall()
        finally:
            conn.close()
        self.sanctioned_set = {str(r["entity_id"]) for r in s_rows}
        self.sanction_epoch = cur_ep
        return self.sanctioned_set

    def build_from_db(self, db_path: str) -> None:
        conn = open_connection(db_path)
        try:
            tx_rows = conn.execute(
                "SELECT account_id, counterparty_id, amount_cents, ts "
                "FROM transactions WHERE tenant_id = ? ORDER BY ts ASC",
                (self.tenant_id,),
            ).fetchall()
        finally:
            conn.close()

        with self.lock:
            self.accounts.clear()
            self.edge_records.clear()
            self.edge_queue.clear()
            self.adj_latest_ts.clear()
            self.max_edge_ts = -1

            acct_recs: dict[str, list[tuple[int, int, str]]] = {}
            for r in tx_rows:
                acc = str(r["account_id"])
                cp = str(r["counterparty_id"])
                amt = int(r["amount_cents"])
                ts = int(r["ts"])
                acct_recs.setdefault(acc, []).append((ts, amt, cp))
                self.edge_records.append((ts, acc, cp))

            for acc, recs in acct_recs.items():
                tracker = AccountWindowTracker()
                tracker.load_sorted_records(recs)
                self.accounts[acc] = tracker

            if self.edge_records:
                self.max_edge_ts = self.edge_records[-1][0]
                cutoff = self.max_edge_ts - SLIDING_WINDOW_SECONDS
                start_idx = bisect.bisect_left(self.edge_records, (cutoff, "", ""))
                for e_ts, u, v in self.edge_records[start_idx:]:
                    self.edge_queue.append((e_ts, u, v))
                    self._set_edge_ts(u, v, e_ts)

            self.sync_sanctions(db_path)

    def _set_edge_ts(self, u: str, v: str, ts: int) -> None:
        u_map = self.adj_latest_ts.get(u)
        if u_map is None:
            u_map = {}
            self.adj_latest_ts[u] = u_map
        if ts >= u_map.get(v, -1):
            u_map[v] = ts

        v_map = self.adj_latest_ts.get(v)
        if v_map is None:
            v_map = {}
            self.adj_latest_ts[v] = v_map
        if ts >= v_map.get(u, -1):
            v_map[u] = ts

    def _evict_edges_before(self, win_start: int) -> None:
        while self.edge_queue and self.edge_queue[0][0] < win_start:
            old_ts, u, v = self.edge_queue.popleft()
            u_map = self.adj_latest_ts.get(u)
            if u_map is not None and u_map.get(v) == old_ts:
                u_map.pop(v, None)
                if not u_map:
                    self.adj_latest_ts.pop(u, None)
            v_map = self.adj_latest_ts.get(v)
            if v_map is not None and v_map.get(u) == old_ts:
                v_map.pop(u, None)
                if not v_map:
                    self.adj_latest_ts.pop(v, None)

    def compute_hop_and_record_edge(
        self,
        db_path: str,
        account_id: str,
        counterparty_id: str,
        ts: int,
    ) -> int:
        sanctioned = self.sync_sanctions(db_path)
        win_start = ts - SLIDING_WINDOW_SECONDS

        if ts >= self.max_edge_ts:
            self._evict_edges_before(win_start)
            self.edge_records.append((ts, account_id, counterparty_id))
            self.max_edge_ts = ts
            self.edge_queue.append((ts, account_id, counterparty_id))
            self._set_edge_ts(account_id, counterparty_id, ts)

            if not sanctioned:
                return 0
            if account_id in sanctioned or counterparty_id in sanctioned:
                return 1

            # 从交易两端 (account_id, counterparty_id) 出发执行最多 2 层有界 BFS 寻找受制裁实体
            # d_min = 1 => hop = 2; d_min = 2 => hop = 3
            nbrs_1: set[str] = set()
            for ep in (account_id, counterparty_id):
                ep_map = self.adj_latest_ts.get(ep)
                if ep_map:
                    for nb, e_ts in ep_map.items():
                        if win_start <= e_ts <= ts:
                            if nb in sanctioned:
                                return 2
                            nbrs_1.add(nb)

            for nb1 in nbrs_1:
                nb1_map = self.adj_latest_ts.get(nb1)
                if nb1_map:
                    for nb2, e_ts in nb1_map.items():
                        if win_start <= e_ts <= ts and nb2 in sanctioned:
                            return 3
            return 0

        # 乱序时间戳精确回退路径：利用 edge_records 二分切片构建局部 [win_start, ts] 邻接表
        bisect.insort(self.edge_records, (ts, account_id, counterparty_id))
        if ts >= self.max_edge_ts - SLIDING_WINDOW_SECONDS:
            self.edge_queue.append((ts, account_id, counterparty_id))
            self._set_edge_ts(account_id, counterparty_id, ts)

        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1

        lo = bisect.bisect_left(self.edge_records, (win_start, "", ""))
        hi = bisect.bisect_right(self.edge_records, (ts, "\uffff", "\uffff"))
        local_adj: dict[str, set[str]] = {}
        for i in range(lo, hi):
            e_ts, u, v = self.edge_records[i]
            if win_start <= e_ts <= ts:
                local_adj.setdefault(u, set()).add(v)
                local_adj.setdefault(v, set()).add(u)

        nbrs_1_local: set[str] = set()
        for ep in (account_id, counterparty_id):
            for nb in local_adj.get(ep, ()):
                if nb in sanctioned:
                    return 2
                nbrs_1_local.add(nb)
        for nb1 in nbrs_1_local:
            for nb2 in local_adj.get(nb1, ()):
                if nb2 in sanctioned:
                    return 3
        return 0


_TX_ENGINE_GUARD = threading.Lock()
_TX_ENGINES: dict[str, TenantTxEngine] = {}


def get_tenant_tx_engine(db_path: str, tenant_id: str) -> TenantTxEngine:
    db_key = str(pathlib.Path(db_path).resolve())
    key = f"{db_key}::{tenant_id}"
    with _TX_ENGINE_GUARD:
        eng = _TX_ENGINES.get(key)
        if eng is not None:
            return eng
    new_eng = TenantTxEngine(tenant_id)
    new_eng.build_from_db(db_key)
    with _TX_ENGINE_GUARD:
        existing = _TX_ENGINES.get(key)
        if existing is not None:
            return existing
        if len(_TX_ENGINES) > 128:
            _TX_ENGINES.pop(next(iter(_TX_ENGINES)), None)
        _TX_ENGINES[key] = new_eng
        return new_eng


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    eng = get_tenant_tx_engine(db_path, tenant_id)
    with eng.lock:
        sanctioned = eng.sync_sanctions(db_path)
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1

        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect.bisect_left(eng.edge_records, (win_start, "", ""))
        hi = bisect.bisect_right(eng.edge_records, (ts, "\uffff", "\uffff"))
        local_adj: dict[str, set[str]] = {
            account_id: {counterparty_id},
            counterparty_id: {account_id},
        }
        for i in range(lo, hi):
            e_ts, u, v = eng.edge_records[i]
            if win_start <= e_ts <= ts:
                local_adj.setdefault(u, set()).add(v)
                local_adj.setdefault(v, set()).add(u)

        nbrs_1: set[str] = set()
        for ep in (account_id, counterparty_id):
            for nb in local_adj.get(ep, ()):
                if nb in sanctioned:
                    return 2
                nbrs_1.add(nb)
        for nb1 in nbrs_1:
            for nb2 in local_adj.get(nb1, ()):
                if nb2 in sanctioned:
                    return 3
        return 0


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    if not ent or len(ent) > 128:
        raise ValueError("Valid entity_id is required")
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if active else 0
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
            "active = excluded.active, updated_at = excluded.updated_at",
            (caller.tenant_id, ent, str(list_source or "CUSTOM"), act_val, now_ts),
        )
        conn.commit()
    finally:
        conn.close()

    bump_domain_epoch(db_path, caller.tenant_id, "sanction")

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": list_source,
        "active": bool(act_val),
        "updated_at": now_ts,
    }
