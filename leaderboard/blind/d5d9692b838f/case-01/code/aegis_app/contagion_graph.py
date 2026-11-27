# -*- coding: utf-8 -*-
"""三跳受制裁黑名单实体动态滑窗传染图谱（双向前沿剪枝 O(min_deg) + 乱序定位 + 原子回滚）与名单管理模块。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import borrow_connection, get_db_hub, write_transaction
from .middleware import strict_bool
from .window_stats import AccountWindowTracker


class SanctionSetSnapshot:
    __slots__ = ("epoch", "entities")

    def __init__(self, epoch: int, entities: frozenset[str]) -> None:
        self.epoch = epoch
        self.entities = entities


class TenantContagionGraph:
    """维护租户 24h 活跃无向交易关联图的增量滑窗邻接表（支持乱序时间戳与逆序原子回滚）。"""

    __slots__ = ("ts_list", "u_list", "v_list", "left", "right", "adj")

    def __init__(self) -> None:
        self.ts_list: list[int] = []
        self.u_list: list[str] = []
        self.v_list: list[str] = []
        self.left = 0
        self.right = 0
        self.adj: dict[str, dict[str, int]] = {}

    def load_sorted_initial(self, edges: list[tuple[int, str, str]]) -> None:
        for ts, u, v in edges:
            self.ts_list.append(ts)
            self.u_list.append(u)
            self.v_list.append(v)

    def _add_edge(self, u: str, v: str) -> None:
        if u == v:
            nu = self.adj.setdefault(u, {})
            nu[u] = nu.get(u, 0) + 1
            return
        nu = self.adj.setdefault(u, {})
        nu[v] = nu.get(v, 0) + 1
        nv = self.adj.setdefault(v, {})
        nv[u] = nv.get(u, 0) + 1

    def _rem_edge(self, u: str, v: str) -> None:
        if u == v:
            nu = self.adj.get(u)
            if nu is not None:
                cnt = nu.get(u, 0)
                if cnt <= 1:
                    nu.pop(u, None)
                    if not nu:
                        self.adj.pop(u, None)
                else:
                    nu[u] = cnt - 1
            return

        nu = self.adj.get(u)
        if nu is not None:
            cnt = nu.get(v, 0)
            if cnt <= 1:
                nu.pop(v, None)
                if not nu:
                    self.adj.pop(u, None)
            else:
                nu[v] = cnt - 1

        nv = self.adj.get(v)
        if nv is not None:
            cnt = nv.get(u, 0)
            if cnt <= 1:
                nv.pop(u, None)
                if not nv:
                    self.adj.pop(v, None)
            else:
                nv[u] = cnt - 1

    def reposition(self, win_start: int, win_end: int) -> None:
        ts_arr = self.ts_list
        if not ts_arr:
            return
        t_left = bisect_left(ts_arr, win_start)
        t_right = bisect_right(ts_arr, win_end)

        cur_l = self.left
        cur_r = self.right
        us = self.u_list
        vs = self.v_list

        if cur_l == cur_r or t_left == t_right or max(cur_l, t_left) >= min(cur_r, t_right):
            self.adj.clear()
            self.left = t_left
            self.right = t_right
            for idx in range(t_left, t_right):
                self._add_edge(us[idx], vs[idx])
            return

        if t_right > cur_r:
            for idx in range(cur_r, t_right):
                self._add_edge(us[idx], vs[idx])
        elif t_right < cur_r:
            for idx in range(t_right, cur_r):
                self._rem_edge(us[idx], vs[idx])
        self.right = t_right

        if t_left > cur_l:
            for idx in range(cur_l, t_left):
                self._rem_edge(us[idx], vs[idx])
        elif t_left < cur_l:
            for idx in range(t_left, cur_l):
                self._add_edge(us[idx], vs[idx])
        self.left = t_left

    def query_hop(self, account_id: str, counterparty_id: str, sanctioned: frozenset[str]) -> int:
        """双向前沿折半（Meet-in-the-Middle）计算 1..3 跳最短传染距离，免疫星型超级节点退化。"""
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1

        adj = self.adj
        nu = adj.get(account_id)
        nv = adj.get(counterparty_id)
        if not nu and not nv:
            return 0

        # 第 2 跳判定（d_min == 1）：检查 u 或 v 的直接邻居中是否包含受制裁实体
        len_s = len(sanctioned)
        if nu:
            if len(nu) <= len_s:
                for nb in nu:
                    if nb in sanctioned:
                        return 2
            else:
                for s in sanctioned:
                    if s in nu:
                        return 2
        if nv:
            if len(nv) <= len_s:
                for nb in nv:
                    if nb in sanctioned:
                        return 2
            else:
                for s in sanctioned:
                    if s in nv:
                        return 2

        # 第 3 跳判定（d_min == 2）：比较 {u, v} 邻域规模与 S 邻域规模，始终展开更小一侧
        deg_uv = (len(nu) if nu else 0) + (len(nv) if nv else 0)
        deg_s = 0
        for s in sanctioned:
            ns = adj.get(s)
            if ns:
                deg_s += len(ns)
                if deg_s > deg_uv:
                    break

        if deg_s == 0:
            return 0

        if deg_s <= deg_uv:
            for s in sanctioned:
                ns = adj.get(s)
                if not ns:
                    continue
                for mid in ns:
                    if (nu and mid in nu) or (nv and mid in nv):
                        return 3
        else:
            seen_mid: set[str] = set()
            for nb_map in (nu, nv):
                if not nb_map:
                    continue
                for mid in nb_map:
                    if mid in seen_mid:
                        continue
                    seen_mid.add(mid)
                    nmid = adj.get(mid)
                    if not nmid:
                        continue
                    if len(nmid) <= len_s:
                        for target in nmid:
                            if target in sanctioned:
                                return 3
                    else:
                        for s in sanctioned:
                            if s in nmid:
                                return 3
        return 0

    def insert_and_query(
        self,
        ts: int,
        account_id: str,
        counterparty_id: str,
        sanctioned: frozenset[str],
        window_seconds: int,
    ) -> tuple[int, int]:
        self.reposition(ts - window_seconds, ts)
        ins_pos = self.right
        if ins_pos == len(self.ts_list):
            self.ts_list.append(ts)
            self.u_list.append(account_id)
            self.v_list.append(counterparty_id)
        else:
            self.ts_list.insert(ins_pos, ts)
            self.u_list.insert(ins_pos, account_id)
            self.v_list.insert(ins_pos, counterparty_id)

        self.right += 1
        self._add_edge(account_id, counterparty_id)
        hop = self.query_hop(account_id, counterparty_id, sanctioned)
        return ins_pos, hop

    def undo_insert(self, ins_pos: int) -> None:
        u = self.u_list[ins_pos]
        v = self.v_list[ins_pos]
        if self.left <= ins_pos < self.right:
            self._rem_edge(u, v)
            self.right -= 1
        elif ins_pos < self.left:
            self.left -= 1
            self.right -= 1
        self.ts_list.pop(ins_pos)
        self.u_list.pop(ins_pos)
        self.v_list.pop(ins_pos)


class TenantRiskRuntimeState:
    """聚合单租户账户滑窗集合与动态三跳传染图（由 Layer 1 tenant_risk_lock 保护）。"""

    __slots__ = ("accounts", "graph")

    def __init__(self) -> None:
        self.accounts: dict[str, AccountWindowTracker] = {}
        self.graph = TenantContagionGraph()


def get_sanctioned_set(db_path: str, tenant_id: str) -> frozenset[str]:
    hub = get_db_hub(db_path)
    target_ep = hub.get_epochs(tenant_id).sanction_epoch
    cached: SanctionSetSnapshot | None = hub.sanction_snapshots.get(tenant_id)
    if cached is not None and cached.epoch == target_ep:
        return cached.entities

    with hub.tenant_meta_lock(tenant_id):
        target_ep = hub.get_epochs(tenant_id).sanction_epoch
        cached = hub.sanction_snapshots.get(tenant_id)
        if cached is not None and cached.epoch == target_ep:
            return cached.entities

        with borrow_connection(db_path) as conn:
            rows = conn.execute(
                "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
        entities = frozenset(str(r["entity_id"]) for r in rows)
        hub.sanction_snapshots.set(tenant_id, SanctionSetSnapshot(target_ep, entities))
        return entities


def get_tenant_risk_state(db_path: str, tenant_id: str) -> TenantRiskRuntimeState:
    """获取或按时间升序一次性流式构建租户内存滑窗与传染图状态（调用方须已持 tenant_risk_lock）。"""
    hub = get_db_hub(db_path)
    state: TenantRiskRuntimeState | None = hub.risk_states.get(tenant_id)
    if state is not None:
        return state

    state = TenantRiskRuntimeState()
    acct_buffers: dict[str, list[tuple[int, int, str]]] = {}
    graph_edges: list[tuple[int, str, str]] = []

    with borrow_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT account_id, counterparty_id, amount_cents, ts "
            "FROM transactions WHERE tenant_id = ? ORDER BY ts ASC",
            (tenant_id,),
        )
        while True:
            batch = cur.fetchmany(512)
            if not batch:
                break
            for r in batch:
                acct = str(r["account_id"])
                cp = str(r["counterparty_id"])
                amt = int(r["amount_cents"])
                ts = int(r["ts"])
                acct_buffers.setdefault(acct, []).append((ts, amt, cp))
                graph_edges.append((ts, acct, cp))

    for acct, rows in acct_buffers.items():
        tracker = AccountWindowTracker()
        tracker.load_sorted_initial(rows)
        state.accounts[acct] = tracker
    state.graph.load_sorted_initial(graph_edges)

    hub.risk_states.set(tenant_id, state)
    return state


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
    sanctioned = get_sanctioned_set(db_path, tenant_id)
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    hub = get_db_hub(db_path)
    with hub.tenant_risk_lock(tenant_id):
        state = get_tenant_risk_state(db_path, tenant_id)
        state.graph.reposition(int(ts) - SLIDING_WINDOW_SECONDS, int(ts))
        return state.graph.query_hop(account_id, counterparty_id, sanctioned)


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单（递增 sanction_epoch 即时生效）。"""
    require_admin(caller)
    ent = str(entity_id or "").strip()
    src = str(list_source or "CUSTOM").strip() or "CUSTOM"
    if not ent or len(ent) > 128 or len(src) > 128:
        raise ValueError("Valid entity_id and list_source are required")
    act_bool = strict_bool(active, "active")
    act_val = 1 if act_bool else 0
    now_ts = int(caller.request_ts or int(time.time()))

    hub = get_db_hub(db_path)
    with hub.tenant_meta_lock(caller.tenant_id):
        with write_transaction(db_path) as conn:
            conn.execute(
                "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                "active = excluded.active, updated_at = excluded.updated_at",
                (caller.tenant_id, ent, src, act_val, now_ts),
            )
        hub.bump_sanction_epoch(caller.tenant_id)

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": src,
        "active": act_bool,
        "updated_at": now_ts,
    }
