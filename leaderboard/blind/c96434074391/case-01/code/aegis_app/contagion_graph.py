# -*- coding: utf-8 -*-
"""三跳受制裁实体动态资金传染图（双向邻域交集搜索、乱序精确回退与批次回滚）及名单管理模块。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import deque
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import SLIDING_WINDOW_SECONDS
from .db import DatabaseRuntime, get_db_runtime
from .middleware import strict_bool


class ContagionBatchUndo:
    """单批次传染图原子回滚记录。"""

    __slots__ = ("monotonic_ops", "full_snapshot")

    def __init__(self) -> None:
        # (prev_max_ts, u, v, popped_front_edges)
        self.monotonic_ops: list[tuple[int, str, str, list[tuple[int, str, str]]]] = []
        self.full_snapshot: tuple[list[int], list[str], list[str]] | None = None


class TenantContagionGraph:
    """租户 24 小时活跃资金关联图（独立 sanctions_epoch + 双向 1 步邻域交集判定三跳传染）。"""

    __slots__ = (
        "tenant_id",
        "sanctions_epoch",
        "sanctioned_set",
        "hist_ts",
        "hist_u",
        "hist_v",
        "max_ts",
        "hot_ready",
        "win_edges",
        "adj_counts",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.sanctions_epoch = 1
        self.sanctioned_set: set[str] = set()
        self.hist_ts: list[int] = []
        self.hist_u: list[str] = []
        self.hist_v: list[str] = []
        self.max_ts = -1
        self.hot_ready = False
        self.win_edges: deque[tuple[int, str, str]] = deque()
        self.adj_counts: dict[str, dict[str, int]] = {}

    def _inc_edge(self, u: str, v: str) -> None:
        if u == v:
            return
        nu = self.adj_counts.get(u)
        if nu is None:
            self.adj_counts[u] = {v: 1}
        else:
            nu[v] = nu.get(v, 0) + 1
        nv = self.adj_counts.get(v)
        if nv is None:
            self.adj_counts[v] = {u: 1}
        else:
            nv[u] = nv.get(u, 0) + 1

    def _dec_edge(self, u: str, v: str) -> None:
        if u == v:
            return
        nu = self.adj_counts.get(u)
        if nu is not None:
            rem = nu.get(v, 0) - 1
            if rem <= 0:
                nu.pop(v, None)
                if not nu:
                    self.adj_counts.pop(u, None)
            else:
                nu[v] = rem
        nv = self.adj_counts.get(v)
        if nv is not None:
            rem = nv.get(u, 0) - 1
            if rem <= 0:
                nv.pop(u, None)
                if not nv:
                    self.adj_counts.pop(v, None)
            else:
                nv[u] = rem

    def rebuild_hot_window(self, anchor_ts: int) -> None:
        self.win_edges.clear()
        self.adj_counts.clear()
        win_start = anchor_ts - SLIDING_WINDOW_SECONDS
        start_idx = bisect_left(self.hist_ts, win_start)
        for idx in range(start_idx, len(self.hist_ts)):
            e_ts = self.hist_ts[idx]
            u = self.hist_u[idx]
            v = self.hist_v[idx]
            self.win_edges.append((e_ts, u, v))
            self._inc_edge(u, v)
        self.hot_ready = True

    @staticmethod
    def _compute_hop_from_adj(
        sanctioned: set[str],
        adj: dict[str, Any],
        account_id: str,
        counterparty_id: str,
    ) -> int:
        if not sanctioned:
            return 0
        if account_id in sanctioned or counterparty_id in sanctioned:
            return 1

        nu = adj.get(account_id)
        nv = adj.get(counterparty_id)
        if not nu and not nv:
            return 0

        len_u = len(nu) if nu else 0
        len_v = len(nv) if nv else 0

        # 第 2 跳判定：account_id 或 counterparty_id 与任一受制裁实体直接相邻（d_min == 1 -> hop = 2）
        if len(sanctioned) <= len_u + len_v:
            for s in sanctioned:
                if (nu and s in nu) or (nv and s in nv):
                    return 2
        else:
            if nu:
                for x in nu:
                    if x in sanctioned:
                        return 2
            if nv:
                for x in nv:
                    if x in sanctioned:
                        return 2

        # 第 3 跳判定（双向 BFS 中间层交集）：端点 1 步邻域与受制裁集合 1 步邻域相交（d_min == 2 -> hop = 3）
        end_1hop: set[str] = set()
        if nu:
            end_1hop.update(nu.keys() if isinstance(nu, dict) else nu)
        if nv:
            end_1hop.update(nv.keys() if isinstance(nv, dict) else nv)
        end_1hop.discard(account_id)
        end_1hop.discard(counterparty_id)
        if not end_1hop:
            return 0

        end_len = len(end_1hop)
        for s in sanctioned:
            ns = adj.get(s)
            if not ns:
                continue
            if len(ns) <= end_len:
                for w in ns:
                    if w in end_1hop:
                        return 3
            else:
                for w in end_1hop:
                    if w in ns:
                        return 3
        return 0

    def query_hop_readonly(self, account_id: str, counterparty_id: str, ts: int) -> int:
        """只读评估单笔交易在 [ts - 86400, ts] 活跃图上的三跳传染等级（不修改持久图状态）。"""
        if not self.sanctioned_set:
            return 0
        if account_id in self.sanctioned_set or counterparty_id in self.sanctioned_set:
            return 1

        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect_left(self.hist_ts, win_start)
        hi = bisect_right(self.hist_ts, ts)
        local_adj: dict[str, set[str]] = {}
        for idx in range(lo, hi):
            u = self.hist_u[idx]
            v = self.hist_v[idx]
            if u != v:
                local_adj.setdefault(u, set()).add(v)
                local_adj.setdefault(v, set()).add(u)
        if account_id != counterparty_id:
            local_adj.setdefault(account_id, set()).add(counterparty_id)
            local_adj.setdefault(counterparty_id, set()).add(account_id)
        return self._compute_hop_from_adj(self.sanctioned_set, local_adj, account_id, counterparty_id)

    def evaluate_and_record(
        self,
        account_id: str,
        counterparty_id: str,
        ts: int,
        undo: ContagionBatchUndo,
    ) -> int:
        """评估当前笔的三跳制裁传染跳数，并将该笔边实时并入窗口图（支持乱序与原子回滚）。"""
        if undo.full_snapshot is not None or ts < self.max_ts:
            if undo.full_snapshot is None:
                if undo.monotonic_ops:
                    replayed: list[tuple[int, str, str]] = []
                    for prev_max, u_p, v_p, popped in reversed(undo.monotonic_ops):
                        e_t, _, _ = self.win_edges.pop()
                        replayed.append((e_t, u_p, v_p))
                        self._dec_edge(u_p, v_p)
                        self.hist_ts.pop()
                        self.hist_u.pop()
                        self.hist_v.pop()
                        for pt, pu, pv in reversed(popped):
                            self.win_edges.appendleft((pt, pu, pv))
                            self._inc_edge(pu, pv)
                        self.max_ts = prev_max
                    undo.monotonic_ops.clear()
                    undo.full_snapshot = (list(self.hist_ts), list(self.hist_u), list(self.hist_v))
                    for rt_t, rt_u, rt_v in reversed(replayed):
                        pos = bisect_right(self.hist_ts, rt_t)
                        self.hist_ts.insert(pos, rt_t)
                        self.hist_u.insert(pos, rt_u)
                        self.hist_v.insert(pos, rt_v)
                        if rt_t > self.max_ts:
                            self.max_ts = rt_t
                    self.hot_ready = False
                else:
                    undo.full_snapshot = (list(self.hist_ts), list(self.hist_u), list(self.hist_v))

            hop = self.query_hop_readonly(account_id, counterparty_id, ts)
            ins = bisect_right(self.hist_ts, ts)
            self.hist_ts.insert(ins, ts)
            self.hist_u.insert(ins, account_id)
            self.hist_v.insert(ins, counterparty_id)
            if ts > self.max_ts:
                self.max_ts = ts
            self.hot_ready = False
            return hop

        # 单调热路径
        if not self.hot_ready:
            self.rebuild_hot_window(ts)

        prev_max = self.max_ts
        win_start = ts - SLIDING_WINDOW_SECONDS
        popped_edges: list[tuple[int, str, str]] = []
        dq = self.win_edges
        while dq and dq[0][0] < win_start:
            old_ts, old_u, old_v = dq.popleft()
            popped_edges.append((old_ts, old_u, old_v))
            self._dec_edge(old_u, old_v)

        dq.append((ts, account_id, counterparty_id))
        self._inc_edge(account_id, counterparty_id)
        self.hist_ts.append(ts)
        self.hist_u.append(account_id)
        self.hist_v.append(counterparty_id)
        self.max_ts = ts

        undo.monotonic_ops.append((prev_max, account_id, counterparty_id, popped_edges))
        return self._compute_hop_from_adj(self.sanctioned_set, self.adj_counts, account_id, counterparty_id)

    def rollback(self, undo: ContagionBatchUndo) -> None:
        """将内存三跳传染图 100% 原子回退至批处理开始前的状态。"""
        for prev_max, u_p, v_p, popped in reversed(undo.monotonic_ops):
            self.win_edges.pop()
            self._dec_edge(u_p, v_p)
            self.hist_ts.pop()
            self.hist_u.pop()
            self.hist_v.pop()
            for pt, pu, pv in reversed(popped):
                self.win_edges.appendleft((pt, pu, pv))
                self._inc_edge(pu, pv)
            self.max_ts = prev_max

        if undo.full_snapshot is not None:
            self.hist_ts, self.hist_u, self.hist_v = undo.full_snapshot
            self.max_ts = self.hist_ts[-1] if self.hist_ts else -1
            self.hot_ready = False
            self.win_edges.clear()
            self.adj_counts.clear()


def _load_tenant_contagion_graph(rt: DatabaseRuntime, tenant_id: str) -> TenantContagionGraph:
    graph = TenantContagionGraph(tenant_id)
    with rt.read_conn() as conn:
        s_rows = conn.execute(
            "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        graph.sanctioned_set = {str(r["entity_id"]) for r in s_rows}

        cur = conn.execute(
            "SELECT account_id, counterparty_id, ts FROM transactions WHERE tenant_id = ? ORDER BY ts ASC",
            (tenant_id,),
        )
        while True:
            rows = cur.fetchmany(1024)
            if not rows:
                break
            for r in rows:
                t_val = int(r["ts"])
                graph.hist_ts.append(t_val)
                graph.hist_u.append(str(r["account_id"]))
                graph.hist_v.append(str(r["counterparty_id"]))
                if t_val > graph.max_ts:
                    graph.max_ts = t_val
    return graph


def get_tenant_contagion_graph(rt: DatabaseRuntime, tenant_id: str) -> TenantContagionGraph:
    cached = rt.contagion_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.tenant_meta_lock(tenant_id):
        cached = rt.contagion_cache.get(tenant_id)
        if cached is not None:
            return cached
        loaded = _load_tenant_contagion_graph(rt, tenant_id)
        rt.contagion_cache.set(tenant_id, loaded)
        return loaded


def compute_sanction_contagion_hop(
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级。"""
    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(tenant_id):
        graph = get_tenant_contagion_graph(rt, tenant_id)
        return graph.query_hop_readonly(account_id, counterparty_id, int(ts))


def manage_sanctioned_entity(
    db_path: str,
    caller: CallerContext,
    *,
    entity_id: str,
    list_source: str = "OFAC_SDN",
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员实时新增、激活或停用租户受制裁黑名单实体（局部更新 sanctions_epoch）。"""
    require_admin(caller)
    act_bool = strict_bool(active, "active")
    if not isinstance(entity_id, str) or not entity_id.strip() or len(entity_id.strip()) > 128:
        raise ValueError("Valid entity_id is required")
    if not isinstance(list_source, str) or len(list_source.strip()) > 64:
        raise ValueError("Invalid list_source")
    ent = entity_id.strip()
    src_name = list_source.strip() or "CUSTOM"
    now_ts = int(caller.request_ts or int(time.time()))
    act_val = 1 if act_bool else 0

    rt = get_db_runtime(db_path)
    with rt.acquire_risk_lock(caller.tenant_id):
        with rt.tenant_meta_lock(caller.tenant_id):
            with rt.write_tx() as conn:
                conn.execute(
                    "INSERT INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant_id, entity_id) DO UPDATE SET list_source = excluded.list_source, "
                    "active = excluded.active, updated_at = excluded.updated_at",
                    (caller.tenant_id, ent, src_name, act_val, now_ts),
                )
            graph = rt.contagion_cache.get(caller.tenant_id)
            if graph is not None:
                if act_bool:
                    graph.sanctioned_set.add(ent)
                else:
                    graph.sanctioned_set.discard(ent)
                graph.sanctions_epoch += 1

    return {
        "tenant_id": caller.tenant_id,
        "entity_id": ent,
        "list_source": src_name,
        "active": act_bool,
        "updated_at": now_ts,
    }
