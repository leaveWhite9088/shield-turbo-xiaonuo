# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。"""
from __future__ import annotations

from collections import deque
import time
from typing import Any

from .acl_wall import get_org_cache
from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .middleware import parse_strict_int
from .runtime import GatewayRuntime, get_runtime


class TenantPermState:
    """租户内原生角色与借调关系图内存快照（与 perm_epoch 绑定，完全解耦 doc/acl 纪元）。"""

    __slots__ = (
        "active_users",
        "user_base_org_roles",
        "user_explicit_grants",
        "delegations_by_grantee",
    )

    def __init__(self) -> None:
        self.active_users: set[str] = set()
        self.user_base_org_roles: dict[str, frozenset[str]] = {}
        self.user_explicit_grants: dict[str, set[str]] = {}
        # grantee_uid -> list[(grantor_uid, role_name, starts_at, expires_at)]
        self.delegations_by_grantee: dict[str, list[tuple[str, str, int, int]]] = {}

    @classmethod
    def load(cls, rt: GatewayRuntime, tenant_id: str) -> "TenantPermState":
        state = cls()
        org_cache = get_org_cache(rt.db_path, tenant_id)
        with rt.read_conn() as conn:
            u_rows = conn.execute(
                "SELECT user_id, org_node_id, base_role, active FROM users WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            g_rows = conn.execute(
                "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
            d_rows = conn.execute(
                "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
                "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()

        for r in u_rows:
            if int(r["active"]) != 1:
                continue
            uid = str(r["user_id"])
            state.active_users.add(uid)
            base_roles = set(org_cache.get_inherited_roles(str(r["org_node_id"])))
            base_roles.add(str(r["base_role"]))
            state.user_base_org_roles[uid] = frozenset(base_roles)

        for gr in g_rows:
            uid = str(gr["user_id"])
            state.user_explicit_grants.setdefault(uid, set()).add(str(gr["granted_role"]))

        for dr in d_rows:
            grantee = str(dr["grantee_user_id"])
            state.delegations_by_grantee.setdefault(grantee, []).append(
                (
                    str(dr["grantor_user_id"]),
                    str(dr["delegated_role"]),
                    int(dr["starts_at"]),
                    int(dr["expires_at"]),
                )
            )
        return state

    def native_roles(self, user_id: str) -> set[str]:
        if user_id not in self.active_users:
            return set()
        base = self.user_base_org_roles.get(user_id, frozenset())
        explicit = self.user_explicit_grants.get(user_id)
        if explicit:
            return set(base) | explicit
        return set(base)

    def has_native_role(self, user_id: str, role_name: str) -> bool:
        if user_id not in self.active_users:
            return False
        if role_name in self.user_base_org_roles.get(user_id, frozenset()):
            return True
        explicit = self.user_explicit_grants.get(user_id)
        return bool(explicit and role_name in explicit)

    def active_delegated_roles(self, grantee_user_id: str, at_ts: int) -> set[str]:
        """在指定时刻 at_ts 实时核验 1~MAX_DELEGATION_HOPS(2) 跳借调角色。

        特性：
        - 逐段实时核验 starts_at <= at_ts < expires_at（上游窗口到期零写自动降级）；
        - 必须追溯到当前活跃且仍持有该原生角色的源头委托人（源头撤权瞬间级联失效）；
        - 使用路径 visited 与深度上限 MAX_DELEGATION_HOPS 彻底免疫任意有向环路。
        """
        if grantee_user_id not in self.active_users:
            return set()
        direct_edges = self.delegations_by_grantee.get(grantee_user_id)
        if not direct_edges:
            return set()

        effective: set[str] = set()
        # 第一跳候选：按角色收集有效直接委托人
        hop1_by_role: dict[str, set[str]] = {}
        for grantor_uid, role_name, s_ts, e_ts in direct_edges:
            if not (s_ts <= at_ts < e_ts):
                continue
            if grantor_uid == grantee_user_id or grantor_uid not in self.active_users:
                continue
            if role_name in effective:
                continue
            if self.has_native_role(grantor_uid, role_name):
                effective.add(role_name)
                continue
            hop1_by_role.setdefault(role_name, set()).add(grantor_uid)

        if MAX_DELEGATION_HOPS < 2 or not hop1_by_role:
            return effective

        # 第二跳核验（及通用深度 <= MAX_DELEGATION_HOPS 受限 BFS）
        for role_name, hop1_grantors in hop1_by_role.items():
            if role_name in effective:
                continue
            # BFS 状态：(当前节点, 跳数, 路径访问集合)
            found = False
            q: deque[tuple[str, int, frozenset[str]]] = deque()
            for g1 in hop1_grantors:
                q.append((g1, 1, frozenset((grantee_user_id, g1))))
            while q and not found:
                curr, hop, path_visited = q.popleft()
                if hop >= MAX_DELEGATION_HOPS:
                    continue
                up_edges = self.delegations_by_grantee.get(curr)
                if not up_edges:
                    continue
                for up_grantor, up_role, s_ts, e_ts in up_edges:
                    if up_role != role_name or not (s_ts <= at_ts < e_ts):
                        continue
                    if up_grantor in path_visited or up_grantor not in self.active_users:
                        continue
                    if self.has_native_role(up_grantor, role_name):
                        effective.add(role_name)
                        found = True
                        break
                    if hop + 1 < MAX_DELEGATION_HOPS:
                        q.append((up_grantor, hop + 1, path_visited | {up_grantor}))
        return effective

    def has_active_hop1_delegation(self, user_id: str, role_name: str, at_ts: int) -> bool:
        """检查 user_id 在 at_ts 时刻是否直接从原生持有人获得了该角色的一级借调（用于二级转借调资格审核）。"""
        if user_id not in self.active_users:
            return False
        for grantor_uid, r_name, s_ts, e_ts in self.delegations_by_grantee.get(user_id, ()):
            if r_name != role_name or not (s_ts <= at_ts < e_ts):
                continue
            if grantor_uid == user_id or grantor_uid not in self.active_users:
                continue
            if self.has_native_role(grantor_uid, role_name):
                return True
        return False

    def would_create_cycle(self, grantor_user_id: str, grantee_user_id: str, role_name: str) -> bool:
        """检测添加有向边 grantor -> grantee（针对同角色）是否会形成任意长度的有向环路。"""
        if grantor_user_id == grantee_user_id:
            return True
        # 从 grantor 沿现有活跃入边反向遍历，若能到达 grantee 则加边必然成环
        visited: set[str] = {grantor_user_id}
        stack: list[str] = [grantor_user_id]
        while stack:
            curr = stack.pop()
            for up_grantor, up_role, _, _ in self.delegations_by_grantee.get(curr, ()):
                if up_role != role_name:
                    continue
                if up_grantor == grantee_user_id:
                    return True
                if up_grantor not in visited:
                    visited.add(up_grantor)
                    stack.append(up_grantor)
        return False


def get_perm_state(db_path: str, tenant_id: str) -> TenantPermState:
    rt = get_runtime(db_path)
    state = rt.perm_states.get(tenant_id)
    if state is not None:
        return state
    with rt.perm_lock(tenant_id):
        state = rt.perm_states.get(tenant_id)
        if state is None:
            state = TenantPermState.load(rt, tenant_id)
            rt.perm_states[tenant_id] = state
        return state


def update_user_role_grant_cache(
    db_path: str,
    tenant_id: str,
    user_id: str,
    role_name: str,
    *,
    granted: bool,
) -> None:
    """增量更新内存角色授予状态并递增 perm_epoch，确保下游借调瞬间级联失效。"""
    rt = get_runtime(db_path)
    with rt.perm_lock(tenant_id):
        state = rt.perm_states.get(tenant_id)
        if state is not None:
            if granted:
                state.user_explicit_grants.setdefault(user_id, set()).add(role_name)
            else:
                gset = state.user_explicit_grants.get(user_id)
                if gset is not None:
                    gset.discard(role_name)
        rt.epochs(tenant_id).perm_epoch += 1


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    rt = get_runtime(db_path)
    with rt.perm_lock(tenant_id):
        state = get_perm_state(db_path, tenant_id)
        return state.native_roles(user_id)


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。"""
    rt = get_runtime(db_path)
    with rt.perm_lock(tenant_id):
        state = get_perm_state(db_path, tenant_id)
        return state.active_delegated_roles(grantee_user_id, int(at_ts))


def create_or_revoke_delegation(
    db_path: str,
    tenant_id: str,
    actor_user_id: str,
    actor_roles: set[str],
    *,
    grantor_user_id: str,
    grantee_user_id: str,
    delegated_role: str,
    starts_at: int,
    expires_at: int,
    action: str = "create",
    now_ts: int | None = None,
) -> dict[str, Any]:
    """创建或撤销跨部门角色借调委托（支持原生持有人发起一级借调，或有效一级受托人发起二级转借调，严防有向环路）。"""
    norm_grantor = str(grantor_user_id or "").strip()
    norm_grantee = str(grantee_user_id or "").strip()
    norm_role = str(delegated_role or "").strip()
    norm_action = str(action or "create").strip().lower()

    if norm_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {norm_role}")
    if actor_user_id != norm_grantor and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if not norm_grantor or not norm_grantee:
        raise ValueError("grantor_user_id and grantee_user_id are required")
    if norm_grantor == norm_grantee:
        raise ValueError("Cannot delegate role to self")

    eval_ts = parse_strict_int(
        now_ts if now_ts is not None else int(time.time()),
        "now_ts",
        min_val=0,
    )
    s_ts = parse_strict_int(starts_at, "starts_at")
    e_ts = parse_strict_int(expires_at, "expires_at")

    rt = get_runtime(db_path)
    with rt.perm_lock(tenant_id):
        state = get_perm_state(db_path, tenant_id)
        if norm_grantor not in state.active_users or norm_grantee not in state.active_users:
            raise LookupError("Grantor or grantee not found in tenant")

        if norm_action == "create":
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")
            if state.would_create_cycle(norm_grantor, norm_grantee, norm_role):
                raise ValueError("Delegation cycle detected and rejected")

            can_delegate = state.has_native_role(norm_grantor, norm_role)
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                can_delegate = state.has_active_hop1_delegation(norm_grantor, norm_role, eval_ts)
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            with rt.write_tx() as conn:
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, norm_grantor, norm_grantee, norm_role, s_ts, e_ts, eval_ts),
                )
            state.delegations_by_grantee.setdefault(norm_grantee, []).append(
                (norm_grantor, norm_role, s_ts, e_ts)
            )
            affected = 1
        elif norm_action == "revoke":
            with rt.write_tx() as conn:
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, norm_grantor, norm_grantee, norm_role),
                )
                affected = cur.rowcount
            edges = state.delegations_by_grantee.get(norm_grantee)
            if edges:
                new_edges = [
                    e for e in edges if not (e[0] == norm_grantor and e[1] == norm_role)
                ]
                if new_edges:
                    state.delegations_by_grantee[norm_grantee] = new_edges
                else:
                    state.delegations_by_grantee.pop(norm_grantee, None)
        else:
            raise ValueError("action must be 'create' or 'revoke'")

        rt.epochs(tenant_id).perm_epoch += 1

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": norm_grantor,
        "grantee_user_id": norm_grantee,
        "delegated_role": norm_role,
        "action": norm_action,
        "affected": affected,
    }
