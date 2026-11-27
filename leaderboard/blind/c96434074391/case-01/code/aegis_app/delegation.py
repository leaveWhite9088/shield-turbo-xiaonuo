# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（最多二级受控转借调）、防环路图核验与独立权限纪元模块。"""
from __future__ import annotations

from collections import deque
import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import DatabaseRuntime, get_db_runtime
from .middleware import strict_int


class UserRecord:
    __slots__ = ("user_id", "username", "org_node_id", "base_role", "api_token_hash", "active")

    def __init__(
        self,
        user_id: str,
        username: str,
        org_node_id: str,
        base_role: str,
        api_token_hash: str,
        active: bool,
    ) -> None:
        self.user_id = user_id
        self.username = username
        self.org_node_id = org_node_id
        self.base_role = base_role
        self.api_token_hash = api_token_hash
        self.active = active


class DelegationEdge:
    __slots__ = ("grantor_id", "grantee_id", "role", "starts_at", "expires_at")

    def __init__(
        self,
        grantor_id: str,
        grantee_id: str,
        role: str,
        starts_at: int,
        expires_at: int,
    ) -> None:
        self.grantor_id = grantor_id
        self.grantee_id = grantee_id
        self.role = role
        self.starts_at = starts_at
        self.expires_at = expires_at


class TenantAuthState:
    """租户身份、组织继承链、显式角色与借调有向图快照（独立 auth_epoch）。"""

    __slots__ = (
        "tenant_id",
        "status",
        "webhook_secret",
        "auth_epoch",
        "users",
        "org_lineage",
        "org_inherited_roles",
        "explicit_grants",
        "delegations_by_grantee",
        "delegations_by_grantor",
    )

    def __init__(self, tenant_id: str, status: str, webhook_secret: str) -> None:
        self.tenant_id = tenant_id
        self.status = status
        self.webhook_secret = webhook_secret
        self.auth_epoch = 1
        self.users: dict[str, UserRecord] = {}
        self.org_lineage: dict[str, tuple[str, ...]] = {}
        self.org_inherited_roles: dict[str, frozenset[str]] = {}
        self.explicit_grants: dict[str, set[str]] = {}
        self.delegations_by_grantee: dict[str, list[DelegationEdge]] = {}
        self.delegations_by_grantor: dict[str, list[DelegationEdge]] = {}

    def native_roles_of(self, user_id: str) -> set[str]:
        u = self.users.get(user_id)
        if u is None or not u.active:
            return set()
        roles: set[str] = {u.base_role}
        inh = self.org_inherited_roles.get(u.org_node_id)
        if inh:
            roles.update(inh)
        exp = self.explicit_grants.get(user_id)
        if exp:
            roles.update(exp)
        return roles

    def add_delegation_edge(self, edge: DelegationEdge) -> None:
        self.delegations_by_grantee.setdefault(edge.grantee_id, []).append(edge)
        self.delegations_by_grantor.setdefault(edge.grantor_id, []).append(edge)

    def remove_delegation_edges(self, grantor_id: str, grantee_id: str, role: str) -> None:
        g_list = self.delegations_by_grantee.get(grantee_id)
        if g_list:
            self.delegations_by_grantee[grantee_id] = [
                e for e in g_list if not (e.grantor_id == grantor_id and e.role == role)
            ]
        r_list = self.delegations_by_grantor.get(grantor_id)
        if r_list:
            self.delegations_by_grantor[grantor_id] = [
                e for e in r_list if not (e.grantee_id == grantee_id and e.role == role)
            ]


def _load_tenant_auth_state(rt: DatabaseRuntime, tenant_id: str) -> TenantAuthState | None:
    with rt.read_conn() as conn:
        t_row = conn.execute(
            "SELECT tenant_id, status, webhook_secret FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if not t_row:
            return None

        state = TenantAuthState(
            tenant_id=str(t_row["tenant_id"]),
            status=str(t_row["status"]),
            webhook_secret=str(t_row["webhook_secret"]),
        )

        node_rows = conn.execute(
            "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        parent_map: dict[str, str | None] = {}
        role_map: dict[str, str | None] = {}
        for nr in node_rows:
            nid = str(nr["node_id"])
            parent_map[nid] = str(nr["parent_node_id"]) if nr["parent_node_id"] else None
            role_map[nid] = str(nr["inherited_role"]) if nr["inherited_role"] else None

        for nid in parent_map:
            lineage: list[str] = []
            inh_roles: set[str] = set()
            curr: str | None = nid
            visited: set[str] = set()
            while curr and curr not in visited and curr in parent_map:
                visited.add(curr)
                lineage.append(curr)
                r_val = role_map.get(curr)
                if r_val:
                    inh_roles.add(r_val)
                curr = parent_map.get(curr)
            state.org_lineage[nid] = tuple(lineage)
            state.org_inherited_roles[nid] = frozenset(inh_roles)

        u_rows = conn.execute(
            "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
            "FROM users WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        for ur in u_rows:
            uid = str(ur["user_id"])
            state.users[uid] = UserRecord(
                user_id=uid,
                username=str(ur["username"]),
                org_node_id=str(ur["org_node_id"]),
                base_role=str(ur["base_role"]),
                api_token_hash=str(ur["api_token_hash"]),
                active=bool(int(ur["active"])),
            )

        g_rows = conn.execute(
            "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        for gr in g_rows:
            state.explicit_grants.setdefault(str(gr["user_id"]), set()).add(str(gr["granted_role"]))

        d_rows = conn.execute(
            "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
            "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        for dr in d_rows:
            state.add_delegation_edge(
                DelegationEdge(
                    grantor_id=str(dr["grantor_user_id"]),
                    grantee_id=str(dr["grantee_user_id"]),
                    role=str(dr["delegated_role"]),
                    starts_at=int(dr["starts_at"]),
                    expires_at=int(dr["expires_at"]),
                )
            )
    return state


def get_tenant_auth_state(rt: DatabaseRuntime, tenant_id: str) -> TenantAuthState | None:
    if not tenant_id or len(tenant_id) > 128:
        return None
    cached = rt.auth_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.tenant_meta_lock(tenant_id):
        cached = rt.auth_cache.get(tenant_id)
        if cached is not None:
            return cached
        loaded = _load_tenant_auth_state(rt, tenant_id)
        if loaded is not None:
            rt.auth_cache.set(tenant_id, loaded)
        return loaded


def resolve_delegated_roles_in_memory(
    state: TenantAuthState,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """在内存借调有向图上核验 1~2 跳受控时效借调资格（O(deg) 环路免疫、上游到期零写自动降级）。"""
    u_self = state.users.get(grantee_user_id)
    if u_self is None or not u_self.active:
        return set()

    hop1_edges = state.delegations_by_grantee.get(grantee_user_id)
    if not hop1_edges:
        return set()

    effective: set[str] = set()
    for e1 in hop1_edges:
        role = e1.role
        if role in effective:
            continue
        if not (e1.starts_at <= at_ts < e1.expires_at):
            continue
        mid_uid = e1.grantor_id
        if mid_uid == grantee_user_id:
            continue
        mid_user = state.users.get(mid_uid)
        if mid_user is None or not mid_user.active:
            continue

        # 1 跳直接核验：直接委托人持有原生角色
        if role in state.native_roles_of(mid_uid):
            effective.add(role)
            continue

        # 2 跳转借调核验：中间受托人在同一时刻从持有原生角色的源头获得有效 1 跳委托
        if MAX_DELEGATION_HOPS >= 2:
            hop2_edges = state.delegations_by_grantee.get(mid_uid)
            if not hop2_edges:
                continue
            for e2 in hop2_edges:
                if e2.role != role or not (e2.starts_at <= at_ts < e2.expires_at):
                    continue
                src_uid = e2.grantor_id
                if src_uid == mid_uid or src_uid == grantee_user_id:
                    continue
                if role in state.native_roles_of(src_uid):
                    effective.add(role)
                    break

    return effective


def _has_active_delegation_path(
    state: TenantAuthState,
    start_uid: str,
    target_uid: str,
    role: str,
    ref_ts: int,
) -> bool:
    """用受限 BFS 检测在同角色未过期活跃委托图中从 start_uid 是否可达 target_uid（阻断有向环路）。"""
    if start_uid == target_uid:
        return True
    visited: set[str] = {start_uid}
    queue: deque[str] = deque([start_uid])
    while queue:
        curr = queue.popleft()
        for edge in state.delegations_by_grantor.get(curr, ()):
            if edge.role != role or edge.expires_at <= ref_ts:
                continue
            nxt = edge.grantee_id
            if nxt == target_uid:
                return True
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予拥有的原生角色集合。"""
    rt = get_db_runtime(db_path)
    state = get_tenant_auth_state(rt, tenant_id)
    if state is None:
        return set()
    return state.native_roles_of(user_id)


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多 MAX_DELEGATION_HOPS=2 跳）。"""
    rt = get_db_runtime(db_path)
    state = get_tenant_auth_state(rt, tenant_id)
    if state is None:
        return set()
    return resolve_delegated_roles_in_memory(state, grantee_user_id, int(at_ts))


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
    """创建或撤销跨部门角色借调委托（支持二级转借调并强制拦截有向环路与三级越界）。"""
    norm_role = str(delegated_role or "").strip()
    norm_grantor = str(grantor_user_id or "").strip()
    norm_grantee = str(grantee_user_id or "").strip()
    norm_action = str(action or "create").strip()

    if norm_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {norm_role}")
    if actor_user_id != norm_grantor and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if not norm_grantor or not norm_grantee:
        raise ValueError("grantor_user_id and grantee_user_id are required")
    if norm_grantor == norm_grantee:
        raise ValueError("Cannot delegate role to self")

    eval_ts = strict_int(now_ts if now_ts is not None else int(time.time()), "now_ts", min_val=0)
    s_ts = strict_int(starts_at, "starts_at", min_val=0) if norm_action == "create" else 0
    e_ts = strict_int(expires_at, "expires_at", min_val=0) if norm_action == "create" else 0

    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(tenant_id):
        state = get_tenant_auth_state(rt, tenant_id)
        if state is None:
            raise LookupError("Tenant not found")

        u_grantor = state.users.get(norm_grantor)
        u_grantee = state.users.get(norm_grantee)
        if u_grantor is None or not u_grantor.active or u_grantee is None or not u_grantee.active:
            raise LookupError("Grantor or grantee not found in tenant")

        if norm_action == "create":
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")

            # 拦截有向委托环路（若 grantee 下游已直接或间接指向 grantor，拒绝成环）
            ref_floor = min(eval_ts, s_ts)
            if _has_active_delegation_path(state, norm_grantee, norm_grantor, norm_role, ref_floor):
                raise ValueError("Delegation cycle detected in active chain")

            grantor_native = state.native_roles_of(norm_grantor)
            can_delegate = norm_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                # 校验 grantor 是否在 eval_ts 拥有来自原生持有人的有效 1 跳受托资格
                for e1 in state.delegations_by_grantee.get(norm_grantor, ()):
                    if (
                        e1.role == norm_role
                        and e1.starts_at <= eval_ts < e1.expires_at
                        and e1.grantor_id != norm_grantor
                        and e1.grantor_id != norm_grantee
                        and norm_role in state.native_roles_of(e1.grantor_id)
                    ):
                        can_delegate = True
                        break
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            with rt.write_tx() as conn:
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, norm_grantor, norm_grantee, norm_role, s_ts, e_ts, eval_ts),
                )
            state.add_delegation_edge(DelegationEdge(norm_grantor, norm_grantee, norm_role, s_ts, e_ts))
            state.auth_epoch += 1
            affected = 1
        elif norm_action == "revoke":
            with rt.write_tx() as conn:
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, norm_grantor, norm_grantee, norm_role),
                )
                affected = cur.rowcount
            state.remove_delegation_edges(norm_grantor, norm_grantee, norm_role)
            state.auth_epoch += 1
        else:
            raise ValueError("action must be 'create' or 'revoke'")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": norm_grantor,
        "grantee_user_id": norm_grantee,
        "delegated_role": norm_role,
        "action": norm_action,
        "affected": affected,
    }
