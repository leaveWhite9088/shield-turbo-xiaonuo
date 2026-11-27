# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）、防环路检测与独立 perm_epoch 缓存模块。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .state import GatewayState, get_gateway_state
from .validation import parse_strict_int


class TenantPermCache:
    """单租户身份、组织继承角色、显式授牌与活跃借调委托表快照（按 perm_epoch 失效）。"""

    __slots__ = (
        "epoch",
        "users",
        "org_nodes",
        "role_grants",
        "delegations_by_grantee",
        "native_roles_cache",
    )

    def __init__(
        self,
        epoch: int,
        users: dict[str, tuple[str, str, str, str, int]],
        org_nodes: dict[str, tuple[str | None, str | None]],
        role_grants: dict[str, set[str]],
        delegations_by_grantee: dict[str, list[tuple[str, str, int, int]]],
    ) -> None:
        self.epoch = epoch
        self.users = users
        self.org_nodes = org_nodes
        self.role_grants = role_grants
        self.delegations_by_grantee = delegations_by_grantee
        self.native_roles_cache: dict[str, frozenset[str]] = {}

    def get_native_roles(self, user_id: str) -> frozenset[str]:
        cached = self.native_roles_cache.get(user_id)
        if cached is not None:
            return cached
        u_info = self.users.get(user_id)
        if not u_info or u_info[4] != 1:
            self.native_roles_cache[user_id] = frozenset()
            return frozenset()

        org_node_id, base_role, _, _, _ = u_info
        roles: set[str] = {base_role}
        curr: str | None = org_node_id
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            node = self.org_nodes.get(curr)
            if not node:
                break
            parent_id, inherited_role = node
            if inherited_role:
                roles.add(inherited_role)
            curr = parent_id

        extra = self.role_grants.get(user_id)
        if extra:
            roles.update(extra)
        res = frozenset(roles)
        self.native_roles_cache[user_id] = res
        return res


def get_perm_cache(gw_state: GatewayState, tenant_id: str) -> TenantPermCache:
    t_state = gw_state.tenant(tenant_id)
    cache = t_state.perm_cache
    if cache is not None and cache.epoch == t_state.perm_epoch:
        return cache
    with t_state.perm_lock:
        cache = t_state.perm_cache
        if cache is not None and cache.epoch == t_state.perm_epoch:
            return cache
        epoch = t_state.perm_epoch
        with gw_state.pool.borrow() as conn:
            u_rows = conn.execute(
                "SELECT user_id, org_node_id, base_role, api_token_hash, username, active "
                "FROM users WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            n_rows = conn.execute(
                "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
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

        users = {
            r["user_id"]: (
                r["org_node_id"],
                r["base_role"],
                r["api_token_hash"],
                r["username"],
                int(r["active"]),
            )
            for r in u_rows
        }
        org_nodes = {
            r["node_id"]: (r["parent_node_id"], r["inherited_role"])
            for r in n_rows
        }
        role_grants: dict[str, set[str]] = {}
        for r in g_rows:
            role_grants.setdefault(r["user_id"], set()).add(r["granted_role"])
        delegations_by_grantee: dict[str, list[tuple[str, str, int, int]]] = {}
        for r in d_rows:
            delegations_by_grantee.setdefault(r["grantee_user_id"], []).append(
                (
                    str(r["grantor_user_id"]),
                    str(r["delegated_role"]),
                    int(r["starts_at"]),
                    int(r["expires_at"]),
                )
            )
        cache = TenantPermCache(epoch, users, org_nodes, role_grants, delegations_by_grantee)
        t_state.perm_cache = cache
        return cache


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    gw_state = get_gateway_state(db_path)
    cache = get_perm_cache(gw_state, tenant_id)
    return set(cache.get_native_roles(user_id))


def _collect_upstream_grantors_mem(
    cache: TenantPermCache,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
    visited: set[str] | None = None,
) -> list[tuple[str, int]]:
    if depth >= MAX_DELEGATION_HOPS:
        return []
    if visited is None:
        visited = {grantee_user_id}

    discovered: list[tuple[str, int]] = []
    for gid, d_role, s_ts, e_ts in cache.delegations_by_grantee.get(grantee_user_id, ()):
        if d_role != role_name:
            continue
        if not (s_ts <= at_ts < e_ts):
            continue
        if gid in visited:
            continue
        u_info = cache.users.get(gid)
        if not u_info or u_info[4] != 1:
            continue
        next_hop = depth + 1
        discovered.append((gid, next_hop))
        if next_hop < MAX_DELEGATION_HOPS:
            visited.add(gid)
            discovered.extend(
                _collect_upstream_grantors_mem(
                    cache,
                    gid,
                    role_name,
                    at_ts,
                    next_hop,
                    visited,
                )
            )
            visited.discard(gid)
    return discovered


def resolve_active_delegated_roles_from_cache(
    cache: TenantPermCache,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    candidate_roles = {
        d_role
        for _, d_role, s_ts, e_ts in cache.delegations_by_grantee.get(grantee_user_id, ())
        if s_ts <= at_ts < e_ts
    }
    effective_delegated: set[str] = set()
    for role_name in candidate_roles:
        upstream_chain = _collect_upstream_grantors_mem(
            cache,
            grantee_user_id,
            role_name,
            at_ts,
        )
        for src_uid, hop_dist in upstream_chain:
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                if role_name in cache.get_native_roles(src_uid):
                    effective_delegated.add(role_name)
                    break
    return effective_delegated


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。"""
    gw_state = get_gateway_state(db_path)
    cache = get_perm_cache(gw_state, tenant_id)
    return resolve_active_delegated_roles_from_cache(cache, grantee_user_id, at_ts)


def _would_create_cycle(
    cache: TenantPermCache,
    grantor_user_id: str,
    grantee_user_id: str,
    delegated_role: str,
) -> bool:
    """检查新增 grantor -> grantee 是否会在 active 委托图中形成有向环路。"""
    stack = [grantor_user_id]
    seen: set[str] = set()
    while stack:
        curr = stack.pop()
        if curr == grantee_user_id:
            return True
        if curr in seen:
            continue
        seen.add(curr)
        for up_gid, d_role, _, _ in cache.delegations_by_grantee.get(curr, ()):
            if d_role == delegated_role and up_gid not in seen:
                stack.append(up_gid)
    return False


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
    """创建或撤销跨部门角色借调委托（支持原生持有人发起一级借调，或有效一级受托人发起二级转借调）。"""
    if delegated_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {delegated_role}")
    if actor_user_id != grantor_user_id and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")

    s_ts = parse_strict_int(starts_at, "starts_at")
    e_ts = parse_strict_int(expires_at, "expires_at")
    eval_ts = int(now_ts if now_ts is not None else time.time())

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(tenant_id)
    with t_state.perm_lock:
        cache = get_perm_cache(gw_state, tenant_id)
        g_info = cache.users.get(grantor_user_id)
        e_info = cache.users.get(grantee_user_id)
        if not g_info or g_info[4] != 1 or not e_info or e_info[4] != 1:
            raise LookupError("Grantor or grantee not found in tenant")

        if action == "create":
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")
            if _would_create_cycle(cache, grantor_user_id, grantee_user_id, delegated_role):
                raise ValueError("Delegation cycle detected")

            grantor_native = cache.get_native_roles(grantor_user_id)
            can_delegate = delegated_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = _collect_upstream_grantors_mem(
                    cache,
                    grantor_user_id,
                    delegated_role,
                    eval_ts,
                )
                can_delegate = any(
                    hop == 1 and delegated_role in cache.get_native_roles(src_uid)
                    for src_uid, hop in upstream
                )
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            with gw_state.pool.borrow() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role, s_ts, e_ts, eval_ts),
                )
                conn.commit()
            affected = 1
        elif action == "revoke":
            with gw_state.pool.borrow() as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
                )
                affected = cur.rowcount
                conn.commit()
        else:
            raise ValueError("action must be 'create' or 'revoke'")

        t_state.perm_epoch += 1

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
