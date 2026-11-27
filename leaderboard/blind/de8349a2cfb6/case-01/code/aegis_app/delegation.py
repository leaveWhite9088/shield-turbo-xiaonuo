# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。"""
from __future__ import annotations

import pathlib
import threading
import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE, parse_strict_int
from .db import bump_domain_epoch, get_domain_epoch, open_connection


class _PermStateCache:
    __slots__ = (
        "epoch",
        "users",
        "org_nodes",
        "explicit_grants",
        "native_roles_by_user",
        "delegations_by_grantee",
    )

    def __init__(
        self,
        epoch: int,
        users: dict[str, tuple[str, str, int]],
        org_nodes: dict[str, tuple[str | None, str | None]],
        explicit_grants: dict[str, set[str]],
        native_roles_by_user: dict[str, set[str]],
        delegations_by_grantee: dict[str, list[tuple[str, str, int, int]]],
    ) -> None:
        self.epoch = epoch
        self.users = users
        self.org_nodes = org_nodes
        self.explicit_grants = explicit_grants
        self.native_roles_by_user = native_roles_by_user
        self.delegations_by_grantee = delegations_by_grantee


_PERM_CACHE_LOCK = threading.Lock()
_PERM_CACHES: dict[str, _PermStateCache] = {}


def _get_perm_cache(db_path: str, tenant_id: str) -> _PermStateCache:
    db_key = str(pathlib.Path(db_path).resolve())
    cache_key = f"{db_key}::{tenant_id}"
    cur_epoch = get_domain_epoch(db_key, tenant_id, "perm")
    with _PERM_CACHE_LOCK:
        cached = _PERM_CACHES.get(cache_key)
        if cached is not None and cached.epoch == cur_epoch:
            return cached

    conn = open_connection(db_key)
    try:
        u_rows = conn.execute(
            "SELECT user_id, org_node_id, base_role, active FROM users WHERE tenant_id = ?",
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
    finally:
        conn.close()

    users: dict[str, tuple[str, str, int]] = {}
    for r in u_rows:
        users[str(r["user_id"])] = (str(r["org_node_id"]), str(r["base_role"]), int(r["active"]))

    org_nodes: dict[str, tuple[str | None, str | None]] = {}
    for r in n_rows:
        p_id = str(r["parent_node_id"]) if r["parent_node_id"] else None
        i_role = str(r["inherited_role"]) if r["inherited_role"] else None
        org_nodes[str(r["node_id"])] = (p_id, i_role)

    explicit_grants: dict[str, set[str]] = {}
    for r in g_rows:
        explicit_grants.setdefault(str(r["user_id"]), set()).add(str(r["granted_role"]))

    native_roles_by_user: dict[str, set[str]] = {}
    for uid, (org_id, base_role, act) in users.items():
        if act != 1:
            native_roles_by_user[uid] = set()
            continue
        roles: set[str] = {base_role}
        curr: str | None = org_id
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            node_info = org_nodes.get(curr)
            if not node_info:
                break
            p_node, inh_role = node_info
            if inh_role:
                roles.add(inh_role)
            curr = p_node
        if uid in explicit_grants:
            roles |= explicit_grants[uid]
        native_roles_by_user[uid] = roles

    delegations_by_grantee: dict[str, list[tuple[str, str, int, int]]] = {}
    for r in d_rows:
        grantee = str(r["grantee_user_id"])
        grantor = str(r["grantor_user_id"])
        d_role = str(r["delegated_role"])
        s_ts = int(r["starts_at"])
        e_ts = int(r["expires_at"])
        delegations_by_grantee.setdefault(grantee, []).append((grantor, d_role, s_ts, e_ts))

    state = _PermStateCache(
        epoch=cur_epoch,
        users=users,
        org_nodes=org_nodes,
        explicit_grants=explicit_grants,
        native_roles_by_user=native_roles_by_user,
        delegations_by_grantee=delegations_by_grantee,
    )
    with _PERM_CACHE_LOCK:
        if len(_PERM_CACHES) > 256:
            _PERM_CACHES.pop(next(iter(_PERM_CACHES)), None)
        _PERM_CACHES[cache_key] = state
    return state


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    state = _get_perm_cache(db_path, tenant_id)
    return set(state.native_roles_by_user.get(user_id, set()))


def _collect_upstream_grantors_cached(
    state: _PermStateCache,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
    visited: set[str] | None = None,
) -> list[tuple[str, int]]:
    """沿当前有效时间窗有界回溯指定角色的上游委托路径（严格防环路与 MAX_DELEGATION_HOPS 剪枝）。"""
    if depth >= MAX_DELEGATION_HOPS:
        return []
    seen = set(visited) if visited is not None else {grantee_user_id}
    edges = state.delegations_by_grantee.get(grantee_user_id, ())
    active_grantors: list[str] = []
    for grantor_id, d_role, s_ts, e_ts in edges:
        if d_role != role_name:
            continue
        if not (s_ts <= at_ts < e_ts):
            continue
        if grantor_id in seen:
            continue
        u_info = state.users.get(grantor_id)
        if u_info and u_info[2] == 1 and grantor_id not in active_grantors:
            active_grantors.append(grantor_id)

    discovered: list[tuple[str, int]] = []
    for gid in active_grantors:
        next_hop = depth + 1
        discovered.append((gid, next_hop))
        if next_hop < MAX_DELEGATION_HOPS:
            next_seen = seen | {gid}
            discovered.extend(
                _collect_upstream_grantors_cached(
                    state,
                    gid,
                    role_name,
                    at_ts,
                    next_hop,
                    next_seen,
                )
            )
    return discovered


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。"""
    state = _get_perm_cache(db_path, tenant_id)
    edges = state.delegations_by_grantee.get(grantee_user_id, ())
    if not edges:
        return set()

    candidate_roles = {
        d_role
        for _, d_role, s_ts, e_ts in edges
        if s_ts <= at_ts < e_ts
    }
    if not candidate_roles:
        return set()

    effective_delegated: set[str] = set()
    for role_name in candidate_roles:
        upstream_chain = _collect_upstream_grantors_cached(
            state,
            grantee_user_id,
            role_name,
            at_ts,
            depth=0,
            visited={grantee_user_id},
        )
        for src_uid, hop_dist in upstream_chain:
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                src_native = state.native_roles_by_user.get(src_uid, set())
                if role_name in src_native:
                    effective_delegated.add(role_name)
                    break
    return effective_delegated


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
    if not grantor_user_id or not grantee_user_id or grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self or empty user")

    s_ts = parse_strict_int(starts_at, "starts_at", min_val=0)
    e_ts = parse_strict_int(expires_at, "expires_at", min_val=0)
    eval_ts = int(now_ts if now_ts is not None else time.time())

    state = _get_perm_cache(db_path, tenant_id)
    u_grantor = state.users.get(grantor_user_id)
    u_grantee = state.users.get(grantee_user_id)
    if not u_grantor or u_grantor[2] != 1 or not u_grantee or u_grantee[2] != 1:
        raise LookupError("Grantor or grantee not found in tenant")

    conn = open_connection(db_path)
    try:
        if action == "create":
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")
            grantor_native = state.native_roles_by_user.get(grantor_user_id, set())
            can_delegate = delegated_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = _collect_upstream_grantors_cached(
                    state,
                    grantor_user_id,
                    delegated_role,
                    eval_ts,
                    depth=0,
                    visited={grantor_user_id, grantee_user_id},
                )
                can_delegate = any(
                    hop == 1 and delegated_role in state.native_roles_by_user.get(src_uid, set())
                    for src_uid, hop in upstream
                )
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")
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
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE delegation_grants SET active = 0 "
                "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
            )
            conn.commit()
            affected = cur.rowcount
        else:
            raise ValueError("action must be 'create' or 'revoke'")
    finally:
        conn.close()

    bump_domain_epoch(db_path, tenant_id, "perm")
    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
