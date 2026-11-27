# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）、有向环路免疫与零写自然过期核验模块。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import borrow_connection, write_transaction
from .runtime_state import get_runtime, parse_strict_int


class PermSnapshot:
    """租户级权限与借调图只读快照，绑定 perm_epoch。

    保留每条活跃借调的 (grantor_user_id, delegated_role, starts_at, expires_at)，
    在读取时按 at_ts 实时评估 starts_at <= at_ts < expires_at，实现上游窗口自然到期零写降级。
    """

    __slots__ = ("user_active", "user_native_roles", "delegations_by_grantee")

    def __init__(
        self,
        user_active: dict[str, bool],
        user_native_roles: dict[str, frozenset[str]],
        delegations_by_grantee: dict[str, tuple[tuple[str, str, int, int], ...]],
    ) -> None:
        self.user_active = user_active
        self.user_native_roles = user_native_roles
        self.delegations_by_grantee = delegations_by_grantee


def get_perm_snapshot(db_path: str, tenant_id: str) -> PermSnapshot:
    rt = get_runtime(db_path)
    tstate = rt.get_tenant(tenant_id)
    snap = tstate.perm_snapshot
    if snap is not None and tstate.perm_snapshot_epoch == tstate.perm_epoch:
        return snap

    with tstate.perm_lock:
        if tstate.perm_snapshot is not None and tstate.perm_snapshot_epoch == tstate.perm_epoch:
            return tstate.perm_snapshot

        target_epoch = tstate.perm_epoch
        with borrow_connection(db_path) as conn:
            org_rows = conn.execute(
                "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            user_rows = conn.execute(
                "SELECT user_id, org_node_id, base_role, active FROM users WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            grant_rows = conn.execute(
                "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
            del_rows = conn.execute(
                "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
                "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()

        parent_map: dict[str, str | None] = {}
        inherited_map: dict[str, str | None] = {}
        for r in org_rows:
            nid = str(r["node_id"])
            parent_map[nid] = str(r["parent_node_id"]) if r["parent_node_id"] else None
            inherited_map[nid] = str(r["inherited_role"]) if r["inherited_role"] else None

        org_roles_cache: dict[str, set[str]] = {}
        for nid in parent_map:
            rset: set[str] = set()
            curr: str | None = nid
            visited: set[str] = set()
            while curr and curr not in visited:
                visited.add(curr)
                ir = inherited_map.get(curr)
                if ir:
                    rset.add(ir)
                curr = parent_map.get(curr)
            org_roles_cache[nid] = rset

        explicit_by_user: dict[str, set[str]] = {}
        for r in grant_rows:
            explicit_by_user.setdefault(str(r["user_id"]), set()).add(str(r["granted_role"]))

        user_active: dict[str, bool] = {}
        user_native_roles: dict[str, frozenset[str]] = {}
        for r in user_rows:
            uid = str(r["user_id"])
            act = int(r["active"]) == 1
            user_active[uid] = act
            if not act:
                user_native_roles[uid] = frozenset()
            else:
                roles = {str(r["base_role"])}
                roles.update(org_roles_cache.get(str(r["org_node_id"]), ()))
                roles.update(explicit_by_user.get(uid, ()))
                user_native_roles[uid] = frozenset(roles)

        del_map: dict[str, list[tuple[str, str, int, int]]] = {}
        for r in del_rows:
            grantee = str(r["grantee_user_id"])
            grantor = str(r["grantor_user_id"])
            role = str(r["delegated_role"])
            s_ts = int(r["starts_at"])
            e_ts = int(r["expires_at"])
            del_map.setdefault(grantee, []).append((grantor, role, s_ts, e_ts))

        frozen_del = {k: tuple(v) for k, v in del_map.items()}
        snap = PermSnapshot(
            user_active=user_active,
            user_native_roles=user_native_roles,
            delegations_by_grantee=frozen_del,
        )
        tstate.perm_snapshot = snap
        tstate.perm_snapshot_epoch = target_epoch
        return snap


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    snap = get_perm_snapshot(db_path, tenant_id)
    if not snap.user_active.get(user_id, False):
        return set()
    return set(snap.user_native_roles.get(user_id, ()))


def _collect_upstream_grantors_in_memory(
    snap: PermSnapshot,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    max_hops: int = MAX_DELEGATION_HOPS,
) -> list[tuple[str, int]]:
    """有界深度、带环路免疫的 BFS 回溯指定角色的上游有效委托人。"""
    discovered: list[tuple[str, int]] = []
    # BFS queue: (current_user_id, current_hop)
    frontier: list[tuple[str, int]] = [(grantee_user_id, 0)]
    visited: set[str] = {grantee_user_id}

    while frontier:
        curr_uid, depth = frontier.pop(0)
        if depth >= max_hops:
            continue
        edges = snap.delegations_by_grantee.get(curr_uid)
        if not edges:
            continue
        next_hop = depth + 1
        for grantor_id, d_role, s_ts, e_ts in edges:
            if d_role != role_name:
                continue
            if not (s_ts <= at_ts < e_ts):
                continue
            if not snap.user_active.get(grantor_id, False):
                continue
            if grantor_id in visited:
                continue
            visited.add(grantor_id)
            discovered.append((grantor_id, next_hop))
            if next_hop < max_hops:
                frontier.append((grantor_id, next_hop))
    return discovered


def _has_directed_path(
    snap: PermSnapshot,
    start_grantee: str,
    target_grantor: str,
    role_name: str,
) -> bool:
    """检查在当前所有 active=1 借调边中，是否存在从 target_grantor -> ... -> start_grantee 的路径（用于建边防环）。"""
    visited: set[str] = {start_grantee}
    stack: list[str] = [start_grantee]
    while stack:
        curr = stack.pop()
        for grantor_id, d_role, _, _ in snap.delegations_by_grantee.get(curr, ()):
            if d_role != role_name:
                continue
            if grantor_id == target_grantor:
                return True
            if grantor_id not in visited:
                visited.add(grantor_id)
                stack.append(grantor_id)
    return False


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多 MAX_DELEGATION_HOPS=2 跳，环路免疫）。"""
    snap = get_perm_snapshot(db_path, tenant_id)
    if not snap.user_active.get(grantee_user_id, False):
        return set()

    direct_edges = snap.delegations_by_grantee.get(grantee_user_id)
    if not direct_edges:
        return set()

    candidate_roles = {
        d_role
        for _, d_role, s_ts, e_ts in direct_edges
        if s_ts <= at_ts < e_ts
    }
    if not candidate_roles:
        return set()

    effective_delegated: set[str] = set()
    for role_name in candidate_roles:
        upstream = _collect_upstream_grantors_in_memory(
            snap,
            grantee_user_id,
            role_name,
            at_ts,
            max_hops=MAX_DELEGATION_HOPS,
        )
        for src_uid, hop_dist in upstream:
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                if role_name in snap.user_native_roles.get(src_uid, ()):
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
    """创建或撤销跨部门角色借调委托（支持原生持有人一级借调或有效一级受托人二级转借调，拒绝环路）。"""
    if delegated_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {delegated_role}")
    if actor_user_id != grantor_user_id and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if not grantor_user_id or not grantee_user_id or grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")

    eval_ts = int(now_ts if now_ts is not None else time.time())
    tstate = get_runtime(db_path).get_tenant(tenant_id)

    with tstate.perm_lock:
        snap = get_perm_snapshot(db_path, tenant_id)
        if not snap.user_active.get(grantor_user_id, False) or not snap.user_active.get(grantee_user_id, False):
            raise LookupError("Grantor or grantee not found in tenant")

        if action == "create":
            s_ts = parse_strict_int(starts_at, field_name="starts_at", min_val=0)
            e_ts = parse_strict_int(expires_at, field_name="expires_at", min_val=0)
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")

            # 有向环路免疫：若 grantee 已经是 grantor 的上游委托人，拒绝闭环
            if _has_directed_path(snap, grantor_user_id, grantee_user_id, delegated_role):
                raise ValueError("Delegation cycle detected")

            can_delegate = delegated_role in snap.user_native_roles.get(grantor_user_id, ())
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = _collect_upstream_grantors_in_memory(
                    snap,
                    grantor_user_id,
                    delegated_role,
                    eval_ts,
                    max_hops=1,
                )
                can_delegate = any(
                    hop == 1 and delegated_role in snap.user_native_roles.get(src_uid, ())
                    for src_uid, hop in upstream
                )
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            with write_transaction(db_path) as conn:
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role, s_ts, e_ts, eval_ts),
                )
            affected = 1
            tstate.perm_epoch += 1
        elif action == "revoke":
            with write_transaction(db_path) as conn:
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
                )
                affected = cur.rowcount
            tstate.perm_epoch += 1
        else:
            raise ValueError("action must be 'create' or 'revoke'")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
