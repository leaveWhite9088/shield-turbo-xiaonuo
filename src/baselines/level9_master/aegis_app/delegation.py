# -*- coding: utf-8 -*-
"""高性能角色借调委托引擎：租户权限内存快照 + 精确秒级时效窗口 + O(1) 委托人实时资格级联核验。"""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any

from .config import ROLE_DEFAULT_CLEARANCE
from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    normalize_db_key,
    register_cache_reset_hook,
    require_strict_int,
)


@dataclass(frozen=True)
class UserAuthProfile:
    user_id: str
    username: str
    org_node_id: str
    api_token_hash: str
    active: bool
    lineage: tuple[str, ...]
    native_roles: frozenset[str]


@dataclass(frozen=True)
class TenantAuthSnapshot:
    perm_epoch: int
    tenant_status: str
    webhook_secret: str
    users: dict[str, UserAuthProfile]
    # grantee_user_id -> tuple of (grantor_user_id, delegated_role, starts_at, expires_at)
    delegations_by_grantee: dict[str, tuple[tuple[str, str, int, int], ...]]


_SNAP_LOCK = threading.Lock()
_TENANT_AUTH_SNAPS: dict[tuple[str, str], TenantAuthSnapshot] = {}


def _clear_auth_snaps(db_key: str) -> None:
    with _SNAP_LOCK:
        for k in [k for k in _TENANT_AUTH_SNAPS if k[0] == db_key]:
            _TENANT_AUTH_SNAPS.pop(k, None)


register_cache_reset_hook(_clear_auth_snaps)


def get_tenant_auth_snapshot(db_path: str, tenant_id: str, perm_epoch: int) -> TenantAuthSnapshot | None:
    """获取或构建本租户在当前 perm_epoch 下的不可变身份与委托关系快照。"""
    db_key = normalize_db_key(db_path)
    tk = (db_key, tenant_id)
    with _SNAP_LOCK:
        snap = _TENANT_AUTH_SNAPS.get(tk)
        if snap is not None and snap.perm_epoch == perm_epoch:
            return snap

    conn = get_thread_connection(db_path)
    t_row = conn.execute(
        "SELECT status, webhook_secret FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    if not t_row:
        return None

    org_rows = conn.execute(
        "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    org_map = {
        str(r["node_id"]): (r["parent_node_id"], r["inherited_role"])
        for r in org_rows
    }

    grant_rows = conn.execute(
        "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
        (tenant_id,),
    ).fetchall()
    grants_by_user: dict[str, set[str]] = {}
    for gr in grant_rows:
        grants_by_user.setdefault(str(gr["user_id"]), set()).add(str(gr["granted_role"]))

    user_rows = conn.execute(
        "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
        "FROM users WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()

    users_dict: dict[str, UserAuthProfile] = {}
    for ur in user_rows:
        uid = str(ur["user_id"])
        active_flag = bool(ur["active"])
        start_node = str(ur["org_node_id"])

        lineage_list: list[str] = []
        native_set: set[str] = {str(ur["base_role"])} if active_flag else set()
        curr: str | None = start_node
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            lineage_list.append(curr)
            info = org_map.get(curr)
            if not info:
                break
            parent_id, inh_role = info
            if active_flag and inh_role:
                native_set.add(str(inh_role))
            curr = parent_id

        if active_flag and uid in grants_by_user:
            native_set.update(grants_by_user[uid])

        users_dict[uid] = UserAuthProfile(
            user_id=uid,
            username=str(ur["username"]),
            org_node_id=start_node,
            api_token_hash=str(ur["api_token_hash"]),
            active=active_flag,
            lineage=tuple(lineage_list),
            native_roles=frozenset(native_set),
        )

    del_rows = conn.execute(
        "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
        "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
        (tenant_id,),
    ).fetchall()
    del_tmp: dict[str, list[tuple[str, str, int, int]]] = {}
    for dr in del_rows:
        del_tmp.setdefault(str(dr["grantee_user_id"]), []).append(
            (
                str(dr["grantor_user_id"]),
                str(dr["delegated_role"]),
                int(dr["starts_at"]),
                int(dr["expires_at"]),
            )
        )
    del_map = {k: tuple(v) for k, v in del_tmp.items()}

    built = TenantAuthSnapshot(
        perm_epoch=perm_epoch,
        tenant_status=str(t_row["status"]),
        webhook_secret=str(t_row["webhook_secret"]),
        users=users_dict,
        delegations_by_grantee=del_map,
    )

    with _SNAP_LOCK:
        live_eps = get_tenant_epochs(db_path, tenant_id)
        if live_eps.perm == perm_epoch:
            _TENANT_AUTH_SNAPS[tk] = built
    return built


def compute_effective_roles_from_snapshot(
    snap: TenantAuthSnapshot,
    user_id: str,
    at_ts: int,
) -> tuple[set[str], int]:
    """在内存快照上精确核验借调时间窗 [starts_at, expires_at) 与委托人当前原生角色持有状态。"""
    u_prof = snap.users.get(user_id)
    if u_prof is None or not u_prof.active:
        return set(), 0

    roles = set(u_prof.native_roles)
    for grantor_id, del_role, s_ts, e_ts in snap.delegations_by_grantee.get(user_id, ()):
        if s_ts <= at_ts < e_ts:
            grantor_prof = snap.users.get(grantor_id)
            if grantor_prof is not None and grantor_prof.active and del_role in grantor_prof.native_roles:
                roles.add(del_role)

    max_cl = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
    return roles, max_cl


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    eps = get_tenant_epochs(db_path, tenant_id)
    snap = get_tenant_auth_snapshot(db_path, tenant_id, eps.perm)
    if snap is None:
        return set()
    prof = snap.users.get(user_id)
    if prof is None or not prof.active:
        return set()
    return set(prof.native_roles)


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    eps = get_tenant_epochs(db_path, tenant_id)
    snap = get_tenant_auth_snapshot(db_path, tenant_id, eps.perm)
    if snap is None:
        return set()
    delegated: set[str] = set()
    for grantor_id, del_role, s_ts, e_ts in snap.delegations_by_grantee.get(grantee_user_id, ()):
        if s_ts <= at_ts < e_ts:
            grantor_prof = snap.users.get(grantor_id)
            if grantor_prof is not None and grantor_prof.active and del_role in grantor_prof.native_roles:
                delegated.add(del_role)
    return delegated


def create_or_revoke_delegation(
    db_path: str,
    tenant_id: str,
    actor_user_id: str,
    actor_roles: set[str],
    *,
    grantor_user_id: str,
    grantee_user_id: str,
    delegated_role: str,
    starts_at: Any,
    expires_at: Any,
    action: str = "create",
    now_ts: int | None = None,
) -> dict[str, Any]:
    if delegated_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {delegated_role}")
    if actor_user_id != grantor_user_id and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if not grantor_user_id or not grantee_user_id or len(grantor_user_id) > 64 or len(grantee_user_id) > 64:
        raise ValueError("Invalid grantor_user_id or grantee_user_id")
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")
    if action not in ("create", "revoke"):
        raise ValueError("action must be 'create' or 'revoke'")

    checked_start = require_strict_int(starts_at, "starts_at", min_val=0, max_val=9_999_999_999)
    checked_end = require_strict_int(expires_at, "expires_at", min_val=0, max_val=9_999_999_999)
    ts_val = int(now_ts if now_ts is not None else time.time())

    lock = get_striped_lock(db_path, tenant_id, "perm")
    with lock:
        conn = get_thread_connection(db_path)
        u_check = conn.execute(
            "SELECT COUNT(*) AS cnt FROM users WHERE tenant_id = ? AND user_id IN (?, ?) AND active = 1",
            (tenant_id, grantor_user_id, grantee_user_id),
        ).fetchone()
        if not u_check or int(u_check["cnt"]) < 2:
            raise LookupError("Grantor or grantee not found in tenant")

        if action == "create":
            if checked_end <= checked_start:
                raise ValueError("expires_at must be greater than starts_at")
            eps = get_tenant_epochs(db_path, tenant_id)
            snap = get_tenant_auth_snapshot(db_path, tenant_id, eps.perm)
            grantor_prof = snap.users.get(grantor_user_id) if snap else None
            if grantor_prof is None or delegated_role not in grantor_prof.native_roles:
                raise PermissionError("Grantor does not possess the role being delegated")
            conn.execute(
                "INSERT INTO delegation_grants("
                "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (tenant_id, grantor_user_id, grantee_user_id, delegated_role, checked_start, checked_end, ts_val),
            )
            affected = 1
        else:
            cur = conn.execute(
                "UPDATE delegation_grants SET active = 0 "
                "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
            )
            affected = cur.rowcount
        conn.commit()
        bump_tenant_epoch(db_path, tenant_id, "perm")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
