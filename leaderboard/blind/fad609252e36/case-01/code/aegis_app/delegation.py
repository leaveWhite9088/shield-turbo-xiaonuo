# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）、防环路检测与时效窗口级联资格缓存模块。"""
from __future__ import annotations

import bisect
import time
from typing import Any

from .config import INT64_MAX, INT64_MIN, MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import (
    bump_auth_epoch,
    get_tenant_auth_lock,
    get_tenant_epochs,
    normalize_db_key,
    open_connection,
    register_reset_callback,
)
from .middleware import strict_int


class _UserEntry:
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


class _DelegationEdge:
    __slots__ = ("grantor_user_id", "grantee_user_id", "delegated_role", "starts_at", "expires_at")

    def __init__(
        self,
        grantor_user_id: str,
        grantee_user_id: str,
        delegated_role: str,
        starts_at: int,
        expires_at: int,
    ) -> None:
        self.grantor_user_id = grantor_user_id
        self.grantee_user_id = grantee_user_id
        self.delegated_role = delegated_role
        self.starts_at = starts_at
        self.expires_at = expires_at


class TenantAuthSnapshot:
    """租户权限、组织树继承、二级借调图谱与时效边界缓存快照（受 auth_epoch 独立驱动）。"""

    __slots__ = (
        "auth_epoch",
        "tenant_exists",
        "tenant_active",
        "webhook_secret",
        "users",
        "org_nodes",
        "org_lineage",
        "native_roles",
        "delegations_by_grantee",
        "window_boundaries",
        "perm_window_cache",
    )

    def __init__(self, auth_epoch: int) -> None:
        self.auth_epoch = auth_epoch
        self.tenant_exists = False
        self.tenant_active = False
        self.webhook_secret = ""
        self.users: dict[str, _UserEntry] = {}
        self.org_nodes: dict[str, tuple[str | None, str | None]] = {}
        self.org_lineage: dict[str, tuple[str, ...]] = {}
        self.native_roles: dict[str, frozenset[str]] = {}
        self.delegations_by_grantee: dict[str, tuple[_DelegationEdge, ...]] = {}
        self.window_boundaries: tuple[int, ...] = ()
        self.perm_window_cache: dict[str, tuple[int, int, frozenset[str], int]] = {}


_MAX_AUTH_SNAPSHOTS = 256
_MAX_PERM_CACHE_PER_TENANT = 1024
_AUTH_SNAPSHOTS: dict[tuple[str, str], TenantAuthSnapshot] = {}


def _reset_auth_snapshots(db_key: str) -> None:
    for k in [k for k in _AUTH_SNAPSHOTS if k[0] == db_key]:
        _AUTH_SNAPSHOTS.pop(k, None)


register_reset_callback(_reset_auth_snapshots)


def _load_tenant_auth_snapshot(db_path: str, tenant_id: str, target_epoch: int) -> TenantAuthSnapshot:
    snap = TenantAuthSnapshot(target_epoch)
    conn = open_connection(db_path)
    try:
        t_row = conn.execute(
            "SELECT tenant_id, webhook_secret, status FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if not t_row:
            return snap
        snap.tenant_exists = True
        snap.tenant_active = str(t_row["status"]) == "ACTIVE"
        snap.webhook_secret = str(t_row["webhook_secret"] or "")

        n_rows = conn.execute(
            "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        for nr in n_rows:
            snap.org_nodes[str(nr["node_id"])] = (
                str(nr["parent_node_id"]) if nr["parent_node_id"] else None,
                str(nr["inherited_role"]) if nr["inherited_role"] else None,
            )

        for nid in snap.org_nodes:
            lineage: list[str] = []
            curr: str | None = nid
            visited: set[str] = set()
            while curr and curr not in visited:
                visited.add(curr)
                lineage.append(curr)
                node_info = snap.org_nodes.get(curr)
                curr = node_info[0] if node_info else None
            snap.org_lineage[nid] = tuple(lineage)

        u_rows = conn.execute(
            "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
            "FROM users WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        for ur in u_rows:
            uid = str(ur["user_id"])
            snap.users[uid] = _UserEntry(
                user_id=uid,
                username=str(ur["username"]),
                org_node_id=str(ur["org_node_id"]),
                base_role=str(ur["base_role"]),
                api_token_hash=str(ur["api_token_hash"]),
                active=int(ur["active"]) == 1,
            )

        g_rows = conn.execute(
            "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        grants_by_user: dict[str, set[str]] = {}
        for gr in g_rows:
            grants_by_user.setdefault(str(gr["user_id"]), set()).add(str(gr["granted_role"]))

        for uid, u_entry in snap.users.items():
            if not u_entry.active:
                snap.native_roles[uid] = frozenset()
                continue
            r_set: set[str] = {u_entry.base_role}
            for anc_nid in snap.org_lineage.get(u_entry.org_node_id, ()):
                n_info = snap.org_nodes.get(anc_nid)
                if n_info and n_info[1]:
                    r_set.add(n_info[1])
            if uid in grants_by_user:
                r_set.update(grants_by_user[uid])
            snap.native_roles[uid] = frozenset(r_set)

        d_rows = conn.execute(
            "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
            "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        by_grantee: dict[str, list[_DelegationEdge]] = {}
        boundaries: set[int] = set()
        for dr in d_rows:
            s_ts = int(dr["starts_at"])
            e_ts = int(dr["expires_at"])
            edge = _DelegationEdge(
                grantor_user_id=str(dr["grantor_user_id"]),
                grantee_user_id=str(dr["grantee_user_id"]),
                delegated_role=str(dr["delegated_role"]),
                starts_at=s_ts,
                expires_at=e_ts,
            )
            by_grantee.setdefault(edge.grantee_user_id, []).append(edge)
            boundaries.add(s_ts)
            boundaries.add(e_ts)

        snap.delegations_by_grantee = {k: tuple(v) for k, v in by_grantee.items()}
        snap.window_boundaries = tuple(sorted(boundaries))
        return snap
    finally:
        conn.close()


def get_tenant_auth_snapshot(db_path: str, tenant_id: str) -> TenantAuthSnapshot:
    db_key = normalize_db_key(db_path)
    epochs = get_tenant_epochs(db_path, tenant_id)
    cur_epoch = epochs.auth_epoch
    cache_key = (db_key, tenant_id)
    snap = _AUTH_SNAPSHOTS.get(cache_key)
    if snap is not None and snap.auth_epoch == cur_epoch:
        return snap

    with get_tenant_auth_lock(db_path, tenant_id):
        cur_epoch = get_tenant_epochs(db_path, tenant_id).auth_epoch
        snap = _AUTH_SNAPSHOTS.get(cache_key)
        if snap is not None and snap.auth_epoch == cur_epoch:
            return snap
        snap = _load_tenant_auth_snapshot(db_path, tenant_id, cur_epoch)
        if len(_AUTH_SNAPSHOTS) >= _MAX_AUTH_SNAPSHOTS and cache_key not in _AUTH_SNAPSHOTS:
            _AUTH_SNAPSHOTS.pop(next(iter(_AUTH_SNAPSHOTS)), None)
        _AUTH_SNAPSHOTS[cache_key] = snap
        return snap


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    snap = get_tenant_auth_snapshot(db_path, tenant_id)
    return set(snap.native_roles.get(user_id, frozenset()))


def _collect_upstream_grantors_from_snap(
    snap: TenantAuthSnapshot,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
    _visited: set[str] | None = None,
) -> list[tuple[str, int]]:
    """沿当前有效时间窗回溯指定角色的上游委托路径（带严格跳数上界 MAX_DELEGATION_HOPS 与有向环路免疫）。"""
    if depth >= MAX_DELEGATION_HOPS:
        return []
    visited = set(_visited) if _visited is not None else {grantee_user_id}
    edges = snap.delegations_by_grantee.get(grantee_user_id, ())
    active_grantors: list[str] = []
    for dr in edges:
        if dr.delegated_role != role_name:
            continue
        if not (dr.starts_at <= at_ts < dr.expires_at):
            continue
        gid = dr.grantor_user_id
        if gid in visited:
            continue
        u_entry = snap.users.get(gid)
        if u_entry is not None and u_entry.active and gid not in active_grantors:
            active_grantors.append(gid)

    discovered: list[tuple[str, int]] = []
    next_hop = depth + 1
    for gid in active_grantors:
        discovered.append((gid, next_hop))
        if next_hop < MAX_DELEGATION_HOPS:
            discovered.extend(
                _collect_upstream_grantors_from_snap(
                    snap,
                    gid,
                    role_name,
                    at_ts,
                    next_hop,
                    visited | {gid},
                )
            )
    return discovered


def _collect_upstream_grantors(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
    _visited: set[str] | None = None,
) -> list[tuple[str, int]]:
    snap = get_tenant_auth_snapshot(db_path, tenant_id)
    return _collect_upstream_grantors_from_snap(
        snap,
        grantee_user_id,
        role_name,
        at_ts,
        depth,
        _visited,
    )


def _compute_delegated_roles_from_snap(
    snap: TenantAuthSnapshot,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    edges = snap.delegations_by_grantee.get(grantee_user_id, ())
    if not edges:
        return set()
    candidate_roles = {
        dr.delegated_role
        for dr in edges
        if dr.starts_at <= at_ts < dr.expires_at
    }
    if not candidate_roles:
        return set()

    effective_delegated: set[str] = set()
    for role_name in candidate_roles:
        upstream_chain = _collect_upstream_grantors_from_snap(
            snap,
            grantee_user_id,
            role_name,
            at_ts,
            0,
            {grantee_user_id},
        )
        for src_uid, hop_dist in upstream_chain:
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                if role_name in snap.native_roles.get(src_uid, frozenset()):
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
    snap = get_tenant_auth_snapshot(db_path, tenant_id)
    return _compute_delegated_roles_from_snap(snap, grantee_user_id, int(at_ts))


def resolve_cached_effective_permissions(
    db_path: str,
    tenant_id: str,
    user_id: str,
    at_ts: int,
) -> tuple[set[str], int]:
    """结合 auth_epoch 与借调时效边界窗口 [v_from, v_until) 计算并缓存操作员实时有效角色与最高密级。"""
    eval_ts = int(at_ts)
    snap = get_tenant_auth_snapshot(db_path, tenant_id)
    u_entry = snap.users.get(user_id)
    if u_entry is None or not u_entry.active:
        return set(), 0

    cached = snap.perm_window_cache.get(user_id)
    if cached is not None:
        v_from, v_until, eff_roles, max_cl = cached
        if v_from <= eval_ts < v_until:
            return set(eff_roles), max_cl

    native = snap.native_roles.get(user_id, frozenset())
    if not native:
        return set(), 0

    delegated = _compute_delegated_roles_from_snap(snap, user_id, eval_ts)
    all_roles = frozenset(native | delegated)
    max_cl = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in all_roles), default=1)

    bounds = snap.window_boundaries
    if bounds:
        idx = bisect.bisect_right(bounds, eval_ts)
        v_from = bounds[idx - 1] if idx > 0 else INT64_MIN
        v_until = bounds[idx] if idx < len(bounds) else INT64_MAX
    else:
        v_from = INT64_MIN
        v_until = INT64_MAX

    if len(snap.perm_window_cache) >= _MAX_PERM_CACHE_PER_TENANT and user_id not in snap.perm_window_cache:
        snap.perm_window_cache.pop(next(iter(snap.perm_window_cache)), None)
    snap.perm_window_cache[user_id] = (v_from, v_until, all_roles, max_cl)
    return set(all_roles), max_cl


def _would_create_delegation_cycle(
    snap: TenantAuthSnapshot,
    grantor_user_id: str,
    grantee_user_id: str,
    delegated_role: str,
    starts_at: int,
    expires_at: int,
) -> bool:
    """检查新增 grantor -> grantee 委托边是否会在当前或重叠时间窗内构成有向借调环路。"""
    if grantor_user_id == grantee_user_id:
        return True
    stack = [grantor_user_id]
    visited = {grantor_user_id}
    while stack:
        curr = stack.pop()
        for edge in snap.delegations_by_grantee.get(curr, ()):
            if edge.delegated_role != delegated_role:
                continue
            # 若上游有效委托窗口与新窗口存在交集或处于未来有效状态，均纳入环路拓扑检测
            if edge.expires_at <= starts_at and edge.starts_at >= expires_at:
                pass
            up = edge.grantor_user_id
            if up == grantee_user_id:
                return True
            if up not in visited:
                visited.add(up)
                stack.append(up)
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
    if not grantor_user_id or not grantee_user_id:
        raise ValueError("grantor_user_id and grantee_user_id are required")
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")

    s_val = strict_int(starts_at, "starts_at")
    e_val = strict_int(expires_at, "expires_at")
    eval_ts = strict_int(now_ts, "now_ts") if now_ts is not None else int(time.time())

    with get_tenant_auth_lock(db_path, tenant_id):
        snap = get_tenant_auth_snapshot(db_path, tenant_id)
        u_grantor = snap.users.get(grantor_user_id)
        u_grantee = snap.users.get(grantee_user_id)
        if not u_grantor or not u_grantor.active or not u_grantee or not u_grantee.active:
            raise LookupError("Grantor or grantee not found in tenant")

        if action == "create":
            if e_val <= s_val:
                raise ValueError("expires_at must be greater than starts_at")
            if _would_create_delegation_cycle(
                snap,
                grantor_user_id,
                grantee_user_id,
                delegated_role,
                s_val,
                e_val,
            ):
                raise ValueError("Delegation cycle detected")

            grantor_native = snap.native_roles.get(grantor_user_id, frozenset())
            can_delegate = delegated_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = _collect_upstream_grantors_from_snap(
                    snap,
                    grantor_user_id,
                    delegated_role,
                    eval_ts,
                    0,
                    {grantor_user_id, grantee_user_id},
                )
                can_delegate = any(
                    hop == 1 and delegated_role in snap.native_roles.get(src_uid, frozenset())
                    for src_uid, hop in upstream
                )
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            conn = open_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role, s_val, e_val, eval_ts),
                )
                conn.commit()
                affected = 1
            finally:
                conn.close()
            bump_auth_epoch(db_path, tenant_id)
        elif action == "revoke":
            conn = open_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
                )
                affected = cur.rowcount
                conn.commit()
            finally:
                conn.close()
            bump_auth_epoch(db_path, tenant_id)
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
