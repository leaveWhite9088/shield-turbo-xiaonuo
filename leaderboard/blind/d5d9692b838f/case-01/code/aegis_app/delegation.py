# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）、有向环路免疫与多维权限快照模块。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, MAX_SAFE_TS, ROLE_DEFAULT_CLEARANCE
from .db import borrow_connection, get_db_hub, write_transaction
from .middleware import strict_int


class UserAuthRecord:
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


class TenantPermSnapshot:
    """与 perm_epoch 绑定的租户组织树、原生角色与借调有向图内存快照。"""

    __slots__ = (
        "epoch",
        "users",
        "org_lineage",
        "native_roles",
        "by_grantee",
        "by_grantor",
    )

    def __init__(
        self,
        epoch: int,
        users: dict[str, UserAuthRecord],
        org_lineage: dict[str, tuple[str, ...]],
        native_roles: dict[str, frozenset[str]],
        by_grantee: dict[str, tuple[DelegationEdge, ...]],
        by_grantor: dict[str, tuple[DelegationEdge, ...]],
    ) -> None:
        self.epoch = epoch
        self.users = users
        self.org_lineage = org_lineage
        self.native_roles = native_roles
        self.by_grantee = by_grantee
        self.by_grantor = by_grantor

    def resolve_delegated_roles_at(self, grantee_user_id: str, at_ts: int) -> set[str]:
        """在内存中执行环路免疫的有界跳数（<= MAX_DELEGATION_HOPS）时效借调核验。

        上游窗口自然跨过 expires_at 时在读路径零写自动降级；源头撤权通过 perm_epoch 即时级联失效。
        """
        in_edges = self.by_grantee.get(grantee_user_id)
        if not in_edges:
            return set()

        effective: set[str] = set()
        # 按受托角色聚合同刻活跃入边，执行带路径去重的有界深度逆向搜索
        candidate_roles = {
            e.role for e in in_edges if e.starts_at <= at_ts < e.expires_at
        }
        for role_name in candidate_roles:
            # 栈元素: (当前节点 uid, 已走跳数 hop, 当前路径已访问集合)
            stack: list[tuple[str, int, frozenset[str]]] = [
                (grantee_user_id, 0, frozenset({grantee_user_id}))
            ]
            while stack:
                curr_uid, hop, path_seen = stack.pop()
                if hop >= MAX_DELEGATION_HOPS:
                    continue
                for edge in self.by_grantee.get(curr_uid, ()):
                    if edge.role != role_name or not (edge.starts_at <= at_ts < edge.expires_at):
                        continue
                    gid = edge.grantor_id
                    if gid in path_seen:
                        continue
                    src_native = self.native_roles.get(gid)
                    if src_native is None:
                        # 中间或源头操作员非活跃（active != 1），链路阻断
                        continue
                    next_hop = hop + 1
                    if role_name in src_native:
                        effective.add(role_name)
                        stack.clear()
                        break
                    if next_hop < MAX_DELEGATION_HOPS:
                        stack.append((gid, next_hop, path_seen | {gid}))
        return effective

    def has_overlapping_cycle(
        self,
        grantor_id: str,
        grantee_id: str,
        role_name: str,
        starts_at: int,
        expires_at: int,
    ) -> bool:
        """检测新增 grantor_id -> grantee_id 边是否在重叠时间窗内形成有向委托环路。"""
        if grantor_id == grantee_id:
            return True
        visited: set[str] = {grantee_id}
        queue: list[str] = [grantee_id]
        idx = 0
        while idx < len(queue):
            curr = queue[idx]
            idx += 1
            for edge in self.by_grantor.get(curr, ()):
                if edge.role != role_name:
                    continue
                if max(edge.starts_at, starts_at) >= min(edge.expires_at, expires_at):
                    continue
                nxt = edge.grantee_id
                if nxt == grantor_id:
                    return True
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        return False


def get_perm_snapshot(db_path: str, tenant_id: str) -> TenantPermSnapshot:
    hub = get_db_hub(db_path)
    target_ep = hub.get_epochs(tenant_id).perm_epoch
    cached: TenantPermSnapshot | None = hub.perm_snapshots.get(tenant_id)
    if cached is not None and cached.epoch == target_ep:
        return cached

    with hub.tenant_meta_lock(tenant_id):
        target_ep = hub.get_epochs(tenant_id).perm_epoch
        cached = hub.perm_snapshots.get(tenant_id)
        if cached is not None and cached.epoch == target_ep:
            return cached

        with borrow_connection(db_path) as conn:
            org_rows = conn.execute(
                "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            user_rows = conn.execute(
                "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
                "FROM users WHERE tenant_id = ?",
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

        org_map: dict[str, tuple[str | None, str | None]] = {
            str(r["node_id"]): (
                str(r["parent_node_id"]) if r["parent_node_id"] else None,
                str(r["inherited_role"]) if r["inherited_role"] else None,
            )
            for r in org_rows
        }

        org_lineage: dict[str, tuple[str, ...]] = {}
        org_inherited_roles: dict[str, set[str]] = {}
        for node_id in org_map:
            chain: list[str] = []
            inh_roles: set[str] = set()
            curr: str | None = node_id
            seen_nodes: set[str] = set()
            while curr and curr not in seen_nodes:
                seen_nodes.add(curr)
                chain.append(curr)
                info = org_map.get(curr)
                if info is None:
                    break
                parent_id, inh_role = info
                if inh_role:
                    inh_roles.add(inh_role)
                curr = parent_id
            org_lineage[node_id] = tuple(chain)
            org_inherited_roles[node_id] = inh_roles

        explicit_by_user: dict[str, set[str]] = {}
        for gr in grant_rows:
            explicit_by_user.setdefault(str(gr["user_id"]), set()).add(str(gr["granted_role"]))

        users: dict[str, UserAuthRecord] = {}
        native_roles: dict[str, frozenset[str]] = {}
        for ur in user_rows:
            uid = str(ur["user_id"])
            is_act = int(ur["active"]) == 1
            rec = UserAuthRecord(
                user_id=uid,
                username=str(ur["username"]),
                org_node_id=str(ur["org_node_id"]),
                base_role=str(ur["base_role"]),
                api_token_hash=str(ur["api_token_hash"]),
                active=is_act,
            )
            users[uid] = rec
            if rec.org_node_id not in org_lineage:
                org_lineage[rec.org_node_id] = (rec.org_node_id,)
            if is_act:
                rset: set[str] = {rec.base_role}
                rset.update(org_inherited_roles.get(rec.org_node_id, ()))
                rset.update(explicit_by_user.get(uid, ()))
                native_roles[uid] = frozenset(rset)

        grantee_tmp: dict[str, list[DelegationEdge]] = {}
        grantor_tmp: dict[str, list[DelegationEdge]] = {}
        for dr in del_rows:
            edge = DelegationEdge(
                grantor_id=str(dr["grantor_user_id"]),
                grantee_id=str(dr["grantee_user_id"]),
                role=str(dr["delegated_role"]),
                starts_at=int(dr["starts_at"]),
                expires_at=int(dr["expires_at"]),
            )
            grantee_tmp.setdefault(edge.grantee_id, []).append(edge)
            grantor_tmp.setdefault(edge.grantor_id, []).append(edge)

        snap = TenantPermSnapshot(
            epoch=target_ep,
            users=users,
            org_lineage=org_lineage,
            native_roles=native_roles,
            by_grantee={k: tuple(v) for k, v in grantee_tmp.items()},
            by_grantor={k: tuple(v) for k, v in grantor_tmp.items()},
        )
        if users:
            hub.perm_snapshots.set(tenant_id, snap)
        return snap


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    snap = get_perm_snapshot(db_path, tenant_id)
    roles = snap.native_roles.get(user_id)
    return set(roles) if roles is not None else set()


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。"""
    snap = get_perm_snapshot(db_path, tenant_id)
    return snap.resolve_delegated_roles_at(grantee_user_id, int(at_ts))


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
    """创建或撤销跨部门角色借调委托（支持二级转借调，拦截有向环路与非法数值边界）。"""
    grantor_uid = str(grantor_user_id or "").strip()
    grantee_uid = str(grantee_user_id or "").strip()
    role_str = str(delegated_role or "").strip()
    act_str = str(action or "create").strip()

    if not grantor_uid or not grantee_uid or len(grantor_uid) > 128 or len(grantee_uid) > 128:
        raise ValueError("Valid grantor_user_id and grantee_user_id are required")
    if role_str not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {role_str}")
    if actor_user_id != grantor_uid and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if grantor_uid == grantee_uid:
        raise ValueError("Cannot delegate role to self")
    if act_str not in ("create", "revoke"):
        raise ValueError("action must be 'create' or 'revoke'")

    eval_ts = (
        strict_int(now_ts, "now_ts", min_val=0, max_val=MAX_SAFE_TS)
        if now_ts is not None
        else int(time.time())
    )

    hub = get_db_hub(db_path)
    with hub.tenant_meta_lock(tenant_id):
        snap = get_perm_snapshot(db_path, tenant_id)
        if grantor_uid not in snap.native_roles or grantee_uid not in snap.native_roles:
            raise LookupError("Grantor or grantee not found in tenant")

        if act_str == "create":
            s_ts = strict_int(starts_at, "starts_at", min_val=0, max_val=MAX_SAFE_TS)
            e_ts = strict_int(expires_at, "expires_at", min_val=1, max_val=MAX_SAFE_TS)
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")

            if snap.has_overlapping_cycle(grantor_uid, grantee_uid, role_str, s_ts, e_ts):
                raise ValueError("Delegation cycle detected in overlapping window")

            grantor_native = snap.native_roles.get(grantor_uid, frozenset())
            can_delegate = role_str in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                for edge in snap.by_grantee.get(grantor_uid, ()):
                    if (
                        edge.role == role_str
                        and edge.starts_at <= eval_ts < edge.expires_at
                        and edge.grantor_id != grantor_uid
                        and role_str in snap.native_roles.get(edge.grantor_id, frozenset())
                    ):
                        can_delegate = True
                        break
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            with write_transaction(db_path) as conn:
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, grantor_uid, grantee_uid, role_str, s_ts, e_ts, eval_ts),
                )
            affected = 1
        else:
            with write_transaction(db_path) as conn:
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, grantor_uid, grantee_uid, role_str),
                )
                affected = cur.rowcount

        hub.bump_perm_epoch(tenant_id)

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_uid,
        "grantee_user_id": grantee_uid,
        "delegated_role": role_str,
        "action": act_str,
        "affected": affected,
    }
