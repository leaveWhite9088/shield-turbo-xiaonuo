# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。

性能契约：委托行按 delegation 纪元缓存，链路回溯为纯内存运算；递归深度硬上限
MAX_DELEGATION_HOPS（仅 1..2 跳可生效，更深回溯纯浪费）并带 visited 环路防护，
有向委托环路毫秒级免疫，绝不无限递归。
级联有效性约束（与原版语义逐位一致）：
1. 整条借调链路每一段均须 active=1 且满足 starts_at <= at_ts < expires_at；
2. 链路中间受托人与源头委托人当前均须 active=1，且源头委托人当前实际持有该原生角色；
3. 源头撤权 / 上游撤销 / 窗口自然到期即时级联失效下游。
"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection
from .index_cache import get_state


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    users = tstate.users(db_path)
    u_row = users.get(user_id)
    if not u_row or not u_row["active"]:
        return set()

    tree = tstate.org_tree(db_path)
    roles: set[str] = {u_row["base_role"]}
    curr = u_row["org_node_id"]
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        node = tree.get(curr)
        if not node:
            break
        inherited = node[1]
        if inherited:
            roles.add(inherited)
        curr = node[0]

    grants = tstate.role_grants(db_path)
    roles |= grants.get(user_id, set())
    return roles


def _collect_upstream_grantors(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
    visited: set[str] | None = None,
) -> list[tuple[str, int]]:
    """沿当前有效时间窗回溯指定角色的上游委托路径，返回 (上游委托人 user_id, 路径跳数) 列表。

    深度硬上限 + visited 环路防护：委托环路（如 A 委托 B、B 委托 A）不会造成
    无限递归，超过 MAX_DELEGATION_HOPS 的链段对本就无效，直接剪枝。
    """
    if depth >= MAX_DELEGATION_HOPS:
        return []
    if visited is None:
        visited = {grantee_user_id}
    elif grantee_user_id in visited:
        return []
    visited.add(grantee_user_id)

    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    users = tstate.users(db_path)
    delegations = tstate.delegations(db_path)

    discovered: list[tuple[str, int]] = []
    for grantor, g_grantee, g_role, starts_at, expires_at in delegations:
        if g_grantee != grantee_user_id or g_role != role_name:
            continue
        if not (starts_at <= at_ts < expires_at):
            continue
        u_row = users.get(grantor)
        if not u_row or not u_row["active"]:
            continue
        next_hop = depth + 1
        discovered.append((grantor, next_hop))
        discovered.extend(
            _collect_upstream_grantors(
                db_path,
                tenant_id,
                grantor,
                role_name,
                at_ts,
                next_hop,
                visited,
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
    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    delegations = tstate.delegations(db_path)

    candidate_roles = {
        role
        for _grantor, g_grantee, role, starts_at, expires_at in delegations
        if g_grantee == grantee_user_id and starts_at <= at_ts < expires_at
    }

    effective_delegated: set[str] = set()
    for role_name in candidate_roles:
        upstream_chain = _collect_upstream_grantors(
            db_path,
            tenant_id,
            grantee_user_id,
            role_name,
            at_ts,
        )
        for src_uid, hop_dist in upstream_chain:
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                src_native = resolve_base_and_explicit_roles(db_path, tenant_id, src_uid)
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
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")

    eval_ts = int(now_ts if now_ts is not None else time.time())
    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    users = tstate.users(db_path)
    if grantor_user_id not in users or not users[grantor_user_id]["active"]:
        raise LookupError("Grantor or grantee not found in tenant")
    if grantee_user_id not in users or not users[grantee_user_id]["active"]:
        raise LookupError("Grantor or grantee not found in tenant")

    conn = open_connection(db_path)
    try:
        if action == "create":
            if expires_at <= starts_at:
                raise ValueError("expires_at must be greater than starts_at")
            grantor_native = resolve_base_and_explicit_roles(db_path, tenant_id, grantor_user_id)
            can_delegate = delegated_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = _collect_upstream_grantors(
                    db_path,
                    tenant_id,
                    grantor_user_id,
                    delegated_role,
                    eval_ts,
                )
                can_delegate = any(
                    hop == 1 and delegated_role in resolve_base_and_explicit_roles(db_path, tenant_id, src_uid)
                    for src_uid, hop in upstream
                )
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")
            conn.execute(
                "INSERT INTO delegation_grants("
                "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (tenant_id, grantor_user_id, grantee_user_id, delegated_role, int(starts_at), int(expires_at), eval_ts),
            )
            affected = 1
        elif action == "revoke":
            cur = conn.execute(
                "UPDATE delegation_grants SET active = 0 "
                "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
            )
            affected = cur.rowcount
        else:
            raise ValueError("action must be 'create' or 'revoke'")
        conn.commit()
    finally:
        conn.close()

    tstate.bump_delegations()

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
