# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    conn = open_connection(db_path)
    try:
        u_row = conn.execute(
            "SELECT org_node_id, base_role, active FROM users WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        if not u_row or not u_row["active"]:
            return set()

        roles: set[str] = {u_row["base_role"]}
        curr = u_row["org_node_id"]
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            n_row = conn.execute(
                "SELECT parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                (tenant_id, curr),
            ).fetchone()
            if not n_row:
                break
            if n_row["inherited_role"]:
                roles.add(n_row["inherited_role"])
            curr = n_row["parent_node_id"]

        g_rows = conn.execute(
            "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        ).fetchall()
        for gr in g_rows:
            roles.add(gr["granted_role"])
        return roles
    finally:
        conn.close()


def _collect_upstream_grantors(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
) -> list[tuple[str, int]]:
    """沿当前有效时间窗回溯指定角色的上游委托路径，返回 (上游委托人 user_id, 路径跳数) 列表。"""
    conn = open_connection(db_path)
    try:
        d_rows = conn.execute(
            "SELECT grantor_user_id, starts_at, expires_at "
            "FROM delegation_grants "
            "WHERE tenant_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
            (tenant_id, grantee_user_id, role_name),
        ).fetchall()
        active_grantors: list[str] = []
        for dr in d_rows:
            s_ts = int(dr["starts_at"])
            e_ts = int(dr["expires_at"])
            if not (s_ts <= at_ts < e_ts):
                continue
            gid = str(dr["grantor_user_id"])
            u_row = conn.execute(
                "SELECT active FROM users WHERE tenant_id = ? AND user_id = ?",
                (tenant_id, gid),
            ).fetchone()
            if u_row and int(u_row["active"]) == 1:
                active_grantors.append(gid)
    finally:
        conn.close()

    discovered: list[tuple[str, int]] = []
    for gid in active_grantors:
        next_hop = depth + 1
        discovered.append((gid, next_hop))
        discovered.extend(
            _collect_upstream_grantors(
                db_path,
                tenant_id,
                gid,
                role_name,
                at_ts,
                next_hop,
            )
        )
    return discovered


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。

    级联有效性约束：
    1. 整条借调链路（1 跳直接委托或 2 跳转借调）上的每一段记录均须 active=1 且满足 starts_at <= at_ts < expires_at；
    2. 链路中间受托人与源头委托人当前均须 active=1，且源头委托人当前实际持有该原生角色；
    3. 一旦源头委托人被撤回角色、或上游一级委托被撤销/跨过 expires_at，下游受托资格自动级联失效；超过 2 跳不再生效。
    """
    conn = open_connection(db_path)
    try:
        d_rows = conn.execute(
            "SELECT DISTINCT delegated_role, starts_at, expires_at "
            "FROM delegation_grants "
            "WHERE tenant_id = ? AND grantee_user_id = ? AND active = 1",
            (tenant_id, grantee_user_id),
        ).fetchall()
    finally:
        conn.close()

    candidate_roles = {
        str(dr["delegated_role"])
        for dr in d_rows
        if int(dr["starts_at"]) <= at_ts < int(dr["expires_at"])
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
    conn = open_connection(db_path)
    try:
        u_check = conn.execute(
            "SELECT COUNT(*) AS cnt FROM users WHERE tenant_id = ? AND user_id IN (?, ?) AND active = 1",
            (tenant_id, grantor_user_id, grantee_user_id),
        ).fetchone()
        if not u_check or int(u_check["cnt"]) < 2:
            raise LookupError("Grantor or grantee not found in tenant")

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

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
