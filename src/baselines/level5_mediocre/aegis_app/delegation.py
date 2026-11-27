# -*- coding: utf-8 -*-
"""跨部门角色借调委托管理（5级平庸样本：每次鉴权递归新建连接，未防委托有向环路，变更未联动检索缓存失效）。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
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
            if int(dr["starts_at"]) <= at_ts < int(dr["expires_at"]):
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
            _collect_upstream_grantors(db_path, tenant_id, gid, role_name, at_ts, next_hop)
        )
    return discovered


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
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
        for src_uid, hop_dist in _collect_upstream_grantors(db_path, tenant_id, grantee_user_id, role_name, at_ts):
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                if role_name in resolve_base_and_explicit_roles(db_path, tenant_id, src_uid):
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
                upstream = _collect_upstream_grantors(db_path, tenant_id, grantor_user_id, delegated_role, eval_ts)
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
