# -*- coding: utf-8 -*-
"""有界、无环且支持上游自然失效的二级角色借调引擎。"""
from __future__ import annotations

from collections import deque
import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection
from .runtime import bounded_text, strict_int, tenant_write_lock


def _native_roles_conn(conn: Any, tenant_id: str, user_id: str, cache: dict[str, set[str]] | None = None) -> set[str]:
    if cache is not None and user_id in cache:
        return set(cache[user_id])
    row = conn.execute(
        "SELECT org_node_id, base_role, active FROM users WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    ).fetchone()
    if not row or not row["active"]:
        return set()
    roles = {str(row["base_role"])}
    current = row["org_node_id"]
    visited: set[str] = set()
    while current and current not in visited:
        visited.add(current)
        node = conn.execute(
            "SELECT parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
            (tenant_id, current),
        ).fetchone()
        if not node:
            break
        if node["inherited_role"]:
            roles.add(str(node["inherited_role"]))
        current = node["parent_node_id"]
    roles.update(
        str(grant["granted_role"])
        for grant in conn.execute(
            "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        )
    )
    if cache is not None:
        cache[user_id] = set(roles)
    return roles


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    conn = open_connection(db_path)
    try:
        return _native_roles_conn(conn, tenant_id, user_id)
    finally:
        conn.close()


def _user_active_conn(conn: Any, tenant_id: str, user_id: str, cache: dict[str, bool]) -> bool:
    if user_id not in cache:
        row = conn.execute(
            "SELECT active FROM users WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        cache[user_id] = bool(row and int(row["active"]) == 1)
    return cache[user_id]


def _active_delegated_conn(conn: Any, tenant_id: str, grantee_user_id: str, at_ts: int) -> set[str]:
    rows = conn.execute(
        "SELECT DISTINCT delegated_role, starts_at, expires_at FROM delegation_grants "
        "WHERE tenant_id = ? AND grantee_user_id = ? AND active = 1",
        (tenant_id, grantee_user_id),
    ).fetchall()
    candidates = {
        str(row["delegated_role"]) for row in rows
        if int(row["starts_at"]) <= at_ts < int(row["expires_at"])
    }
    native_cache: dict[str, set[str]] = {}
    active_cache: dict[str, bool] = {}
    effective: set[str] = set()
    for role_name in candidates:
        queue: deque[tuple[str, int]] = deque([(grantee_user_id, 0)])
        best_depth = {grantee_user_id: 0}
        while queue:
            current, depth = queue.popleft()
            if depth >= MAX_DELEGATION_HOPS:
                continue
            upstream = conn.execute(
                "SELECT grantor_user_id, starts_at, expires_at FROM delegation_grants "
                "WHERE tenant_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                (tenant_id, current, role_name),
            )
            for edge in upstream:
                if not (int(edge["starts_at"]) <= at_ts < int(edge["expires_at"])):
                    continue
                grantor = str(edge["grantor_user_id"])
                next_depth = depth + 1
                if not _user_active_conn(conn, tenant_id, grantor, active_cache):
                    continue
                if role_name in _native_roles_conn(conn, tenant_id, grantor, native_cache):
                    effective.add(role_name)
                    queue.clear()
                    break
                if next_depth < MAX_DELEGATION_HOPS and next_depth < best_depth.get(grantor, 99):
                    best_depth[grantor] = next_depth
                    queue.append((grantor, next_depth))
    return effective


def resolve_active_delegated_roles(db_path: str, tenant_id: str, grantee_user_id: str, at_ts: int) -> set[str]:
    conn = open_connection(db_path)
    try:
        return _active_delegated_conn(conn, tenant_id, grantee_user_id, at_ts)
    finally:
        conn.close()


def resolve_permissions_conn(conn: Any, tenant_id: str, user_id: str, at_ts: int) -> tuple[set[str], int]:
    native_cache: dict[str, set[str]] = {}
    roles = _native_roles_conn(conn, tenant_id, user_id, native_cache)
    if not roles:
        return set(), 0
    delegated = _active_delegated_conn(conn, tenant_id, user_id, at_ts)
    all_roles = roles | delegated
    clearance = max((ROLE_DEFAULT_CLEARANCE.get(role, 1) for role in all_roles), default=1)
    return all_roles, clearance


def _would_create_cycle(rows: list[Any], grantor: str, grantee: str) -> bool:
    adjacency: dict[str, list[str]] = {}
    for row in rows:
        adjacency.setdefault(str(row["grantor_user_id"]), []).append(str(row["grantee_user_id"]))
    adjacency.setdefault(grantor, []).append(grantee)
    stack = [grantee]
    visited: set[str] = set()
    while stack:
        current = stack.pop()
        if current == grantor:
            return True
        if current in visited:
            continue
        visited.add(current)
        if len(visited) > 4096:
            raise ValueError("Delegation graph exceeds safety budget")
        stack.extend(adjacency.get(current, ()))
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
    if delegated_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {delegated_role}")
    if actor_user_id != grantor_user_id and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    grantor_user_id = bounded_text(grantor_user_id, "grantor_user_id", 128)
    grantee_user_id = bounded_text(grantee_user_id, "grantee_user_id", 128)
    starts_at = strict_int(starts_at, "starts_at")
    expires_at = strict_int(expires_at, "expires_at")
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")
    eval_ts = int(now_ts if now_ts is not None else time.time())

    with tenant_write_lock(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            users = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id IN (?, ?) AND active = 1",
                (tenant_id, grantor_user_id, grantee_user_id),
            ).fetchall()
            if len({row["user_id"] for row in users}) != 2:
                raise LookupError("Grantor or grantee not found")
            if action == "create":
                if expires_at <= starts_at:
                    raise ValueError("expires_at must be greater than starts_at")
                native_cache: dict[str, set[str]] = {}
                can_delegate = delegated_role in _native_roles_conn(conn, tenant_id, grantor_user_id, native_cache)
                if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                    # 只有当前有效的一级受托人可转借调；绝不接受二级再向下扩散。
                    direct = conn.execute(
                        "SELECT grantor_user_id FROM delegation_grants WHERE tenant_id = ? AND grantee_user_id = ? "
                        "AND delegated_role = ? AND active = 1 AND starts_at <= ? AND expires_at > ?",
                        (tenant_id, grantor_user_id, delegated_role, eval_ts, eval_ts),
                    )
                    can_delegate = any(
                        delegated_role in _native_roles_conn(conn, tenant_id, str(row["grantor_user_id"]), native_cache)
                        for row in direct
                    )
                if not can_delegate:
                    raise PermissionError("Grantor does not possess delegatable role within hop limit")
                graph_rows = conn.execute(
                    "SELECT grantor_user_id, grantee_user_id FROM delegation_grants WHERE tenant_id = ? AND active = 1",
                    (tenant_id,),
                ).fetchall()
                if _would_create_cycle(graph_rows, grantor_user_id, grantee_user_id):
                    raise ValueError("Delegation would create a directed cycle")
                conn.execute(
                    "INSERT INTO delegation_grants(tenant_id, grantor_user_id, grantee_user_id, delegated_role, "
                    "starts_at, expires_at, active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, eval_ts),
                )
                affected = 1
            elif action == "revoke":
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 WHERE tenant_id = ? AND grantor_user_id = ? "
                    "AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
                )
                affected = cur.rowcount
            else:
                raise ValueError("action must be 'create' or 'revoke'")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    return {
        "tenant_id": tenant_id, "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id, "delegated_role": delegated_role,
        "action": action, "affected": affected,
    }
