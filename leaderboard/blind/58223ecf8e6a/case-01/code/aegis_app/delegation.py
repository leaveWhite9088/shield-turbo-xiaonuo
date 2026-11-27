# -*- coding: utf-8 -*-
"""有界二级角色借调、原生角色缓存与窗口/撤权级联失效。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection
from .runtime import RUNTIME, db_key
from .security import strict_int


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """返回岗位、组织继承与显式授予角色；按认证纪元缓存小型角色集合。"""
    key = (db_key(db_path), tenant_id, user_id)
    epoch = RUNTIME.epoch(db_path, tenant_id, "auth")
    cached = RUNTIME.base_roles.get(key, epoch)
    if cached is not None:
        return set(cached)

    conn = open_connection(db_path)
    try:
        user = conn.execute(
            "SELECT org_node_id, base_role, active FROM users WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        if not user or not user["active"]:
            roles: set[str] = set()
        else:
            roles = {str(user["base_role"])}
            current = user["org_node_id"]
            visited: set[str] = set()
            while current and current not in visited and len(visited) < 64:
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
            rows = conn.execute(
                "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
                (tenant_id, user_id),
            ).fetchall()
            roles.update(str(row["granted_role"]) for row in rows)
    finally:
        conn.close()
    frozen = frozenset(roles)
    RUNTIME.base_roles.put(key, epoch, frozen)
    return set(roles)


def _tenant_delegation_snapshot(db_path: str, tenant_id: str) -> tuple[tuple[Any, ...], ...]:
    """每认证纪元读取一次委托边与活跃用户，自然过期由每次请求实时判断。"""
    key = (db_key(db_path), tenant_id, "delegations")
    epoch = RUNTIME.epoch(db_path, tenant_id, "auth")
    cached = RUNTIME.delegations.get(key, epoch)
    if cached is not None:
        return cached
    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT delegation_id, grantor_user_id, grantee_user_id, delegated_role, "
            "starts_at, expires_at, active FROM delegation_grants WHERE tenant_id = ? "
            "ORDER BY delegation_id ASC LIMIT 10000",
            (tenant_id,),
        ).fetchall()
        users = conn.execute(
            "SELECT user_id FROM users WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()
    edges = tuple(
        (
            int(row["delegation_id"]), str(row["grantor_user_id"]), str(row["grantee_user_id"]),
            str(row["delegated_role"]), int(row["starts_at"]), int(row["expires_at"]),
            bool(row["active"]),
        )
        for row in rows
    )
    snapshot = (edges, frozenset(str(row["user_id"]) for row in users))
    RUNTIME.delegations.put(key, epoch, snapshot)
    return snapshot


def _valid_edge(edge: tuple[Any, ...], role: str, grantee: str, at_ts: int) -> bool:
    return (
        edge[6] and edge[2] == grantee and edge[3] == role
        and edge[4] <= at_ts < edge[5]
    )


def _has_native_source(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    *,
    exact_hops: int | None = None,
) -> bool:
    """沿 grantee <- grantor 回溯最多两层； visited 免疫任意有向环。"""
    edges, active_users = _tenant_delegation_snapshot(db_path, tenant_id)
    stack: list[tuple[str, int]] = [(grantee_user_id, 0)]
    visited: set[tuple[str, int]] = set()
    while stack:
        current, depth = stack.pop()
        if depth >= MAX_DELEGATION_HOPS or (current, depth) in visited:
            continue
        visited.add((current, depth))
        for edge in edges:
            if not _valid_edge(edge, role_name, current, at_ts):
                continue
            grantor = edge[1]
            next_depth = depth + 1
            if grantor not in active_users:
                continue
            if (exact_hops is None or exact_hops == next_depth) and role_name in resolve_base_and_explicit_roles(
                db_path, tenant_id, grantor
            ):
                return True
            if next_depth < MAX_DELEGATION_HOPS:
                stack.append((grantor, next_depth))
    return False


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """仅认可全链 active、秒级窗口有效且源头仍原生持有角色的 1/2 跳借调。"""
    edges, active_users = _tenant_delegation_snapshot(db_path, tenant_id)
    if grantee_user_id not in active_users:
        return set()
    candidates = {
        edge[3] for edge in edges
        if _valid_edge(edge, edge[3], grantee_user_id, at_ts)
    }
    return {
        role for role in candidates
        if _has_native_source(db_path, tenant_id, grantee_user_id, role, at_ts)
    }


def _would_create_cycle(
    edges: tuple[Any, ...], grantor: str, grantee: str, role: str,
) -> bool:
    """委托方向为 grantor -> grantee；若 grantee 已可达 grantor 则拒绝新环。"""
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        if edge[6] and edge[3] == role:
            adjacency.setdefault(edge[1], []).append(edge[2])
    stack = [grantee]
    visited: set[str] = set()
    while stack and len(visited) < 10000:
        node = stack.pop()
        if node == grantor:
            return True
        if node in visited:
            continue
        visited.add(node)
        stack.extend(adjacency.get(node, ()))
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
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")
    starts_at = strict_int(starts_at, "starts_at")
    expires_at = strict_int(expires_at, "expires_at")
    eval_ts = strict_int(now_ts if now_ts is not None else int(time.time()), "now_ts")

    with RUNTIME.tenant_write(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            users = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id IN (?, ?) AND active = 1",
                (tenant_id, grantor_user_id, grantee_user_id),
            ).fetchall()
            if len(users) < 2:
                raise LookupError("Grantor or grantee not found in tenant")

            if action == "create":
                if expires_at <= starts_at:
                    raise ValueError("expires_at must be greater than starts_at")
                native = resolve_base_and_explicit_roles(db_path, tenant_id, grantor_user_id)
                can_delegate = delegated_role in native
                if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                    can_delegate = _has_native_source(
                        db_path, tenant_id, grantor_user_id, delegated_role, eval_ts, exact_hops=1,
                    )
                if not can_delegate:
                    raise PermissionError("Grantor does not possess delegatable role within hop limit")
                edges, _ = _tenant_delegation_snapshot(db_path, tenant_id)
                if _would_create_cycle(edges, grantor_user_id, grantee_user_id, delegated_role):
                    raise ValueError("Delegation would create a directed cycle")
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, eval_ts),
                )
                affected = 1
            elif action == "revoke":
                cursor = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, grantor_user_id, grantee_user_id, delegated_role),
                )
                affected = cursor.rowcount
            else:
                raise ValueError("action must be 'create' or 'revoke'")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        RUNTIME.bump(db_path, tenant_id, "auth")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
