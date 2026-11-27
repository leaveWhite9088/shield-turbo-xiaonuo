# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。

性能与安全改造要点：

* **委托链解析全程内存化**：委托记录、组织树与用户台账均为租户级只读快照，
  1~2 跳链路的窗口判定、源头撤权级联失效判定退化为内存图遍历；
* **有向环路免疫**：链路回溯深度硬性收敛在 ``MAX_DELEGATION_HOPS``(=2)，
  恶意构造的 A→B→A 环形委托既不会无限递归，也不会被当作有效授权；
* **上游窗口自然到期零写降级**：上游一级窗口到期后，下游二级受托资格
  自动失效，无需任何写操作（纯读取时点判定）。
"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection, write_transaction
from .state import DOMAIN_DELEG
from .tenant_cache import load_delegations, load_org_snapshot


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    snapshot = load_org_snapshot(db_path, tenant_id)
    user = snapshot["users"].get(user_id)
    if not user or not user["active"]:
        return set()

    roles: set[str] = {user["base_role"]}
    nodes = snapshot["nodes"]
    curr = user["org_node_id"]
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        node = nodes.get(curr)
        if not node:
            break
        inherited = node["inherited"]
        if inherited:
            roles.add(inherited)
        curr = node["parent"]

    roles.update(snapshot["grants"].get(user_id, set()))
    return roles


def _collect_upstream_grantors(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    depth: int = 0,
) -> list[tuple[str, int]]:
    """沿当前有效时间窗回溯指定角色的上游委托路径，返回 (上游委托人 user_id, 路径跳数) 列表。

    回溯深度硬性收敛在 ``MAX_DELEGATION_HOPS``：更深跳数在业务上永不生效，
    收敛深度同时消除了「环形委托导致无限递归」的拒绝服务面。
    """
    if depth >= MAX_DELEGATION_HOPS:
        return []

    delegations = load_delegations(db_path, tenant_id)
    if not delegations:
        return []

    org_users = load_org_snapshot(db_path, tenant_id)["users"]

    discovered: list[tuple[str, int]] = []
    seen_paths: set[tuple[str, int]] = set()

    def walk(current_grantee: str, current_depth: int, path: frozenset[str]) -> None:
        if current_depth >= MAX_DELEGATION_HOPS:
            return
        for row in delegations:
            if row["grantee_user_id"] != current_grantee:
                continue
            if row["delegated_role"] != role_name:
                continue
            if not (row["starts_at"] <= at_ts < row["expires_at"]):
                continue
            grantor = row["grantor_user_id"]
            grantor_user = org_users.get(grantor)
            if not grantor_user or not grantor_user["active"]:
                # 链路中间受托人已失效 -> 该段委托不再向下游传导。
                continue
            next_hop = current_depth + 1
            path_key = (grantor, next_hop)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            if grantor in path:
                # 环形委托免疫：禁止绕环重复授信。
                continue
            discovered.append((grantor, next_hop))
            walk(grantor, next_hop, path | {grantor})

    walk(grantee_user_id, depth, frozenset({grantee_user_id}))
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
    delegations = load_delegations(db_path, tenant_id)
    if not delegations:
        return set()

    candidate_roles = {
        row["delegated_role"]
        for row in delegations
        if row["grantee_user_id"] == grantee_user_id
        and row["starts_at"] <= at_ts < row["expires_at"]
    }
    if not candidate_roles:
        return set()

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
        with write_transaction(conn):
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
    finally:
        conn.close()

    # 借调纪元推进：仅失效借调域缓存，文档索引与隔离墙缓存不受牵连。
    from .state import get_runtime_state

    get_runtime_state(db_path).bump(tenant_id, DOMAIN_DELEG)

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
