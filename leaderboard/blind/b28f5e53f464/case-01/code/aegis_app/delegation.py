# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）、防环路检测与有效期内级联资格核验模块。"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .runtime import GatewayRuntime, get_runtime
from .validation import strict_int


def resolve_base_and_explicit_roles(
    db_path: str,
    tenant_id: str,
    user_id: str,
    *,
    runtime: GatewayRuntime | None = None,
) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    rt = runtime or get_runtime(db_path)
    return rt.get_perm_state(tenant_id).get_native_roles(user_id)


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
    *,
    runtime: GatewayRuntime | None = None,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递，免疫有向环路）。"""
    rt = runtime or get_runtime(db_path)
    return rt.get_perm_state(tenant_id).resolve_active_delegated_roles(grantee_user_id, int(at_ts))


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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """创建或撤销跨部门角色借调委托（支持原生持有人发起一级借调，或有效一级受托人发起二级转借调）。"""
    clean_grantor = str(grantor_user_id or "").strip()
    clean_grantee = str(grantee_user_id or "").strip()
    clean_role = str(delegated_role or "").strip()
    clean_action = str(action or "create").strip().lower()

    if clean_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {delegated_role}")
    if actor_user_id != clean_grantor and "COMPLIANCE_ADMIN" not in actor_roles:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if not clean_grantor or not clean_grantee:
        raise ValueError("grantor_user_id and grantee_user_id are required")
    if clean_grantor == clean_grantee:
        raise ValueError("Cannot delegate role to self")

    eval_ts = int(now_ts if now_ts is not None else time.time())
    rt = runtime or get_runtime(db_path)

    with rt.perm_lock(tenant_id):
        perm_state = rt.get_perm_state(tenant_id)
        u_grantor = perm_state.users.get(clean_grantor)
        u_grantee = perm_state.users.get(clean_grantee)
        if not u_grantor or u_grantor[3] != 1 or not u_grantee or u_grantee[3] != 1:
            raise LookupError("Grantor or grantee not found in tenant")

        if clean_action == "create":
            s_ts = strict_int(starts_at, "starts_at")
            e_ts = strict_int(expires_at, "expires_at")
            if e_ts <= s_ts:
                raise ValueError("expires_at must be greater than starts_at")

            grantor_native = perm_state.native_roles.get(clean_grantor, frozenset())
            can_delegate = clean_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                # 仅允许有效一级受托人发起二级转借调
                for src_uid, e_role, edge_s, edge_e in perm_state.delegations_by_grantee.get(clean_grantor, ()):
                    if e_role != clean_role or not (edge_s <= eval_ts < edge_e):
                        continue
                    src_info = perm_state.users.get(src_uid)
                    if src_info and src_info[3] == 1 and clean_role in perm_state.native_roles.get(src_uid, ()):
                        can_delegate = True
                        break
            if not can_delegate:
                raise PermissionError("Grantor does not possess delegatable role within hop limit")

            if perm_state.has_delegation_path(clean_grantee, clean_grantor, clean_role):
                raise ValueError("Delegation cycle detected")

            with rt.write_tx() as conn:
                conn.execute(
                    "INSERT INTO delegation_grants("
                    "tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, clean_grantor, clean_grantee, clean_role, s_ts, e_ts, eval_ts),
                )
            perm_state.delegations_by_grantee[clean_grantee].append(
                (clean_grantor, clean_role, s_ts, e_ts)
            )
            perm_state.perm_epoch += 1
            affected = 1
        elif clean_action == "revoke":
            with rt.write_tx() as conn:
                cur = conn.execute(
                    "UPDATE delegation_grants SET active = 0 "
                    "WHERE tenant_id = ? AND grantor_user_id = ? AND grantee_user_id = ? AND delegated_role = ? AND active = 1",
                    (tenant_id, clean_grantor, clean_grantee, clean_role),
                )
                affected = cur.rowcount
            old_edges = perm_state.delegations_by_grantee.get(clean_grantee)
            if old_edges:
                perm_state.delegations_by_grantee[clean_grantee] = [
                    edge
                    for edge in old_edges
                    if not (edge[0] == clean_grantor and edge[1] == clean_role)
                ]
            perm_state.perm_epoch += 1
        else:
            raise ValueError("action must be 'create' or 'revoke'")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": clean_grantor,
        "grantee_user_id": clean_grantee,
        "delegated_role": clean_role,
        "action": clean_action,
        "affected": affected,
    }
