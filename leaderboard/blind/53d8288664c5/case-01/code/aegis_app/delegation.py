# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。

性能与安全重构（级联失效语义 100% 零失真）：
- 原版沿上游链路逐节点逐条新建 SQLite 连接回溯，改为「租户静态组织图/用户档案
  纪元缓存 + 全量活跃借调边图（delegation 纪元）内存 DFS 回溯」，消除逐节点
  连接放大与整表反复扫描；
- 上游回溯带逐路径 visited 环路免疫与 MAX_DELEGATION_HOPS 深度截断（深度 > 2
  的中间节点对最终 1~2 跳资格判定无贡献，正常链路结果与原版分毫不差），彻底
  免疫委托有向环路造成的递归爆栈/死循环；
- create/revoke 事务提交后立即 bump delegation 纪元，保证后续读取零脏读；
- 上游窗口自然到期为纯读取时判定（零写降级）；源头撤权经 role_grants 纪元由
  授权管理写入方（auth.revoke_or_grant_role）级联失效。
"""
from __future__ import annotations

import time
from typing import Any

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import open_connection
from .epoch_cache import CACHE_MISS, EpochScopedCache, bump_epoch, epoch_token, load_tenant_static

_native_roles_cache = EpochScopedCache("native_roles", 8192)
_delegation_graph_cache = EpochScopedCache("delegation_graph", 256)


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。

    组织树/用户档案走静态纪元缓存；显式授予角色走 role_grants 纪元
    （由 auth.revoke_or_grant_role 写入方 bump 失效），撤权后立即零脏读。
    """
    db_key = str(db_path)
    token = epoch_token(db_path, "org", "users", "role_grants")
    key = (tenant_id, user_id)
    hit = _native_roles_cache.get(db_key, token, key)
    if hit is not CACHE_MISS:
        return set(hit)

    static = load_tenant_static(db_path, tenant_id)
    u_info = static["users"].get(user_id)
    if not u_info or u_info[0] != 1:
        roles: set[str] = set()
    else:
        roles = {u_info[2]}
        org_map = static["org"]
        curr = u_info[1]
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            node = org_map.get(curr)
            if not node:
                break
            if node[1]:
                roles.add(node[1])
            curr = node[0]
        conn = open_connection(db_path)
        try:
            g_rows = conn.execute(
                "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
                (tenant_id, user_id),
            ).fetchall()
        finally:
            conn.close()
        for gr in g_rows:
            roles.add(str(gr["granted_role"]))

    _native_roles_cache.put(db_key, token, key, tuple(sorted(roles)))
    return set(roles)


def _load_delegation_graph(db_path: str, tenant_id: str) -> dict[str, list[tuple[str, str, int, int]]]:
    """按 delegation 纪元缓存租户全部活跃借调边（grantee -> [(role, grantor, starts, expires)]）。"""
    db_key = str(db_path)
    token = epoch_token(db_path, "delegation")
    hit = _delegation_graph_cache.get(db_key, token, tenant_id)
    if hit is not CACHE_MISS:
        return hit

    conn = open_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
            "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    graph: dict[str, list[tuple[str, str, int, int]]] = {}
    for r in rows:
        graph.setdefault(str(r["grantee_user_id"]), []).append(
            (
                str(r["delegated_role"]),
                str(r["grantor_user_id"]),
                int(r["starts_at"]),
                int(r["expires_at"]),
            )
        )
    _delegation_graph_cache.put(db_key, token, tenant_id, graph)
    return graph


def _discover_upstream_holders(
    graph: dict[str, list[tuple[str, str, int, int]]],
    users: dict[str, tuple[int, Any, str]],
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
) -> dict[str, int]:
    """沿有效借调边回溯，返回 {上游用户: 最小跳数}（仅 1~MAX_DELEGATION_HOPS 跳）。

    每段边须窗口有效（starts_at <= at_ts < expires_at）且上游用户 active=1；
    带逐路径 visited 环路免疫与 walked 最小深度剪枝，委托有向环路绝不死循环。
    """
    discovered: dict[str, int] = {}
    walked: dict[str, int] = {}
    hop_cap = MAX_DELEGATION_HOPS

    def _walk(node: str, depth: int, path: frozenset) -> None:
        if depth >= hop_cap:
            return
        for edge_role, grantor, s_ts, e_ts in graph.get(node, ()):
            if edge_role != role_name or not (s_ts <= at_ts < e_ts):
                continue
            u_info = users.get(grantor)
            if not u_info or u_info[0] != 1:
                continue
            hop = depth + 1
            if hop < discovered.get(grantor, 1 << 30):
                discovered[grantor] = hop
            if grantor in path or hop >= walked.get(grantor, 1 << 30):
                continue
            walked[grantor] = hop
            _walk(grantor, hop, path | {grantor})

    _walk(grantee_user_id, 0, frozenset({grantee_user_id}))
    return discovered


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
) -> set[str]:
    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。

    级联有效性约束（与原版语义完全一致）：
    1. 整条借调链路上的每一段记录均须 active=1 且满足 starts_at <= at_ts < expires_at；
    2. 链路中间受托人与源头委托人当前均须 active=1，且源头委托人当前实际持有该原生角色；
    3. 一旦源头委托人被撤回角色、或上游一级委托被撤销/跨过 expires_at，下游受托
       资格自动级联失效；超过 2 跳不再生效。
    """
    graph = _load_delegation_graph(db_path, tenant_id)
    static = load_tenant_static(db_path, tenant_id)
    users = static["users"]

    candidate_roles = {
        edge_role
        for edge_role, _grantor, s_ts, e_ts in graph.get(grantee_user_id, ())
        if s_ts <= at_ts < e_ts
    }

    effective_delegated: set[str] = set()
    for role_name in sorted(candidate_roles):
        upstream_chain = _discover_upstream_holders(graph, users, grantee_user_id, role_name, at_ts)
        for src_uid, hop_dist in upstream_chain.items():
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS and role_name in resolve_base_and_explicit_roles(
                db_path, tenant_id, src_uid
            ):
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
            static = load_tenant_static(db_path, tenant_id)
            graph = _load_delegation_graph(db_path, tenant_id)
            grantor_native = resolve_base_and_explicit_roles(db_path, tenant_id, grantor_user_id)
            can_delegate = delegated_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = _discover_upstream_holders(
                    graph, static["users"], grantor_user_id, delegated_role, eval_ts
                )
                can_delegate = any(
                    hop == 1 and delegated_role in resolve_base_and_explicit_roles(db_path, tenant_id, src_uid)
                    for src_uid, hop in upstream.items()
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

    bump_epoch(db_path, "delegation")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }
