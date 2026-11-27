# -*- coding: utf-8 -*-
"""跨部门角色临时借调委托（最多二级受控转借调）与有效期内级联资格核验。

相对 v3.0 初始版本：
* ``_collect_upstream_grantors`` 改为**按跳层 BFS + visited/根集合环路免疫 + 深度上限**，
  一次批量取数完成，链式递归/环路导致的栈溢出或死循环被消除；
* ``resolve_base_and_explicit_roles`` 采用单连接、批量 IN 查询与组织链指针缓存；
* 委托的有效性判定与原版逐条语义一致（每一段 active=1 且 starts_at<=ts<expires_at、中间人与
  源头均 active、源头当前实际持有该原生角色、1..MAX_DELEGATION_HOPS 跳内生效）。
"""
from __future__ import annotations

import time
from typing import Any, Iterable

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE
from .db import GatewayDB, open_connection

_BFS_BUDGET = 4096


def _resolve_roles(db: GatewayDB, tenant_id: str, user_id: str) -> set[str]:
    """原型角色 = 基础岗位 ∪ 组织树继承 ∪ 管理员显式授予（不含借调）。"""
    u_row = db.one(
        "SELECT org_node_id, base_role, active FROM users WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    )
    if not u_row or not int(u_row["active"]):
        return set()
    roles: set[str] = {u_row["base_role"]}
    parents: dict[str, str | None] = {}
    inherited: dict[str, str | None] = {}
    for r in db.rows("SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?", (tenant_id,)):
        parents[r["node_id"]] = r["parent_node_id"]
        inherited[r["node_id"]] = r["inherited_role"]
    curr = u_row["org_node_id"]
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        if curr not in parents:
            break
        role = inherited.get(curr)
        if role:
            roles.add(role)
        curr = parents.get(curr)
    for gr in db.rows(
        "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
        (tenant_id, user_id),
    ):
        roles.add(gr["granted_role"])
    return roles


def resolve_roles_cached(db: GatewayDB, tenant_id: str, user_id: str, perm_fp: bytes) -> set[str]:
    """原型角色缓存：键 (tenant, user)，指纹 = perm 维度纪元 + 共享缓存世代戳。"""
    shared = db.shared
    if shared is None:
        return _resolve_roles(db, tenant_id, user_id)
    key = (tenant_id, user_id)
    entry = shared.cred_cache.get(key)
    if entry is not None and entry[0] is perm_fp:
        return entry[1]
    roles = _resolve_roles(db, tenant_id, user_id)
    with shared.lock:
        if len(shared.cred_cache) >= 4096:
            for old in list(shared.cred_cache)[:1024]:
                shared.cred_cache.pop(old, None)
        shared.cred_cache[key] = (perm_fp, roles)
    return roles


def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str,
                                    *, db: GatewayDB | None = None) -> set[str]:
    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
    if db is None or db.path != db_path:
        tmp = GatewayDB(db_path)
        try:
            return _resolve_roles(tmp, tenant_id, user_id)
        finally:
            tmp.close_thread()
    return _resolve_roles(db, tenant_id, user_id)


def collect_upstream_grantors(
    db: GatewayDB,
    tenant_id: str,
    grantee_user_id: str,
    role_name: str,
    at_ts: int,
    *,
    max_hop: int | None = None,
) -> dict[str, int]:
    """沿当前有效时间窗回溯上游委托人，返回 ``{上游委托人: 最近跳数}``。

    * 仅在 BFS 的最短跳数首次发现时记录（与递归版“存在路径即命中”等价且更省）；
    * ``visited`` 集合同时包含自身与已展开节点 → 有向环路天然免疫；
    * 跳数超过 ``max_hop``（默认 MAX_DELEGATION_HOPS）或节点数超过预算即停止。
    """
    limit = MAX_DELEGATION_HOPS if max_hop is None else max_hop
    frontier = [grantee_user_id]
    visited: set[str] = {grantee_user_id}
    out: dict[str, int] = {}
    hop = 0
    while frontier and hop < limit:
        hop += 1
        if hop > limit:
            break
        marks = ",".join("?" for _ in frontier)
        rows = db.rows(
            "SELECT grantor_user_id, starts_at, expires_at, active FROM delegation_grants "
            f"WHERE tenant_id = ? AND delegated_role = ? AND grantee_user_id IN ({marks}) AND active = 1",
            tuple([tenant_id, role_name] + frontier),
        )
        candidates: list[str] = []
        for r in rows:
            s_ts = int(r["starts_at"])
            e_ts = int(r["expires_at"])
            if not (s_ts <= at_ts < e_ts):
                continue
            gid = str(r["grantor_user_id"])
            if gid not in candidates:
                candidates.append(gid)
        if not candidates:
            break
        marks = ",".join("?" for _ in candidates)
        alive = {
            r["user_id"]
            for r in db.rows(
                f"SELECT user_id, active FROM users WHERE tenant_id = ? AND user_id IN ({marks})",
                tuple([tenant_id] + candidates),
            )
            if int(r["active"]) == 1
        }
        next_frontier: list[str] = []
        for gid in candidates:
            if gid not in alive:
                continue
            if gid not in visited:
                visited.add(gid)
                out[gid] = hop
                next_frontier.append(gid)
            elif gid not in out and hop < out.get(gid, hop + 1):
                out[gid] = hop
        if len(visited) > _BFS_BUDGET:
            break
        frontier = next_frontier
    return out


def resolve_active_delegated_roles(
    db_path: str,
    tenant_id: str,
    grantee_user_id: str,
    at_ts: int,
    *,
    db: GatewayDB | None = None,
    perm_fp: bytes | None = None,
) -> set[str]:
    """查询 at_ts 时刻对受托人生效的临时借调角色（最多 MAX_DELEGATION_HOPS=2 跳传递）。

    级联有效性约束：
    1. 整条借调链路上每一段记录 active=1 且满足 starts_at <= at_ts < expires_at（上游一级窗口自然到期即降级，无需写库）；
    2. 链路中间受托人与源头委托人当前均 active=1，且源头委托人当前实际持有该原生角色；
    3. 源头撤权 / 上游撤销 / 跨过 expires_at 一律级联失效；超过 2 跳不再生效。
    """
    own = db is None or db.path != db_path
    work = db if not own else GatewayDB(db_path)
    d_rows = work.rows(
        "SELECT DISTINCT delegated_role, starts_at, expires_at FROM delegation_grants "
        "WHERE tenant_id = ? AND grantee_user_id = ? AND active = 1",
        (tenant_id, grantee_user_id),
    )
    candidate_roles = [
        str(dr["delegated_role"])
        for dr in d_rows
        if int(dr["starts_at"]) <= at_ts < int(dr["expires_at"])
    ]
    effective: set[str] = set()
    for role_name in dict.fromkeys(candidate_roles):
        upstream = collect_upstream_grantors(work, tenant_id, grantee_user_id, role_name, at_ts)
        for src_uid, hop_dist in upstream.items():
            if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
                if perm_fp is not None:
                    native = resolve_roles_cached(work, tenant_id, src_uid, perm_fp)
                else:
                    native = _resolve_roles(work, tenant_id, src_uid)
                if role_name in native:
                    effective.add(role_name)
                    break
    return effective


def create_or_revoke_delegation(
    db_path: str,
    tenant_id: str,
    actor_user_id: str,
    actor_roles: Iterable[str],
    *,
    grantor_user_id: str,
    grantee_user_id: str,
    delegated_role: str,
    starts_at: int,
    expires_at: int,
    action: str = "create",
    now_ts: int | None = None,
    db: GatewayDB | None = None,
) -> dict[str, Any]:
    """创建或撤销跨部门角色借调委托（原生持有人发起一级借调，有效一级受托人发起二级转借调）。"""
    actor_role_set = set(actor_roles)
    if delegated_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported delegated_role: {delegated_role}")
    if actor_user_id != grantor_user_id and "COMPLIANCE_ADMIN" not in actor_role_set:
        raise PermissionError("Only grantor or COMPLIANCE_ADMIN may manage delegation")
    if grantor_user_id == grantee_user_id:
        raise ValueError("Cannot delegate role to self")
    if action == "create" and expires_at <= starts_at:
        # 与原版一致：非法窗口先于授权核验被拒绝
        raise ValueError("expires_at must be greater than starts_at")

    eval_ts = int(now_ts if now_ts is not None else time.time())
    own = db is None or db.path != db_path
    work = db if not own else GatewayDB(db_path)

    def _tx(conn):
        u_check = conn.execute(
            "SELECT COUNT(*) AS cnt FROM users WHERE tenant_id = ? AND user_id IN (?, ?) AND active = 1",
            (tenant_id, grantor_user_id, grantee_user_id),
        ).fetchone()
        if not u_check or int(u_check["cnt"]) < 2:
            raise LookupError("Grantor or grantee not found in tenant")
        if action == "create":
            grantor_native = _resolve_roles(work, tenant_id, grantor_user_id)
            can_delegate = delegated_role in grantor_native
            if not can_delegate and MAX_DELEGATION_HOPS >= 2:
                upstream = collect_upstream_grantors(
                    work, tenant_id, grantor_user_id, delegated_role, eval_ts, max_hop=1,
                )
                can_delegate = any(
                    delegated_role in _resolve_roles(work, tenant_id, src_uid)
                    for src_uid, hop in upstream.items() if hop == 1
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
        return affected

    if own:
        conn = open_connection(db_path)
        work = GatewayDB(db_path)
        _attach_thread_conn(work, conn)
        try:
            affected = _tx(conn)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        affected = work.write(_tx)
        if work.shared is not None:
            work.shared.epoch.bump("perm")

    return {
        "tenant_id": tenant_id,
        "grantor_user_id": grantor_user_id,
        "grantee_user_id": grantee_user_id,
        "delegated_role": delegated_role,
        "action": action,
        "affected": affected,
    }


def _attach_thread_conn(db: GatewayDB, conn) -> None:
    """让独立调用方（不带网关共享实例）也能在事务内复用同一连接。"""
    db.attach(conn)
