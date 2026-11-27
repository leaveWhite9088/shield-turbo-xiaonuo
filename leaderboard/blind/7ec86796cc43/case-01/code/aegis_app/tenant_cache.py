# -*- coding: utf-8 -*-
"""租户级只读快照缓存层（组织/权限、隔离墙、借调委托、黑名单、策略、文档索引）。

所有缓存均遵循 **双失效条件**：

    1. **纪元失效**：本进程内的写路径推进对应业务域纪元后，缓存立即失效；
    2. **签名失效**：一次廉价聚合查询得到的结构指纹发生变化时缓存失效，
       用于感知绕过本进程写路径的外部数据库改动。

缓存内容全部为「只读快照 + 派生结构」，不含大体积正文，
常驻内存受租户数、实体数与文档索引预算三重约束。
"""
from __future__ import annotations

import sqlite3
from typing import Any

from .db import open_connection
from .doc_index import TenantDocIndex
from .state import (
    DOMAIN_ACL,
    DOMAIN_DELEG,
    DOMAIN_DOC,
    DOMAIN_ORG,
    DOMAIN_POLICY,
    DOMAIN_SANCTION,
    get_runtime_state,
)


def _scalar(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row is not None else 0


def load_org_snapshot(db_path: str, tenant_id: str) -> dict[str, Any]:
    """组织树 + 用户 + 显式角色授予 的租户级只读快照。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)

    def signature() -> tuple[int, int, int, int, int]:
        conn = open_connection(db_path)
        try:
            row = conn.execute(
                "SELECT (SELECT COUNT(*) FROM users WHERE tenant_id = ?), "
                "(SELECT COUNT(*) FROM org_nodes WHERE tenant_id = ?), "
                "(SELECT COUNT(*) FROM role_grants WHERE tenant_id = ?), "
                "(SELECT COALESCE(SUM(active), 0) FROM users WHERE tenant_id = ?), "
                "(SELECT COUNT(DISTINCT org_node_id) FROM users WHERE tenant_id = ?)",
                (tenant_id, tenant_id, tenant_id, tenant_id, tenant_id),
            ).fetchone()
            return (int(row[0]), int(row[1]), int(row[2]), int(row[3]), int(row[4]))
        finally:
            conn.close()

    def build() -> dict[str, Any]:
        conn = open_connection(db_path)
        try:
            users: dict[str, dict[str, Any]] = {}
            for row in conn.execute(
                "SELECT user_id, org_node_id, base_role, active FROM users WHERE tenant_id = ?",
                (tenant_id,),
            ):
                users[str(row["user_id"])] = {
                    "org_node_id": str(row["org_node_id"]),
                    "base_role": str(row["base_role"]),
                    "active": int(row["active"]) == 1,
                }
            nodes: dict[str, dict[str, Any]] = {}
            for row in conn.execute(
                "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
                (tenant_id,),
            ):
                nodes[str(row["node_id"])] = {
                    "parent": row["parent_node_id"],
                    "inherited": row["inherited_role"],
                }
            grants: dict[str, set[str]] = {}
            for row in conn.execute(
                "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ):
                grants.setdefault(str(row["user_id"]), set()).add(str(row["granted_role"]))
            return {"users": users, "nodes": nodes, "grants": grants}
        finally:
            conn.close()

    return tenant.cached_sig(DOMAIN_ORG, signature(), build)


def load_acl_rules(db_path: str, tenant_id: str) -> dict[str, list[tuple[str, str, str]]]:
    """隔离墙规则快照：doc_id -> [(subject_type, subject_id, effect)]。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)

    def signature() -> int:
        conn = open_connection(db_path)
        try:
            return _scalar(
                conn,
                "SELECT COUNT(*) FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            )
        finally:
            conn.close()

    def build() -> dict[str, list[tuple[str, str, str]]]:
        conn = open_connection(db_path)
        try:
            rules: dict[str, list[tuple[str, str, str]]] = {}
            for row in conn.execute(
                "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
                "WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ):
                rules.setdefault(str(row["doc_id"]), []).append(
                    (
                        str(row["subject_type"]),
                        str(row["subject_id"]),
                        str(row["effect"]).upper(),
                    )
                )
            return rules
        finally:
            conn.close()

    return tenant.cached_sig(DOMAIN_ACL, signature(), build)


def load_delegations(db_path: str, tenant_id: str) -> list[dict[str, Any]]:
    """借调委托快照（仅 active=1 的记录）。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)

    def signature() -> int:
        conn = open_connection(db_path)
        try:
            return _scalar(
                conn,
                "SELECT COUNT(*) FROM delegation_grants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            )
        finally:
            conn.close()

    def build() -> list[dict[str, Any]]:
        conn = open_connection(db_path)
        try:
            rows = conn.execute(
                "SELECT delegation_id, grantor_user_id, grantee_user_id, delegated_role, "
                "starts_at, expires_at, created_at FROM delegation_grants "
                "WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "delegation_id": int(r["delegation_id"]),
                    "grantor_user_id": str(r["grantor_user_id"]),
                    "grantee_user_id": str(r["grantee_user_id"]),
                    "delegated_role": str(r["delegated_role"]),
                    "starts_at": int(r["starts_at"]),
                    "expires_at": int(r["expires_at"]),
                    "created_at": int(r["created_at"]),
                }
                for r in rows
            ]
        finally:
            conn.close()

    return tenant.cached_sig(DOMAIN_DELEG, signature(), build)


def load_sanctioned_entities(db_path: str, tenant_id: str) -> set[str]:
    """活跃受制裁实体集合快照。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)

    def signature() -> int:
        conn = open_connection(db_path)
        try:
            return _scalar(
                conn,
                "SELECT COUNT(*) FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            )
        finally:
            conn.close()

    def build() -> set[str]:
        conn = open_connection(db_path)
        try:
            return {
                str(r["entity_id"])
                for r in conn.execute(
                    "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                    (tenant_id,),
                )
            }
        finally:
            conn.close()

    return tenant.cached_sig(DOMAIN_SANCTION, signature(), build)


def load_policy_snapshot(db_path: str, tenant_id: str) -> dict[str, Any]:
    """租户风控策略快照（以 policy_version 作为签名）。"""
    import json

    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)

    def signature() -> int:
        conn = open_connection(db_path)
        try:
            return _scalar(
                conn,
                "SELECT COALESCE(MAX(policy_version), 0) FROM tenant_policies WHERE tenant_id = ?",
                (tenant_id,),
            )
        finally:
            conn.close()

    def build() -> dict[str, Any]:
        conn = open_connection(db_path)
        try:
            row = conn.execute(
                "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, "
                "velocity_amount_cents, counterparty_fanout_limit, review_threshold, "
                "reject_threshold, custom_rules_json, updated_at "
                "FROM tenant_policies WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
            if not row:
                raise LookupError(f"Policy configuration missing for {tenant_id}")
            policy = dict(row)
            policy["custom_rules"] = json.loads(policy["custom_rules_json"])
            return policy
        finally:
            conn.close()

    return tenant.cached_sig(DOMAIN_POLICY, signature(), build)


def load_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex:
    """租户文档增量索引（可降级为流式扫描模式）。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)

    def signature() -> tuple[int, int]:
        conn = open_connection(db_path)
        try:
            row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(updated_at), 0) FROM compliance_docs "
                "WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
                (tenant_id,),
            ).fetchone()
            return (int(row[0]) if row else 0, int(row[1]) if row else 0)
        finally:
            conn.close()

    def build() -> TenantDocIndex:
        index = TenantDocIndex(tenant_id)
        conn = open_connection(db_path)
        try:
            index.build(conn)
        finally:
            conn.close()
        return index

    return tenant.cached_sig(DOMAIN_DOC, signature(), build)


def peek_doc_index(db_path: str, tenant_id: str) -> TenantDocIndex | None:
    """取出已缓存的文档索引对象（不触发重建），供写路径做增量更新。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)
    cached = tenant.peek(DOMAIN_DOC)
    if isinstance(cached, TenantDocIndex):
        return cached
    return None


def refresh_doc_index_signature(db_path: str, tenant_id: str, index: TenantDocIndex) -> None:
    """本进程写入文档后刷新索引签名，避免下次访问误判为外部改动而整体重建。"""
    state = get_runtime_state(db_path)
    tenant = state.tenant(tenant_id)
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(MAX(updated_at), 0) FROM compliance_docs "
            "WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
            (tenant_id,),
        ).fetchone()
        sig = (int(row[0]) if row else 0, int(row[1]) if row else 0)
    finally:
        conn.close()
    tenant.refresh_sig(DOMAIN_DOC, sig, index)
