# -*- coding: utf-8 -*-
"""租户身份认证、组织层级权限汇总、利益冲突隔离墙核验与配额/回调管理模块。"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any

from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import get_pooled_connection, hash_api_token
from .runtime import ConflictError, get_runtime


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class CallerContext:
    tenant_id: str
    user_id: str
    username: str
    org_node_id: str
    effective_roles: set[str]
    max_clearance: int
    org_ancestors: tuple[str, ...] = field(default_factory=tuple)


def _resolve_org_ancestors_with_conn(
    conn: sqlite3.Connection,
    tenant_id: str,
    start_node_id: str,
) -> list[str]:
    """在既有连接上沿组织架构树向上遍历，返回当前部门及所有上级部门节点 ID 列表。"""
    ancestors: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        ancestors.append(curr)
        row = conn.execute(
            "SELECT parent_node_id FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
            (tenant_id, curr),
        ).fetchone()
        curr = row["parent_node_id"] if row else None
    return ancestors


def resolve_org_ancestors(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """沿组织架构树向上遍历，返回当前部门及所有上级部门节点 ID 列表。"""
    conn = get_pooled_connection(db_path)
    return _resolve_org_ancestors_with_conn(conn, tenant_id, start_node_id)


def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """检查目标文档是否对指定用户或其所属组织层级链设置了利益冲突隔离墙（DENY）。"""
    conn = get_pooled_connection(db_path)
    u_row = conn.execute(
        "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    ).fetchone()
    if not u_row:
        return True
    org_chain = set(_resolve_org_ancestors_with_conn(conn, tenant_id, u_row["org_node_id"]))
    acl_rows = conn.execute(
        "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
        "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
        (tenant_id, doc_id),
    ).fetchall()
    for r in acl_rows:
        if r["effect"] != "DENY":
            continue
        if r["subject_type"] == "USER" and r["subject_id"] == user_id:
            return True
        if r["subject_type"] == "ORG_NODE" and r["subject_id"] in org_chain:
            return True
    return False


def configure_doc_acl_rule(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员新增或解除文档利益冲突隔离墙规则（Chinese Wall），并立即失效文档缓存。"""
    require_admin(caller)
    if subject_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if not doc_id or not subject_id:
        raise ValueError("doc_id and subject_id are required")

    now_ts = int(time.time())
    rt = get_runtime(db_path)
    with rt.get_tenant_lock(caller.tenant_id):
        conn = rt.get_connection()
        try:
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (caller.tenant_id, doc_id),
            ).fetchone()
            if not doc_row:
                raise LookupError(f"Document not found in tenant: {doc_id}")

            conn.execute("BEGIN IMMEDIATE")
            if active:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, ?, ?, 'DENY', 1, ?)",
                    (caller.tenant_id, doc_id, subject_type, subject_id, now_ts),
                )
            else:
                conn.execute(
                    "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ?",
                    (now_ts, caller.tenant_id, doc_id, subject_type, subject_id),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        rt.bump_epoch("doc", caller.tenant_id)

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "effect": "DENY",
        "active": bool(active),
    }


def _load_user_auth_bundle(
    conn: sqlite3.Connection,
    tenant_id: str,
    user_id: str,
) -> dict[str, Any] | None:
    t_row = conn.execute(
        "SELECT status FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    if not t_row or t_row["status"] != "ACTIVE":
        return {"tenant_active": False}

    u_row = conn.execute(
        "SELECT user_id, tenant_id, username, org_node_id, base_role, api_token_hash, active "
        "FROM users WHERE user_id = ? AND tenant_id = ?",
        (user_id, tenant_id),
    ).fetchone()
    if not u_row or not u_row["active"]:
        return None

    ancestors = _resolve_org_ancestors_with_conn(conn, tenant_id, u_row["org_node_id"])
    roles: set[str] = {u_row["base_role"]}
    if ancestors:
        placeholders = ",".join("?" for _ in ancestors)
        n_rows = conn.execute(
            f"SELECT inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id IN ({placeholders})",
            (tenant_id, *ancestors),
        ).fetchall()
        for nr in n_rows:
            if nr["inherited_role"]:
                roles.add(nr["inherited_role"])

    g_rows = conn.execute(
        "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
        (tenant_id, user_id),
    ).fetchall()
    for gr in g_rows:
        roles.add(gr["granted_role"])

    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
    return {
        "tenant_active": True,
        "username": u_row["username"],
        "org_node_id": u_row["org_node_id"],
        "api_token_hash": u_row["api_token_hash"],
        "roles": frozenset(roles),
        "max_clearance": max_clearance,
        "org_ancestors": tuple(ancestors),
    }


def authenticate_caller(db_path: str, headers: dict[str, str]) -> CallerContext:
    """校验请求头中的租户与操作员访问凭证，并解析有效角色集合与组织祖先链。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)

    rt = get_runtime(db_path)
    ep_before, cached = rt.get_perm_cached(tenant_id, user_id)
    if cached is None:
        conn = rt.get_connection()
        bundle = _load_user_auth_bundle(conn, tenant_id, user_id)
        if bundle is not None and bundle.get("tenant_active"):
            rt.put_perm_cached(tenant_id, user_id, ep_before, bundle)
    else:
        bundle = cached

    if bundle is not None and not bundle.get("tenant_active", False):
        raise AuthError("Unknown or inactive tenant", 403)
    if bundle is None:
        raise AuthError("Invalid operator identity", 401)

    provided_hash = hash_api_token(raw_token)
    if not hmac.compare_digest(bundle["api_token_hash"], provided_hash):
        raise AuthError("Invalid access token", 401)

    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=bundle["username"],
        org_node_id=bundle["org_node_id"],
        effective_roles=set(bundle["roles"]),
        max_clearance=bundle["max_clearance"],
        org_ancestors=bundle["org_ancestors"],
    )


def resolve_effective_permissions(db_path: str, tenant_id: str, user_id: str) -> tuple[set[str], int]:
    """沿着组织汇报树向上汇总继承角色，并合并显式授权记录，返回有效角色集合与最高密级。"""
    rt = get_runtime(db_path)
    ep_before, cached = rt.get_perm_cached(tenant_id, user_id)
    if cached is not None and cached.get("tenant_active"):
        return set(cached["roles"]), cached["max_clearance"]

    conn = rt.get_connection()
    bundle = _load_user_auth_bundle(conn, tenant_id, user_id)
    if not bundle or not bundle.get("tenant_active"):
        return set(), 0
    rt.put_perm_cached(tenant_id, user_id, ep_before, bundle)
    return set(bundle["roles"]), bundle["max_clearance"]


def require_admin(caller: CallerContext) -> None:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise AuthError("COMPLIANCE_ADMIN role required", 403)


def revoke_or_grant_role(
    db_path: str,
    caller: CallerContext,
    *,
    target_user_id: str,
    role_name: str,
    action: str,
) -> dict[str, Any]:
    """管理员工临时角色授权（支持 grant 与 revoke），提交后立即失效租户权限缓存。"""
    require_admin(caller)
    if role_name not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    if action not in ("grant", "revoke"):
        raise ValueError("action must be 'grant' or 'revoke'")

    now_ts = int(time.time())
    rt = get_runtime(db_path)
    with rt.get_tenant_lock(caller.tenant_id):
        conn = rt.get_connection()
        try:
            target = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ?",
                (caller.tenant_id, target_user_id),
            ).fetchone()
            if not target:
                raise LookupError("Target operator not found in tenant")

            conn.execute("BEGIN IMMEDIATE")
            if action == "revoke":
                cur = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, target_user_id, role_name),
                )
                changed = cur.rowcount
            else:
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                    (caller.tenant_id, target_user_id, role_name, now_ts),
                )
                changed = 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        rt.bump_epoch("perm", caller.tenant_id)

    eff_roles, eff_cl = resolve_effective_permissions(db_path, caller.tenant_id, target_user_id)
    return {
        "tenant_id": caller.tenant_id,
        "user_id": target_user_id,
        "action": action,
        "role": role_name,
        "updated_records": changed,
        "effective_clearance": eff_cl,
        "effective_roles": sorted(eff_roles),
    }


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """原子扣减租户指定类型的业务配额并返回剩余额度（细粒度锁 + SQL 条件更新防 TOCTOU）。"""
    if amount <= 0:
        raise ValueError("Quota consumption amount must be positive")
    if not quota_type:
        raise ValueError("quota_type is required")

    now_ts = int(time.time())
    rt = get_runtime(db_path)
    with rt.get_resource_lock(caller.tenant_id, f"quota:{quota_type}"):
        conn = rt.get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE tenant_quotas "
                "SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amount, now_ts, caller.tenant_id, quota_type, amount),
            )
            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, quota_type),
                ).fetchone()
                conn.rollback()
                if not row:
                    raise LookupError(f"Quota bucket not found: {quota_type}")
                return {
                    "accepted": False,
                    "quota_type": quota_type,
                    "remaining_quota": int(row["remaining_quota"]),
                    "reason": "QUOTA_EXHAUSTED",
                }

            row_after = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, quota_type),
            ).fetchone()
            new_rem = int(row_after["remaining_quota"])
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    amount,
                    now_ts,
                    json.dumps({"quota_type": quota_type, "consumed": amount, "remaining": new_rem}),
                ),
            )
            conn.commit()
            return {
                "accepted": True,
                "quota_type": quota_type,
                "consumed": amount,
                "remaining_quota": new_rem,
            }
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    """原子核销单次使用的风控应急放行令牌（细粒度锁 + CAS 条件更新防重放/竞态）。"""
    if not token_id or not tx_ref:
        raise ValueError("token_id and tx_ref are required")

    now_ts = int(time.time())
    rt = get_runtime(db_path)
    with rt.get_resource_lock(caller.tenant_id, f"token:{token_id}"):
        conn = rt.get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, token_id, caller.tenant_id),
            )
            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT token_id FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                    (token_id, caller.tenant_id),
                ).fetchone()
                conn.rollback()
                if not row:
                    raise LookupError("Override token not found")
                return {
                    "redeemed": False,
                    "token_id": token_id,
                    "reason": "TOKEN_ALREADY_USED",
                }

            meta_row = conn.execute(
                "SELECT purpose FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (token_id, caller.tenant_id),
            ).fetchone()
            purpose = meta_row["purpose"] if meta_row else ""
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    now_ts,
                    json.dumps({"token_id": token_id, "tx_ref": tx_ref, "purpose": purpose}),
                ),
            )
            conn.commit()
            return {
                "redeemed": True,
                "token_id": token_id,
                "purpose": purpose,
                "tx_ref": tx_ref,
            }
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise


def process_settlement_webhook(
    db_path: str,
    headers: dict[str, str],
    raw_body: str,
    *,
    now_override: int | None = None,
) -> dict[str, Any]:
    """验证外部清算中心回调签名、时间窗与 Nonce 防重放并登记入账通知。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(nonce) > 128:
        raise AuthError("Invalid webhook nonce", 400)

    try:
        callback_ts = int(ts_str)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = int(now_override if now_override is not None else time.time())
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp expired or outside tolerance window", 401)

    rt = get_runtime(db_path)
    conn = rt.get_connection()
    t_row = conn.execute(
        "SELECT webhook_secret, status FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    if not t_row or t_row["status"] != "ACTIVE":
        raise AuthError("Unknown webhook tenant", 403)

    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}"
    expected_sig = hmac.new(
        t_row["webhook_secret"].encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    provided_sig = sig_header.removeprefix("sha256=").strip().lower()
    if not hmac.compare_digest(provided_sig, expected_sig.lower()):
        raise AuthError("Webhook signature verification failed", 401)

    payload = json.loads(raw_body)
    if not isinstance(payload, dict):
        raise ValueError("Invalid settlement payload format")
    settlement_ref = str(payload.get("settlement_ref") or "")
    amount_cents = int(payload.get("amount_cents") or 0)
    if not settlement_ref or amount_cents < 0:
        raise ValueError("Invalid settlement payload fields")

    with rt.get_resource_lock(tenant_id, f"webhook:{nonce}"):
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction:
                conn.rollback()
            raise ConflictError("Webhook replay detected: duplicate nonce") from exc
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
