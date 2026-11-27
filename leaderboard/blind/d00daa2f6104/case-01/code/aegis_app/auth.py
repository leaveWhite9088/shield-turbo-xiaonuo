# -*- coding: utf-8 -*-
"""常量时间认证、实时二级委托权限及清算回调防重放。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import hash_api_token, open_connection
from .delegation import create_or_revoke_delegation, resolve_active_delegated_roles, resolve_permissions_conn
from .runtime import bounded_text, strict_int, tenant_write_lock


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
    request_ts: int


def resolve_effective_permissions(
    db_path: str,
    tenant_id: str,
    user_id: str,
    *,
    at_ts: int | None = None,
) -> tuple[set[str], int]:
    eval_ts = int(at_ts if at_ts is not None else time.time())
    conn = open_connection(db_path)
    try:
        return resolve_permissions_conn(conn, tenant_id, user_id, eval_ts)
    finally:
        conn.close()


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    norm_headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()
    if not tenant_id or not user_id or not raw_token or max(len(tenant_id), len(user_id), len(raw_token)) > 512:
        raise AuthError("Invalid authentication credentials", 401)
    req_ts = int(now_override if now_override is not None else time.time())
    supplied_hash = hash_api_token(raw_token)
    dummy_hash = "0" * 64
    conn = open_connection(db_path)
    try:
        tenant = conn.execute(
            "SELECT status FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        user = conn.execute(
            "SELECT user_id, username, org_node_id, api_token_hash, active FROM users "
            "WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        stored_hash = str(user["api_token_hash"]) if user else dummy_hash
        token_ok = hmac.compare_digest(stored_hash, supplied_hash)
        if not tenant or tenant["status"] != "ACTIVE" or not user or not user["active"] or not token_ok:
            # 不论租户、用户或令牌哪一项失败，都执行同一条散列比较路径。
            hmac.compare_digest(dummy_hash, supplied_hash)
            raise AuthError("Invalid authentication credentials", 401)
        roles, max_clearance = resolve_permissions_conn(conn, tenant_id, user_id, req_ts)
        return CallerContext(
            tenant_id=tenant_id, user_id=user_id, username=str(user["username"]),
            org_node_id=str(user["org_node_id"]), effective_roles=roles,
            max_clearance=max_clearance, request_ts=req_ts,
        )
    finally:
        conn.close()


def require_admin(caller: CallerContext) -> None:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise AuthError("COMPLIANCE_ADMIN role required", 403)


def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    return is_doc_blocked_by_wall(db_path, tenant_id, user_id, doc_id)


def configure_doc_acl_rule(db_path: str, caller: CallerContext, **kwargs: Any) -> dict[str, Any]:
    require_admin(caller)
    return upsert_doc_acl_rule(db_path, caller.tenant_id, **kwargs)


def manage_role_delegation(
    db_path: str,
    caller: CallerContext,
    *,
    grantor_user_id: str,
    grantee_user_id: str,
    delegated_role: str,
    starts_at: int,
    expires_at: int,
    action: str = "create",
) -> dict[str, Any]:
    try:
        return create_or_revoke_delegation(
            db_path, caller.tenant_id, caller.user_id, caller.effective_roles,
            grantor_user_id=grantor_user_id, grantee_user_id=grantee_user_id,
            delegated_role=delegated_role, starts_at=starts_at, expires_at=expires_at,
            action=action, now_ts=caller.request_ts,
        )
    except PermissionError as exc:
        raise AuthError(str(exc), 403) from exc


def revoke_or_grant_role(
    db_path: str,
    caller: CallerContext,
    *,
    target_user_id: str,
    role_name: str,
    action: str,
) -> dict[str, Any]:
    require_admin(caller)
    if role_name not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    target_user_id = bounded_text(target_user_id, "user_id", 128)
    now_ts = int(caller.request_ts)
    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not conn.execute(
                "SELECT 1 FROM users WHERE tenant_id = ? AND user_id = ?",
                (caller.tenant_id, target_user_id),
            ).fetchone():
                raise LookupError("Target operator not found")
            if action == "revoke":
                cur = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? WHERE tenant_id = ? "
                    "AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, target_user_id, role_name),
                )
                changed = cur.rowcount
            elif action == "grant":
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                    (caller.tenant_id, target_user_id, role_name, now_ts),
                )
                changed = 1
            else:
                raise ValueError("action must be 'grant' or 'revoke'")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    roles, clearance = resolve_effective_permissions(
        db_path, caller.tenant_id, target_user_id, at_ts=now_ts
    )
    return {
        "tenant_id": caller.tenant_id, "user_id": target_user_id, "action": action,
        "role": role_name, "updated_records": changed,
        "effective_clearance": clearance, "effective_roles": sorted(roles),
    }


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is forbidden: {value}")


def process_settlement_webhook(
    db_path: str,
    headers: dict[str, str],
    raw_body: str,
    *,
    now_override: int | None = None,
) -> dict[str, Any]:
    norm_headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_text = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    signature = (norm_headers.get("x-aegis-signature") or "").strip()
    if not tenant_id or not ts_text or not nonce or not signature or len(nonce) > 128 or len(raw_body) > 1_048_576:
        raise AuthError("Malformed webhook request", 400)
    try:
        callback_ts = strict_int(int(ts_text), "callback_ts")
    except (ValueError, TypeError) as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc
    now_ts = int(now_override if now_override is not None else time.time())
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp is outside the accepted window", 401)

    with tenant_write_lock(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            tenant = conn.execute(
                "SELECT webhook_secret, status FROM tenants WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            if not tenant or tenant["status"] != "ACTIVE":
                raise AuthError("Webhook authentication failed", 401)
            expected = hmac.new(
                str(tenant["webhook_secret"]).encode("utf-8"),
                f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            provided = signature.removeprefix("sha256=").strip()
            if len(provided) != 64 or not hmac.compare_digest(provided, expected):
                raise AuthError("Webhook signature verification failed", 401)
            payload = json.loads(raw_body, parse_constant=_reject_json_constant)
            if not isinstance(payload, dict):
                raise ValueError("Settlement payload must be an object")
            settlement_ref = bounded_text(payload.get("settlement_ref") or "", "settlement_ref", 256)
            amount_cents = strict_int(payload.get("amount_cents"), "amount_cents", minimum=0)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise AuthError("Webhook nonce has already been consumed", 409) from exc
            return {
                "acknowledged": True, "tenant_id": tenant_id,
                "settlement_ref": settlement_ref, "amount_cents": amount_cents,
            }
        finally:
            conn.close()
