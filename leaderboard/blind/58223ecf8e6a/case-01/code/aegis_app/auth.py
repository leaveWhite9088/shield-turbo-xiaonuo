# -*- coding: utf-8 -*-
"""租户认证、实时借调权限、角色管理和防重放清算回调。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import sqlite3
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import hash_api_token, open_connection
from .delegation import (
    create_or_revoke_delegation,
    resolve_active_delegated_roles,
    resolve_base_and_explicit_roles,
)
from .runtime import RUNTIME
from .security import bounded_text, parse_json_bytes, strict_int


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
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
    eval_ts = strict_int(at_ts if at_ts is not None else int(time.time()), "at_ts")
    roles = resolve_base_and_explicit_roles(db_path, tenant_id, user_id)
    if not roles:
        return set(), 0
    delegated = resolve_active_delegated_roles(db_path, tenant_id, user_id, eval_ts)
    all_roles = roles | delegated
    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(role, 1) for role in all_roles), default=1)
    return all_roles, max_clearance


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    norm = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    tenant_id = norm.get("x-aegis-tenant", "").strip()
    user_id = norm.get("x-aegis-user", "").strip()
    raw_token = norm.get("x-aegis-token", "").strip()
    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Invalid authentication credentials", 401)
    if len(tenant_id) > 128 or len(user_id) > 128 or len(raw_token) > 256:
        raise AuthError("Invalid authentication credentials", 401)
    request_ts = strict_int(now_override if now_override is not None else int(time.time()), "request timestamp")

    conn = open_connection(db_path)
    try:
        tenant = conn.execute(
            "SELECT status FROM tenants WHERE tenant_id = ?", (tenant_id,),
        ).fetchone()
        user = conn.execute(
            "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
            "FROM users WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        # 对不存在的用户也执行同长度常量时间比较，减少身份枚举时间差。
        expected = str(user["api_token_hash"]) if user else "0" * 64
        supplied = hash_api_token(raw_token)
        token_ok = hmac.compare_digest(expected, supplied)
        if not tenant or tenant["status"] != "ACTIVE" or not user or not user["active"] or not token_ok:
            raise AuthError("Invalid authentication credentials", 401)
        roles, max_clearance = resolve_effective_permissions(
            db_path, tenant_id, user_id, at_ts=request_ts,
        )
        return CallerContext(
            tenant_id=tenant_id,
            user_id=user_id,
            username=str(user["username"]),
            org_node_id=str(user["org_node_id"]),
            effective_roles=roles,
            max_clearance=max_clearance,
            request_ts=request_ts,
        )
    finally:
        conn.close()


def require_admin(caller: CallerContext) -> None:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise AuthError("COMPLIANCE_ADMIN role required", 403)


def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    return is_doc_blocked_by_wall(db_path, tenant_id, user_id, doc_id)


def configure_doc_acl_rule(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
) -> dict[str, Any]:
    require_admin(caller)
    return upsert_doc_acl_rule(
        db_path, caller.tenant_id, doc_id=doc_id, subject_type=subject_type,
        subject_id=subject_id, effect=effect, active=active,
    )


def manage_role_delegation(db_path: str, caller: CallerContext, **kwargs: Any) -> dict[str, Any]:
    try:
        return create_or_revoke_delegation(
            db_path, caller.tenant_id, caller.user_id, caller.effective_roles,
            now_ts=caller.request_ts, **kwargs,
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
    target_user_id = bounded_text(target_user_id, "user_id", max_length=128)
    now_ts = caller.request_ts
    with RUNTIME.tenant_write(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            target = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
                (caller.tenant_id, target_user_id),
            ).fetchone()
            if not target:
                raise LookupError("Target operator not found in tenant")
            if action == "revoke":
                cursor = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, target_user_id, role_name),
                )
                changed = cursor.rowcount
            elif action == "grant":
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) "
                    "VALUES (?, ?, ?, 1, ?)",
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
        RUNTIME.bump(db_path, caller.tenant_id, "auth")
    roles, clearance = resolve_effective_permissions(
        db_path, caller.tenant_id, target_user_id, at_ts=now_ts,
    )
    return {
        "tenant_id": caller.tenant_id,
        "user_id": target_user_id,
        "action": action,
        "role": role_name,
        "updated_records": changed,
        "effective_clearance": clearance,
        "effective_roles": sorted(roles),
    }


def process_settlement_webhook(
    db_path: str,
    headers: dict[str, str],
    raw_body: str,
    *,
    now_override: int | None = None,
) -> dict[str, Any]:
    norm = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    tenant_id = norm.get("x-aegis-tenant", "").strip()
    timestamp = norm.get("x-aegis-timestamp", "").strip()
    nonce = norm.get("x-aegis-nonce", "").strip()
    signature = norm.get("x-aegis-signature", "").strip()
    if not tenant_id or not timestamp or not nonce or not signature:
        raise AuthError("Missing webhook signature headers", 401)
    if len(tenant_id) > 128 or len(nonce) > 128 or len(signature) > 128:
        raise AuthError("Malformed webhook headers", 400)
    callback_ts = strict_int(timestamp, "callback timestamp")
    now_ts = strict_int(now_override if now_override is not None else int(time.time()), "current timestamp")
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside tolerance", 401)

    conn = open_connection(db_path)
    try:
        tenant = conn.execute(
            "SELECT webhook_secret, status FROM tenants WHERE tenant_id = ?", (tenant_id,),
        ).fetchone()
        secret = str(tenant["webhook_secret"]) if tenant else "invalid-tenant-webhook-secret"
        signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}"
        expected = hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
        provided = signature.removeprefix("sha256=").strip()
        if not tenant or tenant["status"] != "ACTIVE" or not hmac.compare_digest(provided, expected):
            raise AuthError("Webhook signature verification failed", 401)

        payload = parse_json_bytes(raw_body)
        if not isinstance(payload, dict):
            raise ValueError("Webhook payload must be an object")
        settlement_ref = bounded_text(payload.get("settlement_ref"), "settlement_ref", max_length=128)
        amount_cents = strict_int(payload.get("amount_cents"), "amount_cents", minimum=0)
        conn.execute("BEGIN IMMEDIATE")
        try:
            duplicate = conn.execute(
                "SELECT 1 FROM webhook_events WHERE tenant_id = ? AND nonce = ? LIMIT 1",
                (tenant_id, nonce),
            ).fetchone()
            if duplicate:
                raise AuthError("Replayed webhook nonce", 409)
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise AuthError("Replayed webhook nonce", 409) from exc
        except Exception:
            conn.rollback()
            raise
        return {
            "acknowledged": True,
            "tenant_id": tenant_id,
            "settlement_ref": settlement_ref,
            "amount_cents": amount_cents,
        }
    finally:
        conn.close()
