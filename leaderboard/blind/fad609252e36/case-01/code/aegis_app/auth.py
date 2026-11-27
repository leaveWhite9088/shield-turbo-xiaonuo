# -*- coding: utf-8 -*-
"""租户身份认证（含常量时间 Dummy 掩蔽）、有效权限（含临时借调委托链）汇总与合作方回调防重放验签模块。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import sqlite3
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import (
    INT64_MAX,
    ROLE_DEFAULT_CLEARANCE,
    WEBHOOK_TOLERANCE_SECONDS,
)
from .db import (
    bump_auth_epoch,
    get_tenant_auth_lock,
    get_tenant_webhook_lock,
    hash_api_token,
    open_connection,
)
from .delegation import (
    create_or_revoke_delegation,
    get_tenant_auth_snapshot,
    resolve_active_delegated_roles,
    resolve_base_and_explicit_roles,
    resolve_cached_effective_permissions,
)
from .middleware import parse_json_payload, strict_int

_DUMMY_TOKEN_HASH = hashlib.sha256(b"AEGIS-DUMMY-CONSTANT-TIME-MASK-TOKEN").hexdigest()
_DUMMY_WEBHOOK_SECRET = b"AEGIS-DUMMY-CONSTANT-TIME-WEBHOOK-SECRET"


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
    """合并操作员原生角色、组织继承角色、显式授予角色以及在 at_ts 时刻有效且未级联失效的借调角色。"""
    eval_ts = int(at_ts if at_ts is not None else time.time())
    return resolve_cached_effective_permissions(db_path, tenant_id, user_id, eval_ts)


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    """校验请求头凭证（无论租户或用户是否存在均执行常量时间哈希比对以消除时序侧信道）。"""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)
    if len(tenant_id) > 128 or len(user_id) > 128 or len(raw_token) > 512:
        raise AuthError("Invalid authentication header length", 401)

    req_ts = strict_int(now_override, "_now_ts") if now_override is not None else int(time.time())
    provided_hash = hash_api_token(raw_token)

    snap = get_tenant_auth_snapshot(db_path, tenant_id)
    if not snap.tenant_exists or not snap.tenant_active:
        hmac.compare_digest(_DUMMY_TOKEN_HASH, provided_hash)
        raise AuthError("Unknown or inactive tenant", 403)

    u_entry = snap.users.get(user_id)
    if u_entry is None or not u_entry.active:
        hmac.compare_digest(_DUMMY_TOKEN_HASH, provided_hash)
        raise AuthError("Invalid operator identity", 401)

    if not hmac.compare_digest(u_entry.api_token_hash, provided_hash):
        raise AuthError("Invalid access token", 401)

    roles, max_cl = resolve_cached_effective_permissions(
        db_path,
        tenant_id,
        user_id,
        req_ts,
    )
    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=u_entry.username,
        org_node_id=u_entry.org_node_id,
        effective_roles=roles,
        max_clearance=max_cl,
        request_ts=req_ts,
    )


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
        db_path,
        caller.tenant_id,
        doc_id=doc_id,
        subject_type=subject_type,
        subject_id=subject_id,
        effect=effect,
        active=active,
    )


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
            db_path,
            caller.tenant_id,
            caller.user_id,
            caller.effective_roles,
            grantor_user_id=grantor_user_id,
            grantee_user_id=grantee_user_id,
            delegated_role=delegated_role,
            starts_at=starts_at,
            expires_at=expires_at,
            action=action,
            now_ts=caller.request_ts,
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
    target_uid = str(target_user_id or "").strip()
    if not target_uid:
        raise ValueError("user_id is required")

    now_ts = int(caller.request_ts)
    with get_tenant_auth_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            target = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ?",
                (caller.tenant_id, target_uid),
            ).fetchone()
            if not target:
                raise LookupError("Target operator not found in tenant")

            if action == "revoke":
                cur = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, target_uid, role_name),
                )
                changed = cur.rowcount
            elif action == "grant":
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                    (caller.tenant_id, target_uid, role_name, now_ts),
                )
                changed = 1
            else:
                raise ValueError("action must be 'grant' or 'revoke'")
            conn.commit()
        finally:
            conn.close()
        bump_auth_epoch(db_path, caller.tenant_id)

    eff_roles, eff_cl = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        target_uid,
        at_ts=now_ts,
    )
    return {
        "tenant_id": caller.tenant_id,
        "user_id": target_uid,
        "action": action,
        "role": role_name,
        "updated_records": changed,
        "effective_clearance": eff_cl,
        "effective_roles": sorted(eff_roles),
    }


def process_settlement_webhook(
    db_path: str,
    headers: dict[str, str],
    raw_body: str,
    *,
    now_override: int | None = None,
) -> dict[str, Any]:
    """验证外部清算中心回调签名、±300s 时间窗口与并发/串行 Nonce 重放保护。"""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(tenant_id) > 128 or len(nonce) > 256 or len(sig_header) > 256:
        raise AuthError("Invalid webhook header length", 400)

    try:
        callback_ts = strict_int(ts_str, "x-aegis-timestamp", min_val=1)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = strict_int(now_override, "_now_ts") if now_override is not None else int(time.time())
    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}".encode("utf-8")
    provided_sig = sig_header.removeprefix("sha256=").strip()

    snap = get_tenant_auth_snapshot(db_path, tenant_id)
    if not snap.tenant_exists or not snap.tenant_active:
        dummy_sig = hmac.new(_DUMMY_WEBHOOK_SECRET, signing_input, hashlib.sha256).hexdigest()
        hmac.compare_digest(provided_sig, dummy_sig)
        raise AuthError("Unknown webhook tenant", 403)

    expected_sig = hmac.new(
        snap.webhook_secret.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise AuthError("Webhook signature verification failed", 401)

    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside tolerance window", 401)

    payload, _ = parse_json_payload(raw_body)
    raw_ref = payload.get("settlement_ref")
    if not isinstance(raw_ref, str) or not raw_ref.strip() or len(raw_ref.strip()) > 128:
        raise ValueError("Invalid settlement_ref in webhook payload")
    settlement_ref = raw_ref.strip()
    if "amount_cents" not in payload:
        raise ValueError("Missing amount_cents in webhook payload")
    amount_cents = strict_int(payload.get("amount_cents"), "amount_cents", min_val=0, max_val=INT64_MAX // 4)

    with get_tenant_webhook_lock(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            dup = conn.execute(
                "SELECT 1 FROM webhook_events WHERE tenant_id = ? AND nonce = ?",
                (tenant_id, nonce),
            ).fetchone()
            if dup is not None:
                raise AuthError("Duplicate webhook nonce replay detected", 409)
            try:
                conn.execute(
                    "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthError("Duplicate webhook nonce replay detected", 409) from exc
            conn.commit()
        finally:
            conn.close()

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
