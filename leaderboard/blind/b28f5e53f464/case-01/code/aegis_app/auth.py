# -*- coding: utf-8 -*-
"""租户身份认证（常量时间与哑比对掩蔽）、有效权限汇总与防重放回调验签门面模块。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import sqlite3
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import hash_api_token
from .delegation import (
    create_or_revoke_delegation,
    resolve_active_delegated_roles,
    resolve_base_and_explicit_roles,
)
from .runtime import GatewayRuntime, get_runtime
from .validation import safe_json_loads, strict_int

_DUMMY_TOKEN_HASH = "a" * 64
_DUMMY_WEBHOOK_SECRET = b"aegis-dummy-webhook-secret-constant-time-mask"


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
    runtime: GatewayRuntime | None = None,
) -> tuple[set[str], int]:
    """合并操作员原生角色、组织继承角色、显式授予角色以及在 at_ts 时刻有效且未级联失效的借调角色。"""
    eval_ts = int(at_ts if at_ts is not None else time.time())
    rt = runtime or get_runtime(db_path)
    return rt.get_perm_state(tenant_id).resolve_effective_permissions(user_id, eval_ts)


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
    runtime: GatewayRuntime | None = None,
) -> CallerContext:
    """校验请求头凭证（未知租户/用户执行哑哈希常量时间掩蔽）并组装实时权限上下文。"""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tenant_id = norm_headers.get("x-aegis-tenant", "").strip()
    user_id = norm_headers.get("x-aegis-user", "").strip()
    raw_token = norm_headers.get("x-aegis-token", "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)

    req_ts = int(now_override if now_override is not None else time.time())
    provided_hash = hash_api_token(raw_token)
    rt = runtime or get_runtime(db_path)
    perm_state = rt.get_perm_state(tenant_id)

    if perm_state.tenant_status != "ACTIVE":
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Unknown or inactive tenant", 403)

    u_info = perm_state.users.get(user_id)
    if not u_info or u_info[3] != 1:
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Invalid operator identity", 401)

    username, org_node_id, _, _, expected_hash = u_info
    if not hmac.compare_digest(expected_hash, provided_hash):
        raise AuthError("Invalid access token", 401)

    roles, max_cl = perm_state.resolve_effective_permissions(user_id, req_ts)
    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=username,
        org_node_id=org_node_id,
        effective_roles=roles,
        max_clearance=max_cl,
        request_ts=req_ts,
    )


def require_admin(caller: CallerContext) -> None:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise AuthError("COMPLIANCE_ADMIN role required", 403)


def is_doc_blocked_by_acl(
    db_path: str,
    tenant_id: str,
    user_id: str,
    doc_id: str,
    *,
    runtime: GatewayRuntime | None = None,
) -> bool:
    return is_doc_blocked_by_wall(db_path, tenant_id, user_id, doc_id, runtime=runtime)


def configure_doc_acl_rule(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
    runtime: GatewayRuntime | None = None,
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
        runtime=runtime,
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
    runtime: GatewayRuntime | None = None,
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
            runtime=runtime,
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    require_admin(caller)
    clean_target = str(target_user_id or "").strip()
    clean_role = str(role_name or "").strip()
    clean_action = str(action or "").strip().lower()
    if clean_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    if not clean_target:
        raise ValueError("user_id is required")

    now_ts = int(caller.request_ts)
    rt = runtime or get_runtime(db_path)

    with rt.perm_lock(caller.tenant_id):
        perm_state = rt.get_perm_state(caller.tenant_id)
        if clean_target not in perm_state.users:
            raise LookupError("Target operator not found in tenant")

        with rt.write_tx() as conn:
            if clean_action == "revoke":
                cur = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, clean_target, clean_role),
                )
                changed = cur.rowcount
            elif clean_action == "grant":
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                    (caller.tenant_id, clean_target, clean_role, now_ts),
                )
                changed = 1
            else:
                raise ValueError("action must be 'grant' or 'revoke'")

        if clean_action == "revoke":
            perm_state.role_grants[clean_target].discard(clean_role)
        else:
            perm_state.role_grants[clean_target].add(clean_role)
        perm_state._recompute_user_native(clean_target)
        perm_state.perm_epoch += 1

        eff_roles, eff_cl = perm_state.resolve_effective_permissions(clean_target, now_ts)

    return {
        "tenant_id": caller.tenant_id,
        "user_id": clean_target,
        "action": clean_action,
        "role": clean_role,
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """验证外部清算中心回调常量时间 HMAC-SHA256 签名、±300s 时间窗与原子 Nonce 防重放。"""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tenant_id = norm_headers.get("x-aegis-tenant", "").strip()
    ts_str = norm_headers.get("x-aegis-timestamp", "").strip()
    nonce = norm_headers.get("x-aegis-nonce", "").strip()
    sig_header = norm_headers.get("x-aegis-signature", "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(nonce) > 128:
        raise AuthError("Invalid webhook nonce", 400)

    try:
        callback_ts = strict_int(ts_str, "x-aegis-timestamp", allow_str=True)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    rt = runtime or get_runtime(db_path)
    with rt.connection() as conn:
        t_row = conn.execute(
            "SELECT webhook_secret, status FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()

    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}".encode("utf-8")
    provided_sig = sig_header.removeprefix("sha256=").strip()

    if not t_row or t_row["status"] != "ACTIVE":
        dummy_sig = hmac.new(_DUMMY_WEBHOOK_SECRET, signing_input, hashlib.sha256).hexdigest()
        hmac.compare_digest(provided_sig, dummy_sig)
        raise AuthError("Unknown webhook tenant", 403)

    expected_sig = hmac.new(
        str(t_row["webhook_secret"]).encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise AuthError("Webhook signature verification failed", 401)

    now_ts = int(now_override if now_override is not None else time.time())
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside tolerance window", 401)

    payload = safe_json_loads(raw_body)
    if not isinstance(payload, dict):
        raise ValueError("Webhook payload must be a JSON object")
    settlement_ref = str(payload.get("settlement_ref") or "").strip()
    raw_amount = payload.get("amount_cents", 0)
    amount_cents = strict_int(raw_amount if raw_amount is not None else 0, "amount_cents", min_val=0)
    if not settlement_ref:
        raise ValueError("Invalid settlement payload fields")

    try:
        with rt.write_tx() as conn:
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
    except sqlite3.IntegrityError as exc:
        raise AuthError("Duplicate webhook nonce (replay rejected)", 409) from exc

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
