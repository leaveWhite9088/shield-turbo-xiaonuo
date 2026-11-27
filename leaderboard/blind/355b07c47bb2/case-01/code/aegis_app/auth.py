# -*- coding: utf-8 -*-
"""租户身份认证、有效权限（含临时借调委托链）汇总与合作方回调验签防重放门面模块。"""
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
    get_perm_state,
    update_user_role_grant_cache,
)
from .middleware import parse_json_payload, parse_strict_int
from .runtime import GatewayRuntime, get_runtime

_DUMMY_TOKEN_HASH = "0" * 64
_DUMMY_WEBHOOK_SECRET = b"aegis-dummy-constant-time-masking-secret-key"


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


def _get_tenant_info(rt: GatewayRuntime, tenant_id: str) -> tuple[str, str] | None:
    with rt.auth_lock:
        info = rt.tenants_cache.get(tenant_id)
        if info is not None:
            return info
    with rt.read_conn() as conn:
        row = conn.execute(
            "SELECT status, webhook_secret FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return None
    val = (str(row["status"]), str(row["webhook_secret"]))
    with rt.auth_lock:
        rt.tenants_cache[tenant_id] = val
    return val


def _get_user_info(rt: GatewayRuntime, tenant_id: str, user_id: str) -> dict[str, Any] | None:
    key = (tenant_id, user_id)
    with rt.auth_lock:
        info = rt.users_cache.get(key)
        if info is not None:
            return info
    with rt.read_conn() as conn:
        row = conn.execute(
            "SELECT user_id, tenant_id, username, org_node_id, base_role, api_token_hash, active "
            "FROM users WHERE user_id = ? AND tenant_id = ?",
            (user_id, tenant_id),
        ).fetchone()
    if not row:
        return None
    data = {
        "user_id": str(row["user_id"]),
        "tenant_id": str(row["tenant_id"]),
        "username": str(row["username"]),
        "org_node_id": str(row["org_node_id"]),
        "base_role": str(row["base_role"]),
        "api_token_hash": str(row["api_token_hash"]),
        "active": int(row["active"]) == 1,
    }
    with rt.auth_lock:
        rt.users_cache[key] = data
    return data


def resolve_effective_permissions(
    db_path: str,
    tenant_id: str,
    user_id: str,
    *,
    at_ts: int | None = None,
) -> tuple[set[str], int]:
    """合并操作员原生角色、组织继承角色、显式授予角色以及在 at_ts 时刻有效且未级联失效的借调角色。"""
    eval_ts = int(at_ts if at_ts is not None else time.time())
    rt = get_runtime(db_path)
    with rt.perm_lock(tenant_id):
        state = get_perm_state(db_path, tenant_id)
        roles = state.native_roles(user_id)
        if not roles:
            return set(), 0
        delegated = state.active_delegated_roles(user_id, eval_ts)
        all_roles = roles | delegated
    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in all_roles), default=1)
    return all_roles, max_clearance


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    """校验请求头凭证（含常量时间比较与未知租户/用户掩蔽）并组装带实时借调权限的操作员上下文。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = str(norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = str(norm_headers.get("x-aegis-user") or "").strip()
    raw_token = str(norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)
    if len(tenant_id) > 128 or len(user_id) > 128 or len(raw_token) > 512:
        raise AuthError("Invalid authentication header length", 401)

    req_ts = int(now_override if now_override is not None else time.time())
    rt = get_runtime(db_path)

    # 无论租户或用户是否存在，统一预先计算 token 哈希以掩蔽时序侧信道
    provided_hash = hash_api_token(raw_token)

    t_info = _get_tenant_info(rt, tenant_id)
    if not t_info or t_info[0] != "ACTIVE":
        hmac.compare_digest(_DUMMY_TOKEN_HASH, provided_hash)
        raise AuthError("Unknown or inactive tenant", 403)

    u_info = _get_user_info(rt, tenant_id, user_id)
    if not u_info or not u_info["active"]:
        hmac.compare_digest(_DUMMY_TOKEN_HASH, provided_hash)
        raise AuthError("Invalid operator identity", 401)

    if not hmac.compare_digest(u_info["api_token_hash"], provided_hash):
        raise AuthError("Invalid access token", 401)

    roles, max_cl = resolve_effective_permissions(
        db_path,
        tenant_id,
        user_id,
        at_ts=req_ts,
    )
    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=u_info["username"],
        org_node_id=u_info["org_node_id"],
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
    norm_target = str(target_user_id or "").strip()
    norm_role = str(role_name or "").strip()
    norm_action = str(action or "").strip().lower()
    if norm_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {norm_role}")
    if norm_action not in ("grant", "revoke"):
        raise ValueError("action must be 'grant' or 'revoke'")

    now_ts = int(caller.request_ts)
    rt = get_runtime(db_path)
    with rt.perm_lock(caller.tenant_id):
        with rt.write_tx() as conn:
            target = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ?",
                (caller.tenant_id, norm_target),
            ).fetchone()
            if not target:
                raise LookupError("Target operator not found in tenant")

            if norm_action == "revoke":
                cur = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, norm_target, norm_role),
                )
                changed = cur.rowcount
            else:
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                    (caller.tenant_id, norm_target, norm_role, now_ts),
                )
                changed = 1

        update_user_role_grant_cache(
            db_path,
            caller.tenant_id,
            norm_target,
            norm_role,
            granted=(norm_action == "grant"),
        )

    eff_roles, eff_cl = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        norm_target,
        at_ts=now_ts,
    )
    return {
        "tenant_id": caller.tenant_id,
        "user_id": norm_target,
        "action": norm_action,
        "role": norm_role,
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
    """验证外部清算中心回调 HMAC-SHA256 签名、±300s 时间窗及并发/串行 Nonce 防重放。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = str(norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = str(norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = str(norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = str(norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(tenant_id) > 128 or len(nonce) > 128 or len(sig_header) > 256:
        raise AuthError("Invalid webhook header length", 400)

    try:
        callback_ts = parse_strict_int(ts_str, "X-Aegis-Timestamp", allow_str=True)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = int(now_override if now_override is not None else time.time())
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside allowed tolerance window", 401)

    rt = get_runtime(db_path)
    t_info = _get_tenant_info(rt, tenant_id)
    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}".encode("utf-8")
    provided_sig = sig_header.removeprefix("sha256=").strip().lower()

    if not t_info or t_info[0] != "ACTIVE":
        dummy_sig = hmac.new(_DUMMY_WEBHOOK_SECRET, signing_input, hashlib.sha256).hexdigest()
        hmac.compare_digest(provided_sig, dummy_sig)
        raise AuthError("Unknown webhook tenant", 403)

    expected_sig = hmac.new(
        t_info[1].encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise AuthError("Webhook signature verification failed", 401)

    payload, _ = parse_json_payload(raw_body)
    settlement_ref = str(payload.get("settlement_ref") or "").strip()
    amount_cents = parse_strict_int(payload.get("amount_cents"), "amount_cents", default=0, min_val=0)
    if not settlement_ref or len(settlement_ref) > 128:
        raise ValueError("Invalid settlement payload fields")

    try:
        with rt.write_tx() as conn:
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
    except sqlite3.IntegrityError as exc:
        raise AuthError("Duplicate webhook nonce replay detected", 409) from exc

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
