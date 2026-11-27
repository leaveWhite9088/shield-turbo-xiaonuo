# -*- coding: utf-8 -*-
"""租户身份认证、有效权限（含临时借调委托链）汇总与合作方回调验签门面模块。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import pathlib
import sqlite3
import threading
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import (
    MASTER_SIGNING_PEPPER,
    ROLE_DEFAULT_CLEARANCE,
    WEBHOOK_TOLERANCE_SECONDS,
    parse_strict_int,
)
from .db import bump_domain_epoch, get_domain_epoch, hash_api_token, open_connection
from .delegation import (
    create_or_revoke_delegation,
    resolve_active_delegated_roles,
    resolve_base_and_explicit_roles,
)

_DUMMY_TOKEN_HASH = hash_api_token("aegis_dummy_token_constant_time_pad")
_DUMMY_WEBHOOK_SECRET = f"whsec_dummy_{MASTER_SIGNING_PEPPER}"


class _AuthIdentityCache:
    __slots__ = ("epoch", "tenant_status", "webhook_secret", "users")

    def __init__(
        self,
        epoch: int,
        tenant_status: str | None,
        webhook_secret: str | None,
        users: dict[str, tuple[str, str, str, str, int]],
    ) -> None:
        self.epoch = epoch
        self.tenant_status = tenant_status
        self.webhook_secret = webhook_secret
        self.users = users


_AUTH_CACHE_LOCK = threading.Lock()
_AUTH_CACHES: dict[str, _AuthIdentityCache] = {}


def _get_auth_cache(db_path: str, tenant_id: str) -> _AuthIdentityCache:
    db_key = str(pathlib.Path(db_path).resolve())
    cache_key = f"{db_key}::{tenant_id}"
    cur_epoch = get_domain_epoch(db_key, tenant_id, "perm")
    with _AUTH_CACHE_LOCK:
        cached = _AUTH_CACHES.get(cache_key)
        if cached is not None and cached.epoch == cur_epoch:
            return cached

    conn = open_connection(db_key)
    try:
        t_row = conn.execute(
            "SELECT status, webhook_secret FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if not t_row:
            return _AuthIdentityCache(cur_epoch, None, None, {})
        u_rows = conn.execute(
            "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
            "FROM users WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    users: dict[str, tuple[str, str, str, str, int]] = {}
    for r in u_rows:
        users[str(r["user_id"])] = (
            str(r["username"]),
            str(r["org_node_id"]),
            str(r["base_role"]),
            str(r["api_token_hash"]),
            int(r["active"]),
        )
    state = _AuthIdentityCache(
        epoch=cur_epoch,
        tenant_status=str(t_row["status"]),
        webhook_secret=str(t_row["webhook_secret"]),
        users=users,
    )
    with _AUTH_CACHE_LOCK:
        if len(_AUTH_CACHES) > 256:
            _AUTH_CACHES.pop(next(iter(_AUTH_CACHES)), None)
        _AUTH_CACHES[cache_key] = state
    return state


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
    roles = resolve_base_and_explicit_roles(db_path, tenant_id, user_id)
    if not roles:
        return set(), 0

    delegated = resolve_active_delegated_roles(db_path, tenant_id, user_id, eval_ts)
    all_roles = roles | delegated
    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in all_roles), default=1)
    return all_roles, max_clearance


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    """校验请求头凭证并组装带实时借调权限的操作员上下文（含未知租户/用户常量时间掩蔽）。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)

    req_ts = int(now_override if now_override is not None else time.time())
    provided_hash = hash_api_token(raw_token)
    auth_state = _get_auth_cache(db_path, tenant_id)

    if auth_state.tenant_status != "ACTIVE":
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Unknown or inactive tenant", 403)

    u_info = auth_state.users.get(user_id)
    if not u_info or u_info[4] != 1:
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Invalid operator identity", 401)

    username, org_node_id, _, expected_hash, _ = u_info
    if not hmac.compare_digest(provided_hash, expected_hash):
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
        username=username,
        org_node_id=org_node_id,
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
    now_ts = int(caller.request_ts)
    conn = open_connection(db_path)
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
        elif action == "grant":
            conn.execute(
                "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                (caller.tenant_id, target_user_id, role_name, now_ts),
            )
            changed = 1
        else:
            raise ValueError("action must be 'grant' or 'revoke'")
        conn.commit()
    finally:
        conn.close()

    bump_domain_epoch(db_path, caller.tenant_id, "perm")
    eff_roles, eff_cl = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        target_user_id,
        at_ts=now_ts,
    )
    return {
        "tenant_id": caller.tenant_id,
        "user_id": target_user_id,
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
    """验证外部清算中心回调签名并登记入账通知（常量时间验签 + ±300s 时间窗 + Nonce 防重放）。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(nonce) > 128:
        raise AuthError("Malformed webhook nonce", 400)

    try:
        callback_ts = parse_strict_int(ts_str, "timestamp", min_val=1)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = int(now_override if now_override is not None else time.time())
    auth_state = _get_auth_cache(db_path, tenant_id)
    secret_to_use = auth_state.webhook_secret if auth_state.tenant_status == "ACTIVE" and auth_state.webhook_secret else _DUMMY_WEBHOOK_SECRET

    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}"
    expected_sig = hmac.new(
        secret_to_use.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    provided_sig = sig_header.removeprefix("sha256=").strip()
    sig_ok = hmac.compare_digest(provided_sig, expected_sig)

    if auth_state.tenant_status != "ACTIVE" or not auth_state.webhook_secret:
        raise AuthError("Unknown webhook tenant", 403)

    if not sig_ok:
        raise AuthError("Webhook signature verification failed", 401)

    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside tolerance window", 401)

    payload = json.loads(raw_body)
    if not isinstance(payload, dict):
        raise ValueError("Invalid settlement payload")
    settlement_ref = str(payload.get("settlement_ref") or "").strip()
    amount_cents = parse_strict_int(payload.get("amount_cents", -1), "amount_cents", min_val=0)
    if not settlement_ref or amount_cents < 0:
        raise ValueError("Invalid settlement payload fields")

    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT 1 FROM webhook_events WHERE tenant_id = ? AND nonce = ?",
            (tenant_id, nonce),
        ).fetchone()
        if existing:
            conn.rollback()
            raise AuthError("Duplicate webhook nonce replay detected", 409)
        try:
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise AuthError("Duplicate webhook nonce replay detected", 409) from exc
        return {
            "acknowledged": True,
            "tenant_id": tenant_id,
            "settlement_ref": settlement_ref,
            "amount_cents": amount_cents,
        }
    finally:
        conn.close()
