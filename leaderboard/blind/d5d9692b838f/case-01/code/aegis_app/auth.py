# -*- coding: utf-8 -*-
"""租户身份常量时间认证、有效权限（含二级借调链）汇总与合作方回调防重放验签模块。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import (
    MAX_SAFE_TS,
    MAX_TX_AMOUNT_CENTS,
    ROLE_DEFAULT_CLEARANCE,
    WEBHOOK_TOLERANCE_SECONDS,
)
from .db import borrow_connection, get_db_hub, hash_api_token, write_transaction
from .delegation import (
    create_or_revoke_delegation,
    get_perm_snapshot,
)
from .middleware import (
    _precheck_json_structure,
    _reject_json_constant,
    strict_int,
)

_DUMMY_TOKEN_HASH = hash_api_token("aegis-constant-time-dummy-mask-token-v3")
_DUMMY_WEBHOOK_SECRET = b"whsec_constant_time_dummy_mask_secret_v3"


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


def _get_tenant_record(db_path: str, tenant_id: str) -> tuple[str, str] | None:
    """获取缓存的 (status, webhook_secret)，未知租户不落入长驻缓存以防内存放大。"""
    hub = get_db_hub(db_path)
    cached = hub.tenant_records.get(tenant_id)
    if cached is not None:
        return cached
    with borrow_connection(db_path) as conn:
        row = conn.execute(
            "SELECT status, webhook_secret FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
    if not row:
        return None
    val = (str(row["status"]), str(row["webhook_secret"]))
    hub.tenant_records.set(tenant_id, val)
    return val


def resolve_effective_permissions(
    db_path: str,
    tenant_id: str,
    user_id: str,
    *,
    at_ts: int | None = None,
) -> tuple[set[str], int]:
    """合并操作员原生角色、组织继承角色、显式授予角色以及在 at_ts 时刻有效的 1~2 跳借调角色。"""
    eval_ts = int(at_ts if at_ts is not None else time.time())
    snap = get_perm_snapshot(db_path, tenant_id)
    native = snap.native_roles.get(user_id)
    if not native:
        return set(), 0

    delegated = snap.resolve_delegated_roles_at(user_id, eval_ts)
    all_roles = set(native) | delegated
    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in all_roles), default=1)
    return all_roles, max_clearance


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    """常量时间凭证校验（含未知租户/未知用户 dummy 掩蔽）并组装实时权限上下文。"""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if (
        not tenant_id
        or not user_id
        or not raw_token
        or len(tenant_id) > 128
        or len(user_id) > 128
        or len(raw_token) > 512
    ):
        raise AuthError("Missing authentication headers", 401)

    req_ts = (
        strict_int(now_override, "_now_ts", min_val=0, max_val=MAX_SAFE_TS)
        if now_override is not None
        else int(time.time())
    )
    provided_hash = hash_api_token(raw_token)

    t_rec = _get_tenant_record(db_path, tenant_id)
    if t_rec is None or t_rec[0] != "ACTIVE":
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Unknown or inactive tenant", 403)

    snap = get_perm_snapshot(db_path, tenant_id)
    u_rec = snap.users.get(user_id)
    if u_rec is None or not u_rec.active:
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Invalid operator identity", 401)

    if not hmac.compare_digest(u_rec.api_token_hash, provided_hash):
        raise AuthError("Invalid access token", 401)

    native = snap.native_roles.get(user_id, frozenset())
    delegated = snap.resolve_delegated_roles_at(user_id, req_ts)
    all_roles = set(native) | delegated
    max_cl = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in all_roles), default=1)

    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=u_rec.username,
        org_node_id=u_rec.org_node_id,
        effective_roles=all_roles,
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
    starts_at: Any,
    expires_at: Any,
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
    clean_uid = str(target_user_id or "").strip()
    clean_role = str(role_name or "").strip()
    clean_action = str(action or "").strip()

    if not clean_uid or len(clean_uid) > 128:
        raise ValueError("Valid user_id is required")
    if clean_role not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {clean_role}")
    if clean_action not in ("grant", "revoke"):
        raise ValueError("action must be 'grant' or 'revoke'")

    now_ts = int(caller.request_ts)
    hub = get_db_hub(db_path)
    with hub.tenant_meta_lock(caller.tenant_id):
        with write_transaction(db_path) as conn:
            target = conn.execute(
                "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ?",
                (caller.tenant_id, clean_uid),
            ).fetchone()
            if not target:
                raise LookupError("Target operator not found in tenant")

            if clean_action == "revoke":
                cur = conn.execute(
                    "UPDATE role_grants SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND user_id = ? AND granted_role = ? AND active = 1",
                    (now_ts, caller.tenant_id, clean_uid, clean_role),
                )
                changed = cur.rowcount
            else:
                conn.execute(
                    "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) "
                    "VALUES (?, ?, ?, 1, ?)",
                    (caller.tenant_id, clean_uid, clean_role, now_ts),
                )
                changed = 1
        hub.bump_perm_epoch(caller.tenant_id)

    eff_roles, eff_cl = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        clean_uid,
        at_ts=now_ts,
    )
    return {
        "tenant_id": caller.tenant_id,
        "user_id": clean_uid,
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
) -> dict[str, Any]:
    """验证清算中心回调 HMAC-SHA256 常量时间签名、±300s 时间窗及并发原子 Nonce 防重放。"""
    norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if (
        not tenant_id
        or not ts_str
        or not nonce
        or not sig_header
        or len(tenant_id) > 128
        or len(nonce) > 128
        or len(sig_header) > 256
    ):
        raise AuthError("Missing or invalid webhook signature headers", 401)

    try:
        callback_ts = strict_int(
            ts_str,
            "x-aegis-timestamp",
            min_val=1,
            max_val=MAX_SAFE_TS,
            allow_str=True,
        )
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = (
        strict_int(now_override, "_now_ts", min_val=1, max_val=MAX_SAFE_TS)
        if now_override is not None
        else int(time.time())
    )

    signing_bytes = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}".encode("utf-8")
    provided_sig_bytes = sig_header.removeprefix("sha256=").strip().lower().encode("utf-8")

    t_rec = _get_tenant_record(db_path, tenant_id)
    if t_rec is None or t_rec[0] != "ACTIVE":
        dummy_mac = hmac.new(_DUMMY_WEBHOOK_SECRET, signing_bytes, hashlib.sha256).hexdigest().encode("utf-8")
        hmac.compare_digest(provided_sig_bytes, dummy_mac)
        raise AuthError("Unknown webhook tenant", 403)

    expected_sig_bytes = (
        hmac.new(t_rec[1].encode("utf-8"), signing_bytes, hashlib.sha256)
        .hexdigest()
        .encode("utf-8")
    )
    if not hmac.compare_digest(provided_sig_bytes, expected_sig_bytes):
        raise AuthError("Webhook signature verification failed", 401)

    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside allowed tolerance window", 401)

    if not raw_body or not raw_body.strip():
        raise ValueError("Empty webhook payload")
    _precheck_json_structure(raw_body)
    payload = json.loads(raw_body, parse_constant=_reject_json_constant)
    if not isinstance(payload, dict):
        raise ValueError("Webhook JSON payload must be an object")

    settlement_ref = str(payload.get("settlement_ref") or "").strip()
    if not settlement_ref or len(settlement_ref) > 128:
        raise ValueError("Invalid settlement_ref")
    if "amount_cents" not in payload or payload.get("amount_cents") is None:
        raise ValueError("Missing amount_cents")
    amount_cents = strict_int(
        payload.get("amount_cents"),
        "amount_cents",
        min_val=0,
        max_val=MAX_TX_AMOUNT_CENTS,
    )

    try:
        with write_transaction(db_path) as conn:
            dup = conn.execute(
                "SELECT 1 FROM webhook_events WHERE tenant_id = ? AND nonce = ?",
                (tenant_id, nonce),
            ).fetchone()
            if dup is not None:
                raise AuthError("Webhook nonce replay detected", 409)
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
    except sqlite3.IntegrityError as exc:
        raise AuthError("Webhook nonce replay detected", 409) from exc

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
