# -*- coding: utf-8 -*-
"""高性能安全认证门面：常量时间防侧信道掩蔽、级联委托实时核验、隔离墙集合签名与防重放回调验签。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import sqlite3
import time
from typing import Any

from .acl_wall import get_user_denied_docs, is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    hash_api_token,
    require_strict_int,
)
from .delegation import (
    compute_effective_roles_from_snapshot,
    create_or_revoke_delegation,
    get_tenant_auth_snapshot,
)

_NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{4,128}$")
_DUMMY_TOKEN_HASH = hashlib.sha256(b"aegis-constant-time-dummy-mask-token-v2").hexdigest()


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
    denied_doc_ids: frozenset[str] = frozenset()


def resolve_effective_permissions(
    db_path: str,
    tenant_id: str,
    user_id: str,
    *,
    at_ts: int | None = None,
) -> tuple[set[str], int]:
    eval_ts = int(at_ts if at_ts is not None else time.time())
    eps = get_tenant_epochs(db_path, tenant_id)
    snap = get_tenant_auth_snapshot(db_path, tenant_id, eps.perm)
    if snap is None:
        return set(), 0
    return compute_effective_roles_from_snapshot(snap, user_id, eval_ts)


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
) -> CallerContext:
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)
    if len(tenant_id) > 64 or len(user_id) > 64 or len(raw_token) > 256:
        raise AuthError("Invalid authentication header length", 401)

    req_ts = int(now_override if now_override is not None else time.time())
    provided_hash = hash_api_token(raw_token)
    eps = get_tenant_epochs(db_path, tenant_id)
    snap = get_tenant_auth_snapshot(db_path, tenant_id, eps.perm)
    if snap is None or snap.tenant_status != "ACTIVE":
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Unknown or inactive tenant", 403)

    u_prof = snap.users.get(user_id)
    if u_prof is None or not u_prof.active:
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Invalid operator identity", 401)

    if not hmac.compare_digest(provided_hash, u_prof.api_token_hash):
        raise AuthError("Invalid access token", 401)

    roles, max_cl = compute_effective_roles_from_snapshot(snap, user_id, req_ts)
    denied_docs = get_user_denied_docs(
        db_path,
        tenant_id,
        user_id,
        u_prof.lineage,
        eps.perm,
        eps.acl,
    )
    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=u_prof.username,
        org_node_id=u_prof.org_node_id,
        effective_roles=roles,
        max_clearance=max_cl,
        request_ts=req_ts,
        denied_doc_ids=denied_docs,
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
        now_ts=caller.request_ts,
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
    if role_name not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    if action not in ("grant", "revoke"):
        raise ValueError("action must be 'grant' or 'revoke'")
    if not target_user_id or len(target_user_id) > 64:
        raise ValueError("Invalid target_user_id")

    now_ts = int(caller.request_ts)
    lock = get_striped_lock(db_path, caller.tenant_id, "perm")
    with lock:
        conn = get_thread_connection(db_path)
        target = conn.execute(
            "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ?",
            (caller.tenant_id, target_user_id),
        ).fetchone()
        if not target:
            raise LookupError("Target operator not found in tenant")

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
        # 递增 perm 纪元：不仅该用户自身权限即时更新，其下游所有受托人的级联资格核验也同步实时失效！
        bump_tenant_epoch(db_path, caller.tenant_id, "perm")

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
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if not _NONCE_RE.match(nonce):
        raise AuthError("Invalid webhook nonce format", 400)

    try:
        callback_ts = int(ts_str)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = int(now_override if now_override is not None else time.time())
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside allowed window", 401)

    eps = get_tenant_epochs(db_path, tenant_id)
    snap = get_tenant_auth_snapshot(db_path, tenant_id, eps.perm)
    if snap is None or snap.tenant_status != "ACTIVE":
        raise AuthError("Unknown webhook tenant", 403)

    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}"
    expected_sig = hmac.new(
        snap.webhook_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    provided_sig = sig_header.removeprefix("sha256=").strip().lower()
    if len(provided_sig) != 64 or not hmac.compare_digest(provided_sig, expected_sig):
        raise AuthError("Webhook signature verification failed", 401)

    payload = json.loads(raw_body)
    if not isinstance(payload, dict):
        raise ValueError("Webhook payload must be a JSON object")
    settlement_ref = str(payload.get("settlement_ref") or "").strip()
    amount_cents = require_strict_int(payload.get("amount_cents", 0), "amount_cents", min_val=0)
    if not settlement_ref or len(settlement_ref) > 128:
        raise ValueError("Invalid settlement_ref")

    lock = get_striped_lock(db_path, tenant_id, "webhook")
    with lock:
        conn = get_thread_connection(db_path)
        try:
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction:
                conn.rollback()
            raise AuthError("Webhook replay nonce rejected", 409) from exc

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
