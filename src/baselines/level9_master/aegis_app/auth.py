# -*- coding: utf-8 -*-
"""高性能安全认证模块：纪元双检隔离缓存、Chinese Wall 利益冲突集合、常量时间防侧信道掩蔽与 SQL 原子防超扣。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import sqlite3
import threading
import time
from typing import Any

from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import (
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    hash_api_token,
    normalize_db_key,
    require_strict_int,
)

_NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{4,128}$")
_DUMMY_TOKEN_HASH = hashlib.sha256(b"aegis-constant-time-dummy-mask-token").hexdigest()

_AUTH_CACHE_LOCK = threading.Lock()
# key: (db_key, tenant_id, perm_epoch, user_id) -> (username, org_node_id, api_token_hash, active, frozenset_roles, max_cl, frozenset_denied_docs)
_USER_AUTH_CACHE: dict[
    tuple[str, str, int, str],
    tuple[str, str, str, bool, frozenset[str], int, frozenset[str]],
] = {}
_TENANT_META_CACHE: dict[tuple[str, str, int], tuple[str, str]] = {}


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
    denied_doc_ids: frozenset[str] = frozenset()


def _get_tenant_meta(db_path: str, tenant_id: str, perm_epoch: int) -> tuple[str, str] | None:
    db_key = normalize_db_key(db_path)
    ck = (db_key, tenant_id, perm_epoch)
    with _AUTH_CACHE_LOCK:
        cached = _TENANT_META_CACHE.get(ck)
    if cached is not None:
        return cached
    conn = get_thread_connection(db_path)
    row = conn.execute(
        "SELECT status, webhook_secret FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    if not row:
        return None
    val = (str(row["status"]), str(row["webhook_secret"]))
    with _AUTH_CACHE_LOCK:
        cur_ep, _, _ = get_tenant_epochs(db_path, tenant_id)
        if cur_ep == perm_epoch:
            if len(_TENANT_META_CACHE) > 1024:
                _TENANT_META_CACHE.clear()
            _TENANT_META_CACHE[ck] = val
    return val


def _load_and_cache_user_profile(
    db_path: str,
    tenant_id: str,
    user_id: str,
    perm_epoch: int,
) -> tuple[str, str, str, bool, frozenset[str], int, frozenset[str]] | None:
    db_key = normalize_db_key(db_path)
    ck = (db_key, tenant_id, perm_epoch, user_id)
    with _AUTH_CACHE_LOCK:
        cached = _USER_AUTH_CACHE.get(ck)
    if cached is not None:
        return cached

    conn = get_thread_connection(db_path)
    u_row = conn.execute(
        "SELECT username, org_node_id, base_role, api_token_hash, active "
        "FROM users WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    ).fetchone()
    if not u_row:
        return None

    org_rows = conn.execute(
        "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()
    org_map = {r["node_id"]: (r["parent_node_id"], r["inherited_role"]) for r in org_rows}

    roles: set[str] = {u_row["base_role"]}
    ancestors: set[str] = set()
    curr_node = u_row["org_node_id"]
    while curr_node and curr_node not in ancestors:
        ancestors.add(curr_node)
        node_info = org_map.get(curr_node)
        if not node_info:
            break
        parent_id, inh_role = node_info
        if inh_role:
            roles.add(inh_role)
        curr_node = parent_id

    g_rows = conn.execute(
        "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
        (tenant_id, user_id),
    ).fetchall()
    for gr in g_rows:
        roles.add(gr["granted_role"])

    acl_rows = conn.execute(
        "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
        (tenant_id,),
    ).fetchall()
    denied_docs: set[str] = set()
    for ar in acl_rows:
        if ar["effect"] != "DENY":
            continue
        if ar["subject_type"] == "USER" and ar["subject_id"] == user_id:
            denied_docs.add(ar["doc_id"])
        elif ar["subject_type"] == "ORG_NODE" and ar["subject_id"] in ancestors:
            denied_docs.add(ar["doc_id"])

    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
    entry = (
        str(u_row["username"]),
        str(u_row["org_node_id"]),
        str(u_row["api_token_hash"]),
        bool(u_row["active"]),
        frozenset(roles),
        max_clearance,
        frozenset(denied_docs),
    )

    # 双检纪元守卫：若计算期间发生了并发权限撤回或隔离墙更新，严禁回填过期权限快照！
    with _AUTH_CACHE_LOCK:
        live_perm_ep, _, _ = get_tenant_epochs(db_path, tenant_id)
        if live_perm_ep == perm_epoch:
            if len(_USER_AUTH_CACHE) > 2048:
                _USER_AUTH_CACHE.clear()
            _USER_AUTH_CACHE[ck] = entry
    return entry


def resolve_effective_permissions(db_path: str, tenant_id: str, user_id: str) -> tuple[set[str], int]:
    perm_epoch, _, _ = get_tenant_epochs(db_path, tenant_id)
    prof = _load_and_cache_user_profile(db_path, tenant_id, user_id, perm_epoch)
    if not prof or not prof[3]:
        return set(), 0
    return set(prof[4]), prof[5]


def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    perm_epoch, _, _ = get_tenant_epochs(db_path, tenant_id)
    prof = _load_and_cache_user_profile(db_path, tenant_id, user_id, perm_epoch)
    if not prof:
        return True
    return doc_id in prof[6]


def authenticate_caller(db_path: str, headers: dict[str, str]) -> CallerContext:
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)
    if len(tenant_id) > 64 or len(user_id) > 64 or len(raw_token) > 256:
        raise AuthError("Invalid authentication header length", 401)

    provided_hash = hash_api_token(raw_token)
    perm_epoch, _, _ = get_tenant_epochs(db_path, tenant_id)
    t_meta = _get_tenant_meta(db_path, tenant_id, perm_epoch)
    if not t_meta or t_meta[0] != "ACTIVE":
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Unknown or inactive tenant", 403)

    prof = _load_and_cache_user_profile(db_path, tenant_id, user_id, perm_epoch)
    if prof is None or not prof[3]:
        # 掩蔽用户存在性时序差异
        hmac.compare_digest(provided_hash, _DUMMY_TOKEN_HASH)
        raise AuthError("Invalid operator identity", 401)

    username, org_node_id, expected_hash, _active, froles, max_cl, denied_docs = prof
    if not hmac.compare_digest(provided_hash, expected_hash):
        raise AuthError("Invalid access token", 401)

    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=username,
        org_node_id=org_node_id,
        effective_roles=set(froles),
        max_clearance=max_cl,
        denied_doc_ids=denied_docs,
    )


def require_admin(caller: CallerContext) -> None:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise AuthError("COMPLIANCE_ADMIN role required", 403)


def configure_doc_acl_rule(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    active: bool = True,
) -> dict[str, Any]:
    require_admin(caller)
    if subject_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if not doc_id or len(doc_id) > 128 or not subject_id or len(subject_id) > 128:
        raise ValueError("Invalid doc_id or subject_id")

    now_ts = int(time.time())
    lock = get_striped_lock(db_path, caller.tenant_id, "perm")
    with lock:
        conn = get_thread_connection(db_path)
        doc_row = conn.execute(
            "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
            (caller.tenant_id, doc_id),
        ).fetchone()
        if not doc_row:
            raise LookupError(f"Document not found in tenant: {doc_id}")

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
        bump_tenant_epoch(db_path, caller.tenant_id, "perm")

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "effect": "DENY",
        "active": bool(active),
    }


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

    now_ts = int(time.time())
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
        bump_tenant_epoch(db_path, caller.tenant_id, "perm")

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
    amount: Any = 1,
) -> dict[str, Any]:
    checked_amount = require_strict_int(amount, "amount", min_val=1, max_val=1_000_000)
    if not isinstance(quota_type, str) or not quota_type or len(quota_type) > 64:
        raise ValueError("Invalid quota_type")

    now_ts = int(time.time())
    lock = get_striped_lock(db_path, caller.tenant_id, f"quota:{quota_type}")
    with lock:
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (checked_amount, now_ts, caller.tenant_id, quota_type, checked_amount),
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

            rem_row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, quota_type),
            ).fetchone()
            new_rem = int(rem_row["remaining_quota"])
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    checked_amount,
                    now_ts,
                    json.dumps({"quota_type": quota_type, "consumed": checked_amount, "remaining": new_rem}),
                ),
            )
            conn.commit()
            return {
                "accepted": True,
                "quota_type": quota_type,
                "consumed": checked_amount,
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
    if not isinstance(token_id, str) or not token_id or len(token_id) > 128:
        raise ValueError("Invalid token_id")
    if not isinstance(tx_ref, str) or len(tx_ref) > 128:
        raise ValueError("Invalid tx_ref")
    now_ts = int(time.time())
    lock = get_striped_lock(db_path, caller.tenant_id, f"token:{token_id}")
    with lock:
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, token_id, caller.tenant_id),
            )
            row = conn.execute(
                "SELECT purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (token_id, caller.tenant_id),
            ).fetchone()
            if not row:
                conn.rollback()
                raise LookupError("Override token not found")
            if cur.rowcount == 0:
                conn.rollback()
                return {
                    "redeemed": False,
                    "token_id": token_id,
                    "reason": "TOKEN_ALREADY_USED",
                }

            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    now_ts,
                    json.dumps({"token_id": token_id, "tx_ref": tx_ref, "purpose": row["purpose"]}),
                ),
            )
            conn.commit()
            return {
                "redeemed": True,
                "token_id": token_id,
                "purpose": row["purpose"],
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

    perm_epoch, _, _ = get_tenant_epochs(db_path, tenant_id)
    t_meta = _get_tenant_meta(db_path, tenant_id, perm_epoch)
    if not t_meta or t_meta[0] != "ACTIVE":
        raise AuthError("Unknown webhook tenant", 403)

    webhook_secret = t_meta[1]
    signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}"
    expected_sig = hmac.new(
        webhook_secret.encode("utf-8"),
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
    raw_amt = payload.get("amount_cents", 0)
    amount_cents = require_strict_int(raw_amt, "amount_cents", min_val=0)
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
