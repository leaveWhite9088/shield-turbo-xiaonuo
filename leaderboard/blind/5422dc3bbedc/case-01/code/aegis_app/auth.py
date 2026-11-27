# -*- coding: utf-8 -*-
"""租户身份认证、有效权限（含临时借调委托链）汇总与合作方回调验签门面模块。

安全契约：
- API 令牌哈希比较使用 hmac.compare_digest 常量时间比较；
- Webhook 采用常量时间 HMAC 验签 + ±300s 时间窗校验 + BEGIN IMMEDIATE 串行化的
  逐租户 Nonce 防重放（并发/串行重放一律拒绝）；
- 用户/租户/组织树等静态结构走进程内缓存，认证热路径零数据库往返。
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import coerce_strict_int, hash_api_token, immediate_transaction, open_connection
from .delegation import (
    create_or_revoke_delegation,
    resolve_active_delegated_roles,
    resolve_base_and_explicit_roles,
)
from .index_cache import get_state


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
    """校验请求头凭证并组装带实时借调权限的操作员上下文。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)
    if len(tenant_id) > 128 or len(user_id) > 128 or len(raw_token) > 256:
        raise AuthError("Invalid authentication headers", 401)

    req_ts = int(now_override if now_override is not None else time.time())
    state = get_state(db_path)
    t_row = state.tenant_rows().get(tenant_id)
    if not t_row or t_row["status"] != "ACTIVE":
        raise AuthError("Unknown or inactive tenant", 403)

    tstate = state.tenant(tenant_id)
    u_row = tstate.users(db_path).get(user_id)
    if not u_row or not u_row["active"]:
        raise AuthError("Invalid operator identity", 401)

    provided_hash = hash_api_token(raw_token)
    if not hmac.compare_digest(u_row["api_token_hash"], provided_hash):
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
        username=u_row["username"],
        org_node_id=u_row["org_node_id"],
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

    # 撤权即时级联：delegation 解析在请求期动态校验源头原生角色，此处仅需递增纪元
    get_state(db_path).tenant(caller.tenant_id).bump_grants()

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
    """验证外部清算中心回调签名并登记入账通知（常量时间验签 + 时间窗 + Nonce 防重放）。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(nonce) > 128 or len(tenant_id) > 128:
        raise AuthError("Invalid webhook signature headers", 401)
    if len(raw_body.encode("utf-8", "ignore")) > 65536:
        raise AuthError("Webhook payload too large", 400)

    try:
        callback_ts = coerce_strict_int(ts_str, field="webhook timestamp")
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    conn = open_connection(db_path)
    try:
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

        provided_sig = sig_header.removeprefix("sha256=").strip()
        # 常量时间比较，消除逐字节早退时序侧信道
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise AuthError("Webhook signature verification failed", 401)

        now_ts = int(now_override if now_override is not None else time.time())
        # ±300s 时间窗：过旧 / 超前报文一律拒绝
        if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
            raise AuthError("Webhook timestamp outside tolerance window", 400)

        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("Malformed webhook payload")
        if not isinstance(payload, dict):
            raise ValueError("Webhook payload must be an object")
        settlement_ref = str(payload.get("settlement_ref") or "")
        try:
            amount_cents = coerce_strict_int(payload.get("amount_cents"), 0, field="amount_cents")
        except ValueError as exc:
            raise ValueError("Invalid settlement payload fields") from exc
        if not settlement_ref or len(settlement_ref) > 256 or amount_cents < 0:
            raise ValueError("Invalid settlement payload fields")

        # BEGIN IMMEDIATE 串行化去重：并发/串行重复 Nonce 严格仅首个成功入账
        with immediate_transaction(conn):
            dup = conn.execute(
                "SELECT 1 FROM webhook_events WHERE tenant_id = ? AND nonce = ? LIMIT 1",
                (tenant_id, nonce),
            ).fetchone()
            if dup:
                raise AuthError("Webhook nonce replay detected", 409)
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )
        return {
            "acknowledged": True,
            "tenant_id": tenant_id,
            "settlement_ref": settlement_ref,
            "amount_cents": amount_cents,
        }
    finally:
        conn.close()
