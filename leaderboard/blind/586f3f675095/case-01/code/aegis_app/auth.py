# -*- coding: utf-8 -*-
"""租户身份认证、有效权限（含临时借调委托链）汇总与清算回调验签门面。

加固要点：
* 未知租户/未知用户/错误令牌统一经过 **dummy 常量时间摘要掩蔽**（``hmac.compare_digest``），
  响应与耗时不再泄漏“用户是否存在”；
* 认证上下文按 (perm 纪元, 时间秒) 缓存，单次检索循环不再逐文档重算权限（原版每次候选逐条计算）；
* 回调验签常量时间比较、时间窗 ±300s、Nonce 原子防重放。
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import time
from typing import Any

from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule, WallChecker
from .config import (
    CACHE_MAX_CRED,
    MAX_ID_CHARS,
    ROLE_DEFAULT_CLEARANCE,
    WEBHOOK_TOLERANCE_SECONDS,
)
from .db import GatewayDB, hash_api_token, open_connection, SharedResources
from .delegation import (
    create_or_revoke_delegation,
    resolve_active_delegated_roles,
    resolve_base_and_explicit_roles,
    resolve_roles_cached,
)
from .guards import GuardError, guard_json_obj, guard_text

# 未知租户/用户时用于恒定时间比较的哑摘要
_DUMMY_HASH = hashlib.sha256(b"aegis-dummy-token-masking-salt").hexdigest()


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
    db: GatewayDB | None = None
    shared: SharedResources | None = None
    _checker: WallChecker | None = field(default=None, repr=False)

    def wall(self) -> WallChecker:
        if self._checker is None:
            if self.shared is not None:
                self._checker = WallChecker(self.shared, self.tenant_id, self.user_id, self.org_node_id)
            else:
                c = WallChecker.__new__(WallChecker)
                c.shared = None  # type: ignore[assignment]
                c.tenant_id = self.tenant_id
                c.user_id = self.user_id
                c.lineage = []
                self._checker = c
        return self._checker

    def blocked(self, doc_id: str | None) -> bool:
        if doc_id is None:
            return False
        if self.shared is not None:
            return self.wall().blocked(doc_id)
        return is_doc_blocked_by_wall(self.db.path if self.db else "", self.tenant_id, self.user_id, doc_id)


def resolve_effective_permissions(
    db_path: str,
    tenant_id: str,
    user_id: str,
    *,
    at_ts: int | None = None,
    db: GatewayDB | None = None,
) -> tuple[set[str], int]:
    """合并原生角色（岗位/组织继承/显式授予）与 at_ts 时有效且未级联失效的借调角色。

    独立调用方语义与原版一致：一次性读取全部关联行后逐行判定（结果在可观察层面等价）。
    """
    eval_ts = int(at_ts if at_ts is not None else time.time())
    work = db if (db is not None and db.path == db_path) else GatewayDB(db_path)
    try:
        by_user = {r["user_id"]: r for r in work.rows(
            "SELECT user_id, base_role, org_node_id, active FROM users WHERE tenant_id = ?",
            (tenant_id,),
        )}
        u_row = by_user.get(user_id)
        if u_row is None or not u_row["active"]:
            return set(), 0
        roles = _native_roles(work, tenant_id, user_id)
        if not roles:
            return set(), 0
        roles |= _delegated_roles(work, tenant_id, user_id, eval_ts, by_user)
        return roles, max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
    finally:
        if work is not db:
            work.close_thread()


def _delegated_roles(work: GatewayDB, tenant_id: str, user_id: str, eval_ts: int,
                     by_user: dict[str, Any]) -> set[str]:
    """1..MAX_DELEGATION_HOPS 跳传递借调（与原版逐跳回溯语义一致，但有向环路天然免疫）。"""
    from .config import MAX_DELEGATION_HOPS

    edges = work.rows(
        "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
        "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
        (tenant_id,),
    )
    upstream: dict[tuple[str, str], list[str]] = {}
    for e in edges:
        try:
            s_ts = int(e["starts_at"])
            e_ts = int(e["expires_at"])
        except (TypeError, ValueError):
            continue
        if not (s_ts <= eval_ts < e_ts):
            continue
        gid = str(e["grantor_user_id"])
        u_row = by_user.get(gid)
        if u_row is None or int(u_row["active"]) != 1:
            continue
        upstream.setdefault((e["grantee_user_id"], str(e["delegated_role"])), []).append(gid)

    native_cache: dict[str, set[str]] = {}

    def native(uid: str) -> set[str]:
        hit = native_cache.get(uid)
        if hit is None:
            hit = _native_roles(work, tenant_id, uid)
            native_cache[uid] = hit
        return hit

    candidate_roles: set[str] = set()
    for e in edges:
        if e["grantee_user_id"] != user_id:
            continue
        try:
            if int(e["starts_at"]) <= eval_ts < int(e["expires_at"]):
                candidate_roles.add(str(e["delegated_role"]))
        except (TypeError, ValueError):
            continue

    effective: set[str] = set()
    for role_name in candidate_roles:
        chain: list[tuple[str, int]] = []

        def _walk(uid: str, depth: int) -> None:
            for gid in upstream.get((uid, role_name), ()):
                nxt = depth + 1
                chain.append((gid, nxt))
                if nxt < MAX_DELEGATION_HOPS:
                    _walk(gid, nxt)

        _walk(user_id, 0)
        for src_uid, hop in chain:
            if 1 <= hop <= MAX_DELEGATION_HOPS and role_name in native(src_uid):
                effective.add(role_name)
                break
    return effective


def _native_roles(work: GatewayDB, tenant_id: str, user_id: str) -> set[str]:
    """岗位原生角色 ∪ 组织树继承角色 ∪ 管理员显式授予角色（不含他人委托）。"""
    u_row = work.one(
        "SELECT org_node_id, base_role, active FROM users WHERE tenant_id = ? AND user_id = ?",
        (tenant_id, user_id),
    )
    if u_row is None or not u_row["active"]:
        return set()
    roles: set[str] = {u_row["base_role"]}
    curr = u_row["org_node_id"]
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        n_row = work.one(
            "SELECT parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
            (tenant_id, curr),
        )
        if n_row is None:
            break
        if n_row["inherited_role"]:
            roles.add(n_row["inherited_role"])
        curr = n_row["parent_node_id"]
    for g in work.rows(
        "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
        (tenant_id, user_id),
    ):
        roles.add(g["granted_role"])
    return roles


def authenticate_caller(
    db_path: str,
    headers: dict[str, str],
    *,
    now_override: int | None = None,
    db: GatewayDB | None = None,
    shared: SharedResources | None = None,
) -> CallerContext:
    """校验请求头凭证并组装带实时借调权限的操作员上下文（dummy 掩蔽 + 纪元缓存）。"""
    norm_headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)
    if len(tenant_id) > MAX_ID_CHARS or len(user_id) > MAX_ID_CHARS or len(raw_token) > 4096:
        raise AuthError("Invalid operator identity", 401)

    req_ts = int(now_override if now_override is not None else time.time())
    presented = hash_api_token(raw_token)
    work = db if db is not None else GatewayDB(db_path)
    try:
        t_row = work.one("SELECT status FROM tenants WHERE tenant_id = ?", (tenant_id,))
        t_ok = bool(t_row) and t_row["status"] == "ACTIVE"
        u_row = work.one(
            "SELECT username, org_node_id, base_role, api_token_hash, active FROM users "
            "WHERE user_id = ? AND tenant_id = ?",
            (user_id, tenant_id),
        )
        stored = u_row["api_token_hash"] if u_row is not None else _DUMMY_HASH
        token_ok = hmac.compare_digest(str(stored), presented)
        u_ok = bool(u_row) and int(u_row["active"]) == 1
        # dummy 掩蔽：无论用户是否存在都完整执行两次摘要比较
        hmac.compare_digest(_DUMMY_HASH, presented)
        if not t_ok:
            raise AuthError("Unknown or inactive tenant", 403)
        if not u_ok:
            raise AuthError("Invalid operator identity", 401)
        if not token_ok:
            raise AuthError("Invalid access token", 401)

        ctx_key = (tenant_id, user_id, req_ts)
        cred = shared.cred_cache if shared is not None else None
        perm_key = (shared.epoch.get("perm"), req_ts) if shared is not None else None
        cached = cred.get(ctx_key) if cred is not None else None
        if cached is not None and cached[0] == perm_key:
            roles, max_cl = cached[1]
        else:
            fp = _perm_fp(shared, req_ts)
            roles = set(resolve_roles_cached(work, tenant_id, user_id, fp)) if shared is not None \
                else resolve_base_and_explicit_roles(db_path, tenant_id, user_id, db=work)
            if roles:
                delegated = resolve_active_delegated_roles(db_path, tenant_id, user_id, req_ts,
                                                           db=work, perm_fp=fp)
            else:
                delegated = set()
            roles = roles | delegated
            max_cl = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
            if cred is not None:
                if len(cred) >= CACHE_MAX_CRED:
                    for old in list(cred)[: CACHE_MAX_CRED // 4]:
                        cred.pop(old, None)
                cred[ctx_key] = (perm_key, (roles, max_cl))
        return CallerContext(
            tenant_id=tenant_id,
            user_id=user_id,
            username=u_row["username"],
            org_node_id=u_row["org_node_id"],
            effective_roles=roles,
            max_clearance=max_cl,
            request_ts=req_ts,
            db=work,
            shared=shared,
        )
    finally:
        if db is None:
            work.close_thread()


def _perm_fp(shared: SharedResources, req_ts: int) -> bytes:
    return shared.epoch.get("perm").to_bytes(8, "big") + (req_ts & 0xFFFFFFFF).to_bytes(4, "big")


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
    guard_text(doc_id, name="doc_id", max_chars=MAX_ID_CHARS)
    guard_text(subject_id, name="subject_id", max_chars=MAX_ID_CHARS)
    shared = caller.shared
    return upsert_doc_acl_rule(
        db_path,
        caller.tenant_id,
        doc_id=doc_id,
        subject_type=subject_type,
        subject_id=subject_id,
        effect=effect,
        active=active,
        db=caller.db,
        epoch=shared.epoch if shared is not None else None,
        now_ts=caller.request_ts,
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
            db=caller.db,
        )
    except PermissionError as exc:
        raise AuthError(str(exc), 403) from exc
    finally:
        shared = caller.shared
        if shared is not None:
            shared.epoch.bump("perm")


def revoke_or_grant_role(
    db_path: str,
    caller: CallerContext,
    *,
    target_user_id: str,
    role_name: str,
    action: str,
) -> dict[str, Any]:
    """授予或撤回成员角色；撤权后其下游借调资格按 perm 纪元立即级联失效。"""
    require_admin(caller)
    if role_name not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    now_ts = int(caller.request_ts)
    work = caller.db if caller.db is not None else GatewayDB(db_path)

    def _tx(conn):
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
        return changed

    changed = work.write(_tx)
    if caller.shared is not None:
        caller.shared.epoch.bump("perm")

    eff_roles, eff_cl = resolve_effective_permissions(
        db_path,
        caller.tenant_id,
        target_user_id,
        at_ts=now_ts,
        db=work,
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
    db: GatewayDB | None = None,
) -> dict[str, Any]:
    """验证外部清算中心回调签名（HMAC-SHA256 常量时间 + ±300s 窗口 + Nonce 原子防重放）。"""
    norm_headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(tenant_id) > MAX_ID_CHARS or len(nonce) > MAX_ID_CHARS or len(sig_header) > 256:
        raise AuthError("Malformed webhook headers", 400)
    if not (ts_str.isdigit() or (ts_str.startswith("-") and ts_str[1:].isdigit())) or len(ts_str) > 19:
        raise AuthError("Malformed webhook timestamp", 400)
    callback_ts = int(ts_str)

    work = db if db is not None else GatewayDB(db_path)
    try:
        t_row = work.one("SELECT webhook_secret, status FROM tenants WHERE tenant_id = ?", (tenant_id,))
        secret = t_row["webhook_secret"] if t_row is not None else "whsec_dummy_constant_time_masking"
        active = bool(t_row) and t_row["status"] == "ACTIVE"
        signing_input = f"{tenant_id}.{callback_ts}.{nonce}.{raw_body}"
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).hexdigest()
        provided_sig = sig_header.removeprefix("sha256=").strip().lower()
        sig_ok = hmac.compare_digest(provided_sig, expected_sig)
        if not active:
            raise AuthError("Unknown webhook tenant", 403)
        if not sig_ok:
            raise AuthError("Webhook signature verification failed", 401)

        now_ts = int(now_override if now_override is not None else time.time())
        if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
            raise AuthError("Webhook timestamp outside tolerance window", 401)

        payload = guard_json_obj(raw_body) if isinstance(raw_body, str) else {}
        settlement_ref = str(payload.get("settlement_ref") or "")
        raw_amount = payload.get("amount_cents")
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
            raise ValueError("Invalid settlement payload fields")
        amount_cents = int(raw_amount or 0)
        if not settlement_ref or len(settlement_ref) > MAX_ID_CHARS or amount_cents < 0:
            raise ValueError("Invalid settlement payload fields")

        def _tx(conn):
            if conn.execute(
                "SELECT 1 FROM webhook_events WHERE tenant_id = ? AND nonce = ? LIMIT 1",
                (tenant_id, nonce),
            ).fetchone():
                # 串行重放：提前失败，不写任何行
                raise AuthError("Webhook nonce already processed", 401)
            conn.execute(
                "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
            )

        try:
            work.write(_tx)
        except Exception as exc:  # 并发重放：唯一插入在 IMMEDIATE 事务内原子判重
            if "UNIQUE" in str(exc).upper():
                raise AuthError("Webhook nonce already processed", 401) from exc
            raise
        return {
            "acknowledged": True,
            "tenant_id": tenant_id,
            "settlement_ref": settlement_ref,
            "amount_cents": amount_cents,
        }
    finally:
        if db is None:
            work.close_thread()


__all__ = [
    "AuthError", "CallerContext", "authenticate_caller", "require_admin",
    "resolve_effective_permissions", "configure_doc_acl_rule", "manage_role_delegation",
    "revoke_or_grant_role", "process_settlement_webhook", "is_doc_blocked_by_acl",
]
