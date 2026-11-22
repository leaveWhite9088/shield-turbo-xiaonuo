# -*- coding: utf-8 -*-
"""租户身份认证、组织层级权限汇总、利益冲突隔离墙核验与配额/回调管理模块。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import time
from typing import Any

from .config import ROLE_DEFAULT_CLEARANCE
from .db import hash_api_token, open_connection


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


def resolve_org_ancestors(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """沿组织架构树向上遍历，返回当前部门及所有上级部门节点 ID 列表。"""
    ancestors: list[str] = []
    curr = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        ancestors.append(curr)
        conn = open_connection(db_path)
        try:
            row = conn.execute(
                "SELECT parent_node_id FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                (tenant_id, curr),
            ).fetchone()
            curr = row["parent_node_id"] if row else None
        finally:
            conn.close()
    return ancestors


def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """检查目标文档是否对指定用户或其所属组织层级链设置了利益冲突隔离墙（DENY）。"""
    conn = open_connection(db_path)
    try:
        u_row = conn.execute(
            "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        ).fetchone()
        if not u_row:
            return True
        org_chain = resolve_org_ancestors(db_path, tenant_id, u_row["org_node_id"])
        acl_rows = conn.execute(
            "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
            (tenant_id, doc_id),
        ).fetchall()
        for r in acl_rows:
            if r["effect"] != "DENY":
                continue
            if r["subject_type"] == "USER" and r["subject_id"] == user_id:
                return True
            if r["subject_type"] == "ORG_NODE" and r["subject_id"] in org_chain:
                return True
        return False
    finally:
        conn.close()


def configure_doc_acl_rule(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员新增或解除文档利益冲突隔离墙规则（Chinese Wall）。"""
    require_admin(caller)
    if subject_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    now_ts = int(time.time())
    conn = open_connection(db_path)
    try:
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
    finally:
        conn.close()

    return {
        "tenant_id": caller.tenant_id,
        "doc_id": doc_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "effect": "DENY",
        "active": bool(active),
    }


def authenticate_caller(db_path: str, headers: dict[str, str]) -> CallerContext:
    """校验请求头中的租户与操作员访问凭证，并解析有效角色集合。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    user_id = (norm_headers.get("x-aegis-user") or "").strip()
    raw_token = (norm_headers.get("x-aegis-token") or "").strip()

    if not tenant_id or not user_id or not raw_token:
        raise AuthError("Missing authentication headers", 401)

    conn = open_connection(db_path)
    try:
        t_row = conn.execute(
            "SELECT tenant_id, status FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if not t_row or t_row["status"] != "ACTIVE":
            raise AuthError("Unknown or inactive tenant", 403)

        u_row = conn.execute(
            "SELECT user_id, tenant_id, username, org_node_id, base_role, api_token_hash, active "
            "FROM users WHERE user_id = ? AND tenant_id = ?",
            (user_id, tenant_id),
        ).fetchone()
        if not u_row or not u_row["active"]:
            raise AuthError("Invalid operator identity", 401)

        if u_row["api_token_hash"] != hash_api_token(raw_token):
            raise AuthError("Invalid access token", 401)

        roles, max_cl = resolve_effective_permissions(db_path, tenant_id, user_id)
        return CallerContext(
            tenant_id=tenant_id,
            user_id=user_id,
            username=u_row["username"],
            org_node_id=u_row["org_node_id"],
            effective_roles=roles,
            max_clearance=max_cl,
        )
    finally:
        conn.close()


def resolve_effective_permissions(db_path: str, tenant_id: str, user_id: str) -> tuple[set[str], int]:
    """沿着组织汇报树向上汇总继承角色，并合并显式授权记录，返回有效角色集合与最高密级。"""
    conn = open_connection(db_path)
    try:
        u_row = conn.execute(
            "SELECT org_node_id, base_role FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        ).fetchone()
        if not u_row:
            return set(), 0

        roles: set[str] = {u_row["base_role"]}
        for anc_node_id in resolve_org_ancestors(db_path, tenant_id, u_row["org_node_id"]):
            n_row = conn.execute(
                "SELECT inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                (tenant_id, anc_node_id),
            ).fetchone()
            if n_row and n_row["inherited_role"]:
                roles.add(n_row["inherited_role"])

        g_rows = conn.execute(
            "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        ).fetchall()
        for gr in g_rows:
            roles.add(gr["granted_role"])

        max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
        return roles, max_clearance
    finally:
        conn.close()


def require_admin(caller: CallerContext) -> None:
    if "COMPLIANCE_ADMIN" not in caller.effective_roles:
        raise AuthError("COMPLIANCE_ADMIN role required", 403)


def revoke_or_grant_role(
    db_path: str,
    caller: CallerContext,
    *,
    target_user_id: str,
    role_name: str,
    action: str,
) -> dict[str, Any]:
    """管理员工临时角色授权（支持 grant 与 revoke）。"""
    require_admin(caller)
    if role_name not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    now_ts = int(time.time())
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
    amount: int = 1,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度。"""
    if amount <= 0:
        raise ValueError("Quota consumption amount must be positive")
    now_ts = int(time.time())
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
            (caller.tenant_id, quota_type),
        ).fetchone()
        if not row:
            raise LookupError(f"Quota bucket not found: {quota_type}")

        current_rem = int(row["remaining_quota"])
        if current_rem < amount:
            return {
                "accepted": False,
                "quota_type": quota_type,
                "remaining_quota": current_rem,
                "reason": "QUOTA_EXHAUSTED",
            }

        new_rem = current_rem - amount
        conn.execute(
            "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
            "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
            (
                caller.tenant_id,
                caller.user_id,
                amount,
                now_ts,
                json.dumps({"quota_type": quota_type, "consumed": amount, "remaining": new_rem}),
            ),
        )
        conn.execute(
            "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
            (new_rem, now_ts, caller.tenant_id, quota_type),
        )
        conn.commit()
        return {
            "accepted": True,
            "quota_type": quota_type,
            "consumed": amount,
            "remaining_quota": new_rem,
        }
    finally:
        conn.close()


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    """核销单次使用的风控应急放行令牌。"""
    now_ts = int(time.time())
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT token_id, tenant_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
            (token_id, caller.tenant_id),
        ).fetchone()
        if not row:
            raise LookupError("Override token not found")
        if int(row["used"]) != 0:
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
        conn.execute(
            "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? WHERE token_id = ? AND tenant_id = ?",
            (caller.user_id, now_ts, token_id, caller.tenant_id),
        )
        conn.commit()
        return {
            "redeemed": True,
            "token_id": token_id,
            "purpose": row["purpose"],
            "tx_ref": tx_ref,
        }
    finally:
        conn.close()


def process_settlement_webhook(
    db_path: str,
    headers: dict[str, str],
    raw_body: str,
    *,
    now_override: int | None = None,
) -> dict[str, Any]:
    """验证外部清算中心回调签名并登记入账通知。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)

    try:
        callback_ts = int(ts_str)
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
        if provided_sig != expected_sig:
            raise AuthError("Webhook signature verification failed", 401)

        payload = json.loads(raw_body)
        settlement_ref = str(payload.get("settlement_ref") or "")
        amount_cents = int(payload.get("amount_cents") or 0)
        if not settlement_ref or amount_cents < 0:
            raise ValueError("Invalid settlement payload fields")

        now_ts = int(now_override if now_override is not None else time.time())
        conn.execute(
            "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
        )
        conn.commit()
        return {
            "acknowledged": True,
            "tenant_id": tenant_id,
            "settlement_ref": settlement_ref,
            "amount_cents": amount_cents,
        }
    finally:
        conn.close()
