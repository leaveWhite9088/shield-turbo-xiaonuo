# -*- coding: utf-8 -*-
"""租户身份认证、组织层级权限汇总、利益冲突隔离墙核验与配额/回调管理模块。"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any

from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
from .db import ConflictError, get_thread_connection, hash_api_token
from .runtime import (
    CachedUserRecord,
    OrgTreeSnapshot,
    TenantAclSnapshot,
    get_db_runtime,
)


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


def _get_tenant_info(db_path: str, tenant_id: str) -> tuple[str, str] | None:
    """获取 (status, webhook_secret)，带分租户缓存。"""
    tr = get_db_runtime(db_path).tenant(tenant_id)
    with tr.lock:
        if tr.tenant_info is not None:
            return tr.tenant_info
    conn = get_thread_connection(db_path)
    row = conn.execute(
        "SELECT status, webhook_secret FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    if not row:
        return None
    info = (str(row["status"]), str(row["webhook_secret"]))
    with tr.lock:
        tr.tenant_info = info
    return info


def _get_user_record(db_path: str, tenant_id: str, user_id: str) -> CachedUserRecord | None:
    tr = get_db_runtime(db_path).tenant(tenant_id)
    with tr.lock:
        cached = tr.users.get(user_id)
        if cached is not None:
            return cached
    conn = get_thread_connection(db_path)
    row = conn.execute(
        "SELECT user_id, tenant_id, username, org_node_id, base_role, api_token_hash, active "
        "FROM users WHERE user_id = ? AND tenant_id = ?",
        (user_id, tenant_id),
    ).fetchone()
    if not row:
        return None
    rec = CachedUserRecord(
        user_id=str(row["user_id"]),
        tenant_id=str(row["tenant_id"]),
        username=str(row["username"]),
        org_node_id=str(row["org_node_id"]),
        base_role=str(row["base_role"]),
        api_token_hash=str(row["api_token_hash"]),
        active=int(row["active"]),
    )
    with tr.lock:
        tr.users[user_id] = rec
    return rec


def _get_org_tree(db_path: str, tenant_id: str) -> OrgTreeSnapshot:
    """一次性加载并预计算租户组织架构树的祖先链与继承角色集合。"""
    tr = get_db_runtime(db_path).tenant(tenant_id)
    with tr.lock:
        if tr.org_tree is not None:
            return tr.org_tree

    conn = get_thread_connection(db_path)
    rows = conn.execute(
        "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchall()

    parent_map: dict[str, str | None] = {}
    role_map: dict[str, str | None] = {}
    for r in rows:
        nid = str(r["node_id"])
        parent_map[nid] = str(r["parent_node_id"]) if r["parent_node_id"] else None
        role_map[nid] = str(r["inherited_role"]) if r["inherited_role"] else None

    ancestors_by_node: dict[str, tuple[str, ...]] = {}
    inherited_roles_by_node: dict[str, frozenset[str]] = {}

    for nid in parent_map:
        chain: list[str] = []
        roles: set[str] = set()
        curr: str | None = nid
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            chain.append(curr)
            r_name = role_map.get(curr)
            if r_name:
                roles.add(r_name)
            curr = parent_map.get(curr)
        ancestors_by_node[nid] = tuple(chain)
        inherited_roles_by_node[nid] = frozenset(roles)

    snap = OrgTreeSnapshot(
        ancestors_by_node=ancestors_by_node,
        inherited_roles_by_node=inherited_roles_by_node,
    )
    with tr.lock:
        tr.org_tree = snap
    return snap


def resolve_org_ancestors(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """沿组织架构树向上遍历，返回当前部门及所有上级部门节点 ID 列表。"""
    if not start_node_id:
        return []
    tree = _get_org_tree(db_path, tenant_id)
    chain = tree.ancestors_by_node.get(start_node_id)
    if chain is not None:
        return list(chain)
    return [start_node_id]


def get_tenant_acl_snapshot(db_path: str, tenant_id: str) -> TenantAclSnapshot:
    """获取租户级利益冲突隔离墙（Chinese Wall）快照，带 acl_epoch CAS 防竞态回填。"""
    tr = get_db_runtime(db_path).tenant(tenant_id)
    cached = tr.get_cached_acl()
    if cached is not None:
        return cached

    with tr.lock:
        expected_epoch = tr.acl_epoch

    conn = get_thread_connection(db_path)
    rows = conn.execute(
        "SELECT doc_id, subject_type, subject_id FROM doc_acl_rules "
        "WHERE tenant_id = ? AND active = 1 AND effect = 'DENY'",
        (tenant_id,),
    ).fetchall()

    user_map: dict[str, set[str]] = {}
    org_map: dict[str, set[str]] = {}
    for r in rows:
        st = r["subject_type"]
        sid = str(r["subject_id"])
        did = str(r["doc_id"])
        if st == "USER":
            user_map.setdefault(sid, set()).add(did)
        elif st == "ORG_NODE":
            org_map.setdefault(sid, set()).add(did)

    snap = TenantAclSnapshot(
        epoch=expected_epoch,
        user_denies={k: frozenset(v) for k, v in user_map.items()},
        org_denies={k: frozenset(v) for k, v in org_map.items()},
    )
    tr.put_cached_acl(snap)
    return snap


def get_denied_doc_ids(
    db_path: str,
    tenant_id: str,
    user_id: str,
    org_node_id: str,
    *,
    acl_snap: TenantAclSnapshot | None = None,
) -> frozenset[str]:
    """O(组织深度) 计算目标用户受利益冲突墙封禁的全部文档 ID 集合。"""
    snap = acl_snap if acl_snap is not None else get_tenant_acl_snapshot(db_path, tenant_id)
    denied: set[str] = set()
    u_denies = snap.user_denies.get(user_id)
    if u_denies:
        denied.update(u_denies)
    if snap.org_denies and org_node_id:
        tree = _get_org_tree(db_path, tenant_id)
        chain = tree.ancestors_by_node.get(org_node_id, (org_node_id,))
        for nid in chain:
            o_denies = snap.org_denies.get(nid)
            if o_denies:
                denied.update(o_denies)
    return frozenset(denied)


def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """检查目标文档是否对指定用户或其所属组织层级链设置了利益冲突隔离墙（DENY）。"""
    u_rec = _get_user_record(db_path, tenant_id, user_id)
    if not u_rec:
        return True
    denied = get_denied_doc_ids(db_path, tenant_id, user_id, u_rec.org_node_id)
    return doc_id in denied


def configure_doc_acl_rule(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    active: bool = True,
) -> dict[str, Any]:
    """由合规管理员新增或解除文档利益冲突隔离墙规则（Chinese Wall），提交后立即失效 ACL 缓存。"""
    require_admin(caller)
    if subject_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if not doc_id or not subject_id:
        raise ValueError("doc_id and subject_id are required")

    now_ts = int(time.time())
    conn = get_thread_connection(db_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        doc_row = conn.execute(
            "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
            (caller.tenant_id, doc_id),
        ).fetchone()
        if not doc_row:
            conn.execute("ROLLBACK")
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
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    get_db_runtime(db_path).tenant(caller.tenant_id).bump_acl_epoch()

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

    t_info = _get_tenant_info(db_path, tenant_id)
    if not t_info or t_info[0] != "ACTIVE":
        raise AuthError("Unknown or inactive tenant", 403)

    u_rec = _get_user_record(db_path, tenant_id, user_id)
    if not u_rec or not u_rec.active:
        raise AuthError("Invalid operator identity", 401)

    if not hmac.compare_digest(u_rec.api_token_hash, hash_api_token(raw_token)):
        raise AuthError("Invalid access token", 401)

    roles, max_cl = resolve_effective_permissions(db_path, tenant_id, user_id)
    return CallerContext(
        tenant_id=tenant_id,
        user_id=user_id,
        username=u_rec.username,
        org_node_id=u_rec.org_node_id,
        effective_roles=roles,
        max_clearance=max_cl,
    )


def resolve_effective_permissions(db_path: str, tenant_id: str, user_id: str) -> tuple[set[str], int]:
    """沿着组织汇报树向上汇总继承角色，并合并显式授权记录，返回有效角色集合与最高密级。"""
    tr = get_db_runtime(db_path).tenant(tenant_id)
    cached = tr.get_cached_perm(user_id)
    if cached is not None:
        return set(cached[0]), cached[1]

    with tr.lock:
        expected_epoch = tr.perm_epoch

    u_rec = _get_user_record(db_path, tenant_id, user_id)
    if not u_rec or not u_rec.active:
        return set(), 0

    roles: set[str] = {u_rec.base_role}
    tree = _get_org_tree(db_path, tenant_id)
    inherited = tree.inherited_roles_by_node.get(u_rec.org_node_id)
    if inherited:
        roles.update(inherited)

    conn = get_thread_connection(db_path)
    g_rows = conn.execute(
        "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
        (tenant_id, user_id),
    ).fetchall()
    for gr in g_rows:
        roles.add(str(gr["granted_role"]))

    max_clearance = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in roles), default=1)
    tr.put_cached_perm(user_id, expected_epoch, frozenset(roles), max_clearance)
    return roles, max_clearance


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
    """管理员工临时角色授权（支持 grant 与 revoke），提交后立即递增权限版本戳失效缓存。"""
    require_admin(caller)
    if role_name not in ROLE_DEFAULT_CLEARANCE:
        raise ValueError(f"Unsupported role: {role_name}")
    if action not in ("grant", "revoke"):
        raise ValueError("action must be 'grant' or 'revoke'")

    now_ts = int(time.time())
    conn = get_thread_connection(db_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        target = conn.execute(
            "SELECT user_id FROM users WHERE tenant_id = ? AND user_id = ?",
            (caller.tenant_id, target_user_id),
        ).fetchone()
        if not target:
            conn.execute("ROLLBACK")
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
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    get_db_runtime(db_path).tenant(caller.tenant_id).bump_perm_epoch()

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
    """原子扣减租户指定类型的业务配额（细粒度资源锁 + SQLite 条件更新防 TOCTOU 超扣）。"""
    if not quota_type:
        raise ValueError("quota_type is required")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise ValueError("Quota consumption amount must be a positive integer")

    now_ts = int(time.time())
    tr = get_db_runtime(db_path).tenant(caller.tenant_id)
    res_lock = tr.get_resource_lock(f"quota:{quota_type}")

    with res_lock:
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE tenant_quotas "
                "SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amount, now_ts, caller.tenant_id, quota_type, amount),
            )
            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, quota_type),
                ).fetchone()
                conn.execute("ROLLBACK")
                if not row:
                    raise LookupError(f"Quota bucket not found: {quota_type}")
                return {
                    "accepted": False,
                    "quota_type": quota_type,
                    "remaining_quota": int(row["remaining_quota"]),
                    "reason": "QUOTA_EXHAUSTED",
                }

            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, quota_type),
            ).fetchone()
            new_rem = int(row["remaining_quota"])
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
            conn.execute("COMMIT")
            return {
                "accepted": True,
                "quota_type": quota_type,
                "consumed": amount,
                "remaining_quota": new_rem,
            }
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    """原子核销单次使用的风控应急放行令牌（细粒度资源锁 + CAS 条件更新防并发重放）。"""
    if not token_id:
        raise ValueError("token_id is required")

    now_ts = int(time.time())
    tr = get_db_runtime(db_path).tenant(caller.tenant_id)
    res_lock = tr.get_resource_lock(f"override_token:{token_id}")

    with res_lock:
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE override_tokens "
                "SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, token_id, caller.tenant_id),
            )
            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT token_id, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                    (token_id, caller.tenant_id),
                ).fetchone()
                conn.execute("ROLLBACK")
                if not row:
                    raise LookupError("Override token not found")
                return {
                    "redeemed": False,
                    "token_id": token_id,
                    "reason": "TOKEN_ALREADY_USED",
                }

            row = conn.execute(
                "SELECT purpose FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (token_id, caller.tenant_id),
            ).fetchone()
            purpose = str(row["purpose"])
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    now_ts,
                    json.dumps({"token_id": token_id, "tx_ref": tx_ref, "purpose": purpose}),
                ),
            )
            conn.execute("COMMIT")
            return {
                "redeemed": True,
                "token_id": token_id,
                "purpose": purpose,
                "tx_ref": tx_ref,
            }
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


def process_settlement_webhook(
    db_path: str,
    headers: dict[str, str],
    raw_body: str,
    *,
    now_override: int | None = None,
) -> dict[str, Any]:
    """验证外部清算中心回调签名、时间戳窗口与 Nonce 防重放后登记入账通知。"""
    norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
    tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
    ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
    nonce = (norm_headers.get("x-aegis-nonce") or "").strip()
    sig_header = (norm_headers.get("x-aegis-signature") or "").strip()

    if not tenant_id or not ts_str or not nonce or not sig_header:
        raise AuthError("Missing webhook signature headers", 401)
    if len(nonce) > 128:
        raise ValueError("Webhook nonce exceeds maximum length")

    try:
        callback_ts = int(ts_str)
    except ValueError as exc:
        raise AuthError("Malformed webhook timestamp", 400) from exc

    now_ts = int(now_override if now_override is not None else time.time())
    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise AuthError("Webhook timestamp outside permitted replay window", 401)

    t_info = _get_tenant_info(db_path, tenant_id)
    if not t_info or t_info[0] != "ACTIVE":
        raise AuthError("Unknown webhook tenant", 403)
    webhook_secret = t_info[1]

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
    raw_amt = payload.get("amount_cents")
    if isinstance(raw_amt, bool) or raw_amt is None:
        amount_cents = 0
    else:
        amount_cents = int(raw_amt)
    if not settlement_ref or amount_cents < 0:
        raise ValueError("Invalid settlement payload fields")

    conn = get_thread_connection(db_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_body, now_ts),
        )
        conn.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise ConflictError("Duplicate webhook nonce detected (replay rejected)", 409) from exc
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    return {
        "acknowledged": True,
        "tenant_id": tenant_id,
        "settlement_ref": settlement_ref,
        "amount_cents": amount_cents,
    }
