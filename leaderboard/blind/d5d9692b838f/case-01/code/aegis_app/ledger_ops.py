# -*- coding: utf-8 -*-
"""租户配额原子扣减、无死锁偏序跨池调拨（Quota Transfer）与单次应急放行令牌核销服务。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET, INT64_MAX
from .db import get_db_hub, write_transaction
from .middleware import strict_int


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """独立调用入口：遵循 Layer 2 -> Layer 3 偏序从 REALTIME_ALERT_POOL 原子扣减 1 点配额。"""
    ts_val = strict_int(now_ts, "now_ts", min_val=0)
    hub = get_db_hub(db_path)
    with hub.quota_locks(tenant_id, ALERT_QUOTA_BUCKET):
        with write_transaction(db_path) as conn:
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
                (ts_val, tenant_id, ALERT_QUOTA_BUCKET),
            )
            return cur.rowcount == 1


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: Any = 1,
) -> dict[str, Any]:
    """按 Layer 2 (quota_locks) -> Layer 3 (BEGIN IMMEDIATE) 严格原子扣减业务配额，杜绝并发超扣。"""
    q_type = str(quota_type or "").strip()
    if not q_type or len(q_type) > 128:
        raise ValueError("Valid quota_type is required")
    amt = strict_int(amount, "amount", min_val=1, max_val=INT64_MAX)
    now_ts = int(caller.request_ts or int(time.time()))

    hub = get_db_hub(db_path)
    with hub.quota_locks(caller.tenant_id, q_type):
        with write_transaction(db_path) as conn:
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, q_type),
            ).fetchone()
            if not row:
                raise LookupError(f"Quota bucket not found: {q_type}")

            current_rem = int(row["remaining_quota"])
            if current_rem < amt:
                return {
                    "accepted": False,
                    "quota_type": q_type,
                    "remaining_quota": current_rem,
                    "reason": "QUOTA_EXHAUSTED",
                }

            new_rem = current_rem - amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (new_rem, now_ts, caller.tenant_id, q_type),
            )
            conn.execute(
                "INSERT INTO audit_logs("
                "tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json"
                ") VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    amt,
                    now_ts,
                    json.dumps({"quota_type": q_type, "consumed": amt, "remaining": new_rem}),
                ),
            )
            return {
                "accepted": True,
                "quota_type": q_type,
                "consumed": amt,
                "remaining_quota": new_rem,
            }


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: Any,
) -> dict[str, Any]:
    """跨配额池原子额度调拨：遵循全局统一条带升序加锁 + BEGIN IMMEDIATE，高并发双向调拨零死锁且总额严格守恒。"""
    require_admin(caller)
    src_q = str(from_quota or "").strip()
    dst_q = str(to_quota or "").strip()
    if not src_q or not dst_q or src_q == dst_q or len(src_q) > 128 or len(dst_q) > 128:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    amt = strict_int(amount, "amount", min_val=1, max_val=INT64_MAX)
    now_ts = int(caller.request_ts or int(time.time()))

    hub = get_db_hub(db_path)
    with hub.quota_locks(caller.tenant_id, src_q, dst_q):
        with write_transaction(db_path) as conn:
            src_row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, src_q),
            ).fetchone()
            dst_row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, dst_q),
            ).fetchone()
            if not src_row or not dst_row:
                raise LookupError("Source or destination quota pool not found")

            src_rem = int(src_row["remaining_quota"])
            dst_rem = int(dst_row["remaining_quota"])
            if src_rem < amt:
                return {
                    "transferred": False,
                    "from_quota": src_q,
                    "to_quota": dst_q,
                    "from_remaining": src_rem,
                    "to_remaining": dst_rem,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }
            if dst_rem + amt > INT64_MAX:
                raise ValueError("Destination quota balance overflow")

            new_src = src_rem - amt
            new_dst = dst_rem + amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (new_src, now_ts, caller.tenant_id, src_q),
            )
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (new_dst, now_ts, caller.tenant_id, dst_q),
            )
            conn.execute(
                "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, caller.user_id, src_q, dst_q, amt, now_ts),
            )
            return {
                "transferred": True,
                "from_quota": src_q,
                "to_quota": dst_q,
                "amount": amt,
                "from_remaining": new_src,
                "to_remaining": new_dst,
            }


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    """并发安全单次应急放行令牌核销（CAS 条件更新 + BEGIN IMMEDIATE，严格仅成功一次）。"""
    tok_id = str(token_id or "").strip()
    clean_ref = str(tx_ref or "").strip()
    if not tok_id or len(tok_id) > 128 or len(clean_ref) > 256:
        raise ValueError("Valid token_id is required")
    now_ts = int(caller.request_ts or int(time.time()))

    hub = get_db_hub(db_path)
    with hub.token_lock(caller.tenant_id):
        with write_transaction(db_path) as conn:
            row = conn.execute(
                "SELECT purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (tok_id, caller.tenant_id),
            ).fetchone()
            if not row:
                raise LookupError("Override token not found")
            if int(row["used"]) != 0:
                return {
                    "redeemed": False,
                    "token_id": tok_id,
                    "reason": "TOKEN_ALREADY_USED",
                }

            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, tok_id, caller.tenant_id),
            )
            if cur.rowcount != 1:
                return {
                    "redeemed": False,
                    "token_id": tok_id,
                    "reason": "TOKEN_ALREADY_USED",
                }

            purpose = str(row["purpose"])
            conn.execute(
                "INSERT INTO audit_logs("
                "tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json"
                ") VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    now_ts,
                    json.dumps({"token_id": tok_id, "tx_ref": clean_ref, "purpose": purpose}),
                ),
            )
            return {
                "redeemed": True,
                "token_id": tok_id,
                "purpose": purpose,
                "tx_ref": clean_ref,
            }
