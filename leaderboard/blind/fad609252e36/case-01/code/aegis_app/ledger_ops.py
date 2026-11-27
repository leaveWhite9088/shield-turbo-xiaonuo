# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池无死锁字典序调拨（Quota Transfer）与单次应急放行令牌原子核销服务。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET, INT64_MAX
from .db import acquire_quota_locks, get_tenant_token_lock, open_connection
from .middleware import strict_int


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 原子尝试扣减 1 点实时告警配额。"""
    ts_val = strict_int(now_ts, "now_ts", min_val=0)
    with acquire_quota_locks(db_path, tenant_id, ALERT_QUOTA_BUCKET):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (tenant_id, ALERT_QUOTA_BUCKET),
            ).fetchone()
            if not row or int(row["remaining_quota"]) < 1:
                conn.rollback()
                return False
            new_rem = int(row["remaining_quota"]) - 1
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
                (new_rem, ts_val, tenant_id, ALERT_QUOTA_BUCKET),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度（遵循全局配额池锁偏序 + BEGIN IMMEDIATE）。"""
    q_type = str(quota_type or "").strip()
    if not q_type or len(q_type) > 64:
        raise ValueError("Valid quota_type is required")
    amt = strict_int(amount, "amount", min_val=1, max_val=INT64_MAX // 4)
    now_ts = int(caller.request_ts or int(time.time()))

    with acquire_quota_locks(db_path, caller.tenant_id, q_type):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, q_type),
            ).fetchone()
            if not row:
                raise LookupError(f"Quota bucket not found: {q_type}")

            current_rem = int(row["remaining_quota"])
            if current_rem < amt:
                conn.rollback()
                return {
                    "accepted": False,
                    "quota_type": q_type,
                    "remaining_quota": current_rem,
                    "reason": "QUOTA_EXHAUSTED",
                }

            new_rem = current_rem - amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
                (new_rem, now_ts, caller.tenant_id, q_type),
            )
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    amt,
                    now_ts,
                    json.dumps({"quota_type": q_type, "consumed": amt, "remaining": new_rem}),
                ),
            )
            conn.commit()
            return {
                "accepted": True,
                "quota_type": q_type,
                "consumed": amt,
                "remaining_quota": new_rem,
            }
        finally:
            conn.close()


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: int,
) -> dict[str, Any]:
    """在本租户两个配额池之间原子调拨额度（按字典序对双池加锁 + BEGIN IMMEDIATE，消除双向调拨与风控联动死锁）。"""
    require_admin(caller)
    src_q = str(from_quota or "").strip()
    dst_q = str(to_quota or "").strip()
    if not src_q or not dst_q or src_q == dst_q:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    if len(src_q) > 64 or len(dst_q) > 64:
        raise ValueError("Quota pool name too long")
    amt = strict_int(amount, "amount", min_val=1, max_val=INT64_MAX // 4)
    now_ts = int(caller.request_ts or int(time.time()))

    with acquire_quota_locks(db_path, caller.tenant_id, src_q, dst_q):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
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
                conn.rollback()
                return {
                    "transferred": False,
                    "from_quota": src_q,
                    "to_quota": dst_q,
                    "from_remaining": src_rem,
                    "to_remaining": dst_rem,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }
            if dst_rem + amt > INT64_MAX // 2:
                raise ValueError("Destination quota overflow")

            new_src = src_rem - amt
            new_dst = dst_rem + amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
                (new_src, now_ts, caller.tenant_id, src_q),
            )
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
                (new_dst, now_ts, caller.tenant_id, dst_q),
            )
            conn.execute(
                "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) VALUES (?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, caller.user_id, src_q, dst_q, amt, now_ts),
            )
            conn.commit()
            return {
                "transferred": True,
                "from_quota": src_q,
                "to_quota": dst_q,
                "amount": amt,
                "from_remaining": new_src,
                "to_remaining": new_dst,
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
    """原子核销单次使用的风控应急放行令牌（高并发下严格仅成功核销一次）。"""
    tok = str(token_id or "").strip()
    ref = str(tx_ref or "").strip()
    if not tok or len(tok) > 128:
        raise ValueError("Valid token_id is required")
    if len(ref) > 128:
        raise ValueError("tx_ref too long")

    now_ts = int(caller.request_ts or int(time.time()))
    with get_tenant_token_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT token_id, tenant_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (tok, caller.tenant_id),
            ).fetchone()
            if not row:
                raise LookupError("Override token not found")
            if int(row["used"]) != 0:
                conn.rollback()
                return {
                    "redeemed": False,
                    "token_id": tok,
                    "reason": "TOKEN_ALREADY_USED",
                }

            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, tok, caller.tenant_id),
            )
            if cur.rowcount == 0:
                conn.rollback()
                return {
                    "redeemed": False,
                    "token_id": tok,
                    "reason": "TOKEN_ALREADY_USED",
                }

            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    now_ts,
                    json.dumps({"token_id": tok, "tx_ref": ref, "purpose": row["purpose"]}),
                ),
            )
            conn.commit()
            return {
                "redeemed": True,
                "token_id": tok,
                "purpose": row["purpose"],
                "tx_ref": ref,
            }
        finally:
            conn.close()
