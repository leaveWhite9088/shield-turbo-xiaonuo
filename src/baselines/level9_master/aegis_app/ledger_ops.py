# -*- coding: utf-8 -*-
"""高性能原子配额账本服务：规范全序双锁消除双向跨池调拨 AB-BA 死锁 + BEGIN IMMEDIATE 防超扣。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .db import (
    acquire_ordered_striped_locks,
    get_striped_lock,
    get_thread_connection,
    require_strict_int,
)


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

    now_ts = int(caller.request_ts or int(time.time()))
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


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: Any,
) -> dict[str, Any]:
    """按分片索引全序升序加锁并配合 BEGIN IMMEDIATE 单事务原子划转，确保高并发双向调拨零死锁、总额守恒。"""
    require_admin(caller)
    checked_amount = require_strict_int(amount, "amount", min_val=1, max_val=1_000_000)
    if (
        not isinstance(from_quota, str)
        or not isinstance(to_quota, str)
        or not from_quota
        or not to_quota
        or len(from_quota) > 64
        or len(to_quota) > 64
        or from_quota == to_quota
    ):
        raise ValueError("Distinct valid from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    with acquire_ordered_striped_locks(
        db_path,
        caller.tenant_id,
        f"quota:{from_quota}",
        f"quota:{to_quota}",
    ):
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT quota_type, remaining_quota FROM tenant_quotas "
                "WHERE tenant_id = ? AND quota_type IN (?, ?)",
                (caller.tenant_id, from_quota, to_quota),
            ).fetchall()
            q_map = {str(r["quota_type"]): int(r["remaining_quota"]) for r in rows}
            if from_quota not in q_map or to_quota not in q_map:
                conn.rollback()
                raise LookupError("Source or destination quota pool not found")

            src_rem = q_map[from_quota]
            dst_rem = q_map[to_quota]
            if src_rem < checked_amount:
                conn.rollback()
                return {
                    "transferred": False,
                    "from_quota": from_quota,
                    "to_quota": to_quota,
                    "from_remaining": src_rem,
                    "to_remaining": dst_rem,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }

            new_src = src_rem - checked_amount
            new_dst = dst_rem + checked_amount
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
                (new_src, now_ts, caller.tenant_id, from_quota),
            )
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
                (new_dst, now_ts, caller.tenant_id, to_quota),
            )
            conn.execute(
                "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) VALUES (?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, caller.user_id, from_quota, to_quota, checked_amount, now_ts),
            )
            conn.commit()
            return {
                "transferred": True,
                "from_quota": from_quota,
                "to_quota": to_quota,
                "amount": checked_amount,
                "from_remaining": new_src,
                "to_remaining": new_dst,
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

    now_ts = int(caller.request_ts or int(time.time()))
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
