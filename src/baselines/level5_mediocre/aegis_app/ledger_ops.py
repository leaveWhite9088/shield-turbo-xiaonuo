# -*- coding: utf-8 -*-
"""配额账本服务（5级平庸样本：依赖 server.py 全局大锁串行化，未做锁序规范与严格整数校验）。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .db import open_connection


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    if amount <= 0:
        raise ValueError("Quota consumption amount must be positive")
    now_ts = int(caller.request_ts or int(time.time()))
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


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: int,
) -> dict[str, Any]:
    require_admin(caller)
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    if not from_quota or not to_quota or from_quota == to_quota:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        src_row = conn.execute(
            "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
            (caller.tenant_id, from_quota),
        ).fetchone()
        dst_row = conn.execute(
            "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
            (caller.tenant_id, to_quota),
        ).fetchone()
        if not src_row or not dst_row:
            raise LookupError("Source or destination quota pool not found")

        src_rem = int(src_row["remaining_quota"])
        dst_rem = int(dst_row["remaining_quota"])
        if src_rem < amount:
            return {
                "transferred": False,
                "from_quota": from_quota,
                "to_quota": to_quota,
                "from_remaining": src_rem,
                "to_remaining": dst_rem,
                "reason": "INSUFFICIENT_SOURCE_QUOTA",
            }

        new_src = src_rem - amount
        new_dst = dst_rem + amount
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
            (caller.tenant_id, caller.user_id, from_quota, to_quota, amount, now_ts),
        )
        conn.commit()
        return {
            "transferred": True,
            "from_quota": from_quota,
            "to_quota": to_quota,
            "amount": amount,
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
    now_ts = int(caller.request_ts or int(time.time()))
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
