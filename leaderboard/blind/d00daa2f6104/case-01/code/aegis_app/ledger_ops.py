# -*- coding: utf-8 -*-
"""分租户统一锁序下的配额、调拨与单次令牌原子操作。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .db import open_connection
from .runtime import MAX_SQLITE_INT, bounded_text, strict_int, tenant_write_lock


def consume_alert_quota_conn(conn: Any, tenant_id: str, now_ts: int) -> bool:
    """在调用者已有的事务/租户锁内条件扣减；绝不自行提交。"""
    cursor = conn.execute(
        "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
        "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
        (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
    )
    return cursor.rowcount == 1


def try_consume_realtime_alert_quota(db_path: str, tenant_id: str, now_ts: int) -> bool:
    with tenant_write_lock(db_path, tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            consumed = consume_alert_quota_conn(conn, tenant_id, now_ts)
            conn.commit()
            return consumed
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    quota_type = bounded_text(quota_type, "quota_type", 128)
    amount = strict_int(amount, "amount", minimum=1, maximum=MAX_SQLITE_INT)
    now_ts = int(caller.request_ts or int(time.time()))
    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, quota_type),
            ).fetchone()
            if not row:
                raise LookupError("Quota bucket not found")
            current = int(row["remaining_quota"])
            if current < amount:
                conn.rollback()
                return {
                    "accepted": False, "quota_type": quota_type,
                    "remaining_quota": current, "reason": "QUOTA_EXHAUSTED",
                }
            cursor = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amount, now_ts, caller.tenant_id, quota_type, amount),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Concurrent quota update conflict")
            remaining = current - amount
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (caller.tenant_id, caller.user_id, amount, now_ts,
                 json.dumps({"quota_type": quota_type, "consumed": amount, "remaining": remaining})),
            )
            conn.commit()
            return {
                "accepted": True, "quota_type": quota_type,
                "consumed": amount, "remaining_quota": remaining,
            }
        except Exception:
            conn.rollback()
            raise
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
    from_quota = bounded_text(from_quota, "from_quota", 128)
    to_quota = bounded_text(to_quota, "to_quota", 128)
    amount = strict_int(amount, "amount", minimum=1)
    if from_quota == to_quota:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    now_ts = int(caller.request_ts or int(time.time()))
    # 所有共享配额入口均先取本租户 Python 锁，再 BEGIN IMMEDIATE；不在 DB 事务内反向取锁。
    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT quota_type, remaining_quota FROM tenant_quotas "
                "WHERE tenant_id = ? AND quota_type IN (?, ?) ORDER BY quota_type ASC",
                (caller.tenant_id, from_quota, to_quota),
            ).fetchall()
            balances = {str(row["quota_type"]): int(row["remaining_quota"]) for row in rows}
            if from_quota not in balances or to_quota not in balances:
                raise LookupError("Source or destination quota pool not found")
            source = balances[from_quota]
            destination = balances[to_quota]
            if source < amount:
                conn.rollback()
                return {
                    "transferred": False, "from_quota": from_quota, "to_quota": to_quota,
                    "from_remaining": source, "to_remaining": destination,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }
            if destination > MAX_SQLITE_INT - amount:
                raise ValueError("Destination quota would overflow")
            deltas = {from_quota: -amount, to_quota: amount}
            # 固定按 quota_type 字典序写入，数据库层也遵循全局统一偏序。
            for quota_name in sorted(deltas):
                cursor = conn.execute(
                    "UPDATE tenant_quotas SET remaining_quota = remaining_quota + ?, updated_at = ? "
                    "WHERE tenant_id = ? AND quota_type = ?",
                    (deltas[quota_name], now_ts, caller.tenant_id, quota_name),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("Quota row update failed")
            conn.execute(
                "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) VALUES (?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, caller.user_id, from_quota, to_quota, amount, now_ts),
            )
            conn.commit()
            return {
                "transferred": True, "from_quota": from_quota, "to_quota": to_quota,
                "amount": amount, "from_remaining": source - amount,
                "to_remaining": destination + amount,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    token_id = bounded_text(token_id, "token_id", 256)
    tx_ref = bounded_text(tx_ref, "tx_ref", 256, allow_empty=True)
    now_ts = int(caller.request_ts or int(time.time()))
    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (token_id, caller.tenant_id),
            ).fetchone()
            if not row:
                raise LookupError("Override token not found")
            cursor = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, token_id, caller.tenant_id),
            )
            if cursor.rowcount == 0:
                conn.rollback()
                return {"redeemed": False, "token_id": token_id, "reason": "TOKEN_ALREADY_USED"}
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (caller.tenant_id, caller.user_id, now_ts,
                 json.dumps({"token_id": token_id, "tx_ref": tx_ref, "purpose": row["purpose"]})),
            )
            conn.commit()
            return {
                "redeemed": True, "token_id": token_id,
                "purpose": row["purpose"], "tx_ref": tx_ref,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
