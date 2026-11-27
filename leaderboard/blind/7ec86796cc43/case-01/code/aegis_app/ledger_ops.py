# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池调拨（Quota Transfer）与单次应急放行令牌核销服务。

并发与原子性铁律：

* 所有配额读-改-写均在 ``BEGIN IMMEDIATE`` 写事务内完成，并叠加
  **条件更新**（``WHERE remaining_quota >= amount``）作为第二道防线，
  即使锁序被绕过也绝不会超扣或写出负数余额；
* 跨池调拨一次性锁定源池与目标池（按配额名升序，全局统一锁偏序），
  双向交叉调拨零死锁、总额严格守恒；
* 令牌核销使用条件 UPDATE（``AND used = 0``），高并发下严格仅成功核销一次。
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .db import open_connection, write_transaction
from .locks import tenant_write_scope


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额。

    当传入 ``conn`` 时复用调用方事务（风控批次场景），
    从而与批次写入同生共死，实现四位一体强原子提交/回滚。
    """
    owned_conn = conn is None
    if owned_conn:
        conn = open_connection(db_path)
    try:
        if owned_conn:
            with tenant_write_scope(tenant_id, ALERT_QUOTA_BUCKET):
                with write_transaction(conn):
                    cur = conn.execute(
                        "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
                        "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
                        (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
                    )
                    return cur.rowcount == 1
        cur = conn.execute(
            "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
            "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
            (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
        )
        return cur.rowcount == 1
    finally:
        if owned_conn:
            conn.close()


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
    quota_type = str(quota_type or "").strip()
    if not quota_type or len(quota_type) > 64:
        raise ValueError("Invalid quota_type")
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        with tenant_write_scope(caller.tenant_id, quota_type):
            with write_transaction(conn):
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

                cur = conn.execute(
                    "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                    "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                    (amount, now_ts, caller.tenant_id, quota_type, amount),
                )
                if cur.rowcount != 1:
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
    """在本租户两个配额池之间调拨额度（须保证总额守恒、余额非负且高并发双向调拨零死锁）。"""
    require_admin(caller)
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    if not from_quota or not to_quota or from_quota == to_quota:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    from_quota = str(from_quota).strip()
    to_quota = str(to_quota).strip()
    if len(from_quota) > 64 or len(to_quota) > 64:
        raise ValueError("Invalid quota bucket name")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        # 源池与目标池按名称升序一并锁定（全局统一锁偏序），双向交叉调拨零死锁。
        with tenant_write_scope(caller.tenant_id, from_quota, to_quota):
            with write_transaction(conn):
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

                cur = conn.execute(
                    "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                    "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                    (amount, now_ts, caller.tenant_id, from_quota, amount),
                )
                if cur.rowcount != 1:
                    return {
                        "transferred": False,
                        "from_quota": from_quota,
                        "to_quota": to_quota,
                        "from_remaining": src_rem,
                        "to_remaining": dst_rem,
                        "reason": "INSUFFICIENT_SOURCE_QUOTA",
                    }
                conn.execute(
                    "UPDATE tenant_quotas SET remaining_quota = remaining_quota + ?, updated_at = ? "
                    "WHERE tenant_id = ? AND quota_type = ?",
                    (amount, now_ts, caller.tenant_id, to_quota),
                )
                conn.execute(
                    "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) VALUES (?, ?, ?, ?, ?, ?)",
                    (caller.tenant_id, caller.user_id, from_quota, to_quota, amount, now_ts),
                )
                return {
                    "transferred": True,
                    "from_quota": from_quota,
                    "to_quota": to_quota,
                    "amount": amount,
                    "from_remaining": src_rem - amount,
                    "to_remaining": dst_rem + amount,
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
    """核销单次使用的风控应急放行令牌（高并发下严格仅成功核销一次）。"""
    now_ts = int(caller.request_ts or int(time.time()))
    token_id = str(token_id or "").strip()
    if not token_id:
        raise ValueError("token_id is required")
    conn = open_connection(db_path)
    try:
        with tenant_write_scope(caller.tenant_id):
            with write_transaction(conn):
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

                # 条件核销：并发下仅第一个请求的 rowcount 为 1。
                cur = conn.execute(
                    "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                    "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                    (caller.user_id, now_ts, token_id, caller.tenant_id),
                )
                if cur.rowcount != 1:
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
                return {
                    "redeemed": True,
                    "token_id": token_id,
                    "purpose": row["purpose"],
                    "tx_ref": tx_ref,
                }
    finally:
        conn.close()
