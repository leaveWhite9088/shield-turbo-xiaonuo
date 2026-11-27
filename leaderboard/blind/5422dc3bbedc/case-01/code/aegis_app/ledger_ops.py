# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池调拨（Quota Transfer）与单次应急放行令牌核销服务。

并发契约：
- 一律采用 SQLite ``BEGIN IMMEDIATE`` 单写者锁 + 条件 UPDATE（``remaining >= ?`` /
  ``used = 0`` 谓词），彻底消除读-改-写竞态：单池抢扣、跨池双向交叉调拨、
  并发 evaluate-batch 联动扣减 ``REALTIME_ALERT_POOL`` 全部严格串行，
  全局总额守恒、余额非负、令牌仅可核销一次；
- 进程内不引入任何 Python 配额锁，与数据库写锁之间无交叉持有顺序，
  结构性零死锁（统一锁偏序由 SQLite 写锁本身提供）。
"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .db import immediate_transaction, open_connection


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额（条件原子 UPDATE）。"""
    conn = open_connection(db_path)
    try:
        with immediate_transaction(conn):
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
                (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
            )
            return cur.rowcount == 1
    finally:
        conn.close()


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度（高并发下严禁超扣或负数）。"""
    if amount <= 0:
        raise ValueError("Quota consumption amount must be positive")
    if len(quota_type) > 64:
        raise ValueError("Invalid quota_type")
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        with immediate_transaction(conn):
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
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amount, now_ts, caller.tenant_id, quota_type, amount),
            )
            if cur.rowcount != 1:  # 双保险：条件谓词失败视作配额耗尽
                return {
                    "accepted": False,
                    "quota_type": quota_type,
                    "remaining_quota": current_rem,
                    "reason": "QUOTA_EXHAUSTED",
                }
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
    """在本租户两个配额池之间调拨额度（总额守恒、余额非负、高并发双向交叉零死锁零丢失）。"""
    require_admin(caller)
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    if not from_quota or not to_quota or from_quota == to_quota:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    if len(from_quota) > 64 or len(to_quota) > 64:
        raise ValueError("Invalid quota pool name")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        with immediate_transaction(conn):
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

            # 单一写事务内顺序完成：源扣减（条件谓词）→ 目标入账 → 流水登记
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
    conn = open_connection(db_path)
    try:
        with immediate_transaction(conn):
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
            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, token_id, caller.tenant_id),
            )
            if cur.rowcount != 1:  # 并发竞争下的双保险（IMMEDIATE 写锁下理论上不可达）
                return {
                    "redeemed": False,
                    "token_id": token_id,
                    "reason": "TOKEN_ALREADY_USED",
                }
        return {
            "redeemed": True,
            "token_id": token_id,
            "purpose": row["purpose"],
            "tx_ref": tx_ref,
        }
    finally:
        conn.close()
