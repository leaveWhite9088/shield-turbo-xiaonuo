# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池调拨（Quota Transfer）与单次应急放行令牌核销服务。

并发与原子性设计（全局统一锁偏序，任何路径都不会交叉等待）：
1. **SQL 层**：所有写路径统一 ``BEGIN IMMEDIATE``，抢写锁超时后指数退避重试，绝不持有 Python 锁等待 SQLite；
2. **扣减**：单条 ``UPDATE ... SET remaining_quota = remaining_quota - ? WHERE ... >= ?`` 原子扣减，
   以 ``rowcount`` 判定成功，天然抵抗并发抢扣与丢失更新；
3. **调拨**：两账户以 ``(quota_type)`` 字典序为规范加锁顺序，同一事务内完成双减一增，
   任何异常（含并发校验失败）整体回滚，总额严格守恒；
4. **告警池**：与交易批次评估共享同一批处理事务（由调用方传入 ``conn``），随批次回滚一起撤销。
"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET, MAX_ID_CHARS
from .db import GatewayDB
from .guards import guard_text, strict_int

_AUDIT_SQL = (
    "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
    "VALUES (?, ?, ?, ?, ?, '****0000', ?, ?)"
)


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
    *,
    conn=None,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额。

    传入 ``conn`` 时在同一批处理事务内原子扣减（批次回滚即自动退还）；
    否则独立开写事务，直接使用条件更新避免读-改-写竞争。
    """
    sql = (
        "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
        "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1"
    )
    if conn is not None:
        return conn.execute(sql, (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET)).rowcount > 0
    db = GatewayDB(db_path)
    try:
        return db.write(lambda c: c.execute(sql, (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET)).rowcount > 0)
    finally:
        db.close_thread()


def refund_realtime_alert_quota(conn, tenant_id: str, now_ts: int) -> None:
    conn.execute(
        "UPDATE tenant_quotas SET remaining_quota = remaining_quota + 1, updated_at = ? "
        "WHERE tenant_id = ? AND quota_type = ?",
        (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
    )


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度（单语句条件更新，并发安全）。"""
    amount = strict_int(amount, name="amount")
    guard_text(quota_type, name="quota_type", max_chars=MAX_ID_CHARS)
    if amount <= 0:
        raise ValueError("Quota consumption amount must be positive")
    now_ts = int(caller.request_ts or int(time.time()))
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        def _tx(conn):
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
            if cur.rowcount == 0:
                return {
                    "accepted": False,
                    "quota_type": quota_type,
                    "remaining_quota": max(0, current_rem - amount),
                    "reason": "QUOTA_EXHAUSTED",
                }
            new_rem = int(
                conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, quota_type),
                ).fetchone()["remaining_quota"]
            )
            conn.execute(
                _AUDIT_SQL,
                (
                    caller.tenant_id, caller.user_id, "QUOTA_CONSUME", "MEDIUM", amount, now_ts,
                    json.dumps({"quota_type": quota_type, "consumed": amount, "remaining": new_rem}),
                ),
            )
            return {
                "accepted": True,
                "quota_type": quota_type,
                "consumed": amount,
                "remaining_quota": new_rem,
            }

        return db.write(_tx)
    finally:
        if own:
            db.close_thread()


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: int,
) -> dict[str, Any]:
    """在本租户两个配额池之间调拨额度（总额守恒、余额非负、高并发双向调拨零死锁）。"""
    require_admin(caller)
    amount = strict_int(amount, name="amount")
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    if not from_quota or not to_quota or from_quota == to_quota:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    guard_text(from_quota, name="from_quota", max_chars=MAX_ID_CHARS)
    guard_text(to_quota, name="to_quota", max_chars=MAX_ID_CHARS)

    now_ts = int(caller.request_ts or int(time.time()))
    lo, hi = (from_quota, to_quota) if from_quota < to_quota else (to_quota, from_quota)
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        def _tx(conn):
            # 全局规范顺序加锁：先按 quota_type 字典序锁定两个账户（IMMEDIATE 事务已持写锁，
            # 这里以 FOR 语义的读取顺序保证跨层一致的加锁偏序）
            rows = {
                r["quota_type"]: int(r["remaining_quota"])
                for r in conn.execute(
                    "SELECT quota_type, remaining_quota FROM tenant_quotas "
                    "WHERE tenant_id = ? AND quota_type IN (?, ?) ORDER BY quota_type ASC",
                    (caller.tenant_id, lo, hi),
                )
            }
            if from_quota not in rows:
                raise LookupError(f"Quota bucket not found: {from_quota}")
            if to_quota not in rows:
                raise LookupError(f"Quota bucket not found: {to_quota}")
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amount, now_ts, caller.tenant_id, from_quota, amount),
            )
            if cur.rowcount == 0:
                raise ValueError("Insufficient quota for transfer")
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota + ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (amount, now_ts, caller.tenant_id, to_quota),
            )
            rows[from_quota] -= amount
            rows[to_quota] += amount
            conn.execute(
                _AUDIT_SQL,
                (
                    caller.tenant_id, caller.user_id, "QUOTA_TRANSFER", "MEDIUM", amount, now_ts,
                    json.dumps({"from": from_quota, "to": to_quota, "amount": amount}),
                ),
            )
            return {
                "transferred": True,
                "from_quota": from_quota,
                "to_quota": to_quota,
                "amount": amount,
                "from_remaining": rows[from_quota],
                "to_remaining": rows[to_quota],
            }

        return db.write(_tx)
    finally:
        if own:
            db.close_thread()


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    """核销单次应急放行令牌（原子置位，防并发重复核销）。"""
    require_admin(caller)
    tok = str(token_id or "").strip()
    ref = str(tx_ref or "").strip()
    if not tok:
        raise ValueError("token_id is required")
    guard_text(tok, name="token_id", max_chars=MAX_ID_CHARS)
    guard_text(ref, name="tx_ref", max_chars=MAX_ID_CHARS)
    now_ts = int(caller.request_ts or int(time.time()))
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        def _tx(conn):
            row = conn.execute(
                "SELECT token_id, purpose, used FROM override_tokens WHERE tenant_id = ? AND token_id = ?",
                (caller.tenant_id, tok),
            ).fetchone()
            if not row:
                raise LookupError(f"Override token not found: {tok}")
            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, tok, caller.tenant_id),
            )
            if cur.rowcount == 0:
                raise PermissionError("Override token already redeemed")
            conn.execute(
                _AUDIT_SQL,
                (
                    caller.tenant_id, caller.user_id, "OVERRIDE_REDEEM", "HIGH", 0, now_ts,
                    json.dumps({"token_id": tok, "tx_ref": ref, "purpose": row["purpose"]}),
                ),
            )
            return {
                "redeemed": True,
                "token_id": tok,
                "purpose": row["purpose"],
                "tx_ref": ref,
            }

        return db.write(_tx)
    finally:
        if own:
            db.close_thread()
