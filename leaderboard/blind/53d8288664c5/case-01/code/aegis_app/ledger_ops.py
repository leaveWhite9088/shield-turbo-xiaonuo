# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池调拨（Quota Transfer）与单次应急放行令牌核销服务。

并发与一致性契约（无死锁全局锁偏序）：
- 本模块全部配额变更路径（consume / transfer / redeem / 实时告警扣减）一律以
  BEGIN IMMEDIATE 作为事务首语句获取 SQLite 全局写锁，且不持有任何 Python 层
  配额锁，跨接口（quotas/consume × quotas/transfer × evaluate-batch 告警联动）
  天然满足单一偏序，杜绝死锁与丢失更新；
- 实时告警扣减支持通过 conn 复用调用方已持有的 BEGIN IMMEDIATE 事务（供风控
  批次四重强原子提交内联调用），单条条件更新原子完成；
- 扣减 / 调拨 / 核销均为“先原子谓词更新、后提交”模式：高并发下绝不超扣、
  绝不为负、总额严格守恒、令牌严格仅成功核销一次。
"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .db import open_connection

_AMOUNT_MAX = 1 << 62


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
    *,
    conn: Any = None,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额。

    单条条件更新（remaining_quota >= 1 谓词）原子完成，高并发下绝不超扣为负；
    可通过 conn 复用调用方已持有的 BEGIN IMMEDIATE 事务，实现批次级四重强原子提交。
    """
    own_conn = conn is None
    if own_conn:
        conn = open_connection(db_path)
    try:
        cur = conn.execute(
            "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
            "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
            (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
        )
        consumed = cur.rowcount == 1
        if own_conn:
            conn.commit()
        return consumed
    finally:
        if own_conn:
            conn.close()


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度（高并发下严禁超扣或负数）。"""
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise ValueError("Quota consumption amount must be a positive integer")
    if amount > _AMOUNT_MAX:
        raise ValueError("Quota consumption amount exceeds supported range")
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
            (caller.tenant_id, quota_type),
        ).fetchone()
        if not row:
            raise LookupError(f"Quota bucket not found: {quota_type}")

        current_rem = int(row["remaining_quota"])
        if current_rem < amount:
            conn.commit()
            return {
                "accepted": False,
                "quota_type": quota_type,
                "remaining_quota": current_rem,
                "reason": "QUOTA_EXHAUSTED",
            }

        new_rem = current_rem - amount
        conn.execute(
            "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? WHERE tenant_id = ? AND quota_type = ?",
            (new_rem, now_ts, caller.tenant_id, quota_type),
        )
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
    """在本租户两个配额池之间调拨额度（须保证总额守恒、余额非负且高并发双向调拨零死锁）。

    BEGIN IMMEDIATE 作为事务首语句统一获取写锁：读校验、双池更新与调拨流水
    登记在同一写事务内原子提交，并发 consume / evaluate-batch 告警联动扣减
    不会插入其间造成总额漂移。
    """
    require_admin(caller)
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        raise ValueError("Transfer amount must be a positive integer")
    if amount > _AMOUNT_MAX:
        raise ValueError("Transfer amount exceeds supported range")
    if not from_quota or not to_quota or from_quota == to_quota:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
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
            conn.commit()
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
    """核销单次使用的风控应急放行令牌（高并发下严格仅成功核销一次）。

    BEGIN IMMEDIATE 写事务内“查复核销状态 + 条件更新（used = 0 谓词）+ 审计
    流水”原子提交：并发重复核销仅一方成功，另一方返回 TOKEN_ALREADY_USED。
    """
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT token_id, tenant_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
            (token_id, caller.tenant_id),
        ).fetchone()
        if not row:
            raise LookupError("Override token not found")
        if int(row["used"]) != 0:
            conn.commit()
            return {
                "redeemed": False,
                "token_id": token_id,
                "reason": "TOKEN_ALREADY_USED",
            }

        cur = conn.execute(
            "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
            "WHERE token_id = ? AND tenant_id = ? AND used = 0",
            (caller.user_id, now_ts, token_id, caller.tenant_id),
        )
        if cur.rowcount != 1:
            conn.commit()
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
    finally:
        conn.close()
