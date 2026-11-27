# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池调拨（Quota Transfer）与单次应急放行令牌核销服务。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET, parse_strict_int
from .db import get_tenant_quota_lock, open_connection


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额（遵守全局配额锁偏序）。"""
    q_lock = get_tenant_quota_lock(db_path, tenant_id)
    with q_lock:
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
                (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
            )
            if cur.rowcount == 0:
                conn.rollback()
                return False
            conn.commit()
            return True
        except Exception:
            if conn.in_transaction:
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
    """扣减租户指定类型的业务配额并返回剩余额度（遵循全局配额锁 -> BEGIN IMMEDIATE 偏序）。"""
    amt = parse_strict_int(amount, "amount", min_val=1)
    q_type = str(quota_type or "").strip()
    if not q_type:
        raise ValueError("quota_type is required")
    now_ts = int(caller.request_ts or int(time.time()))

    q_lock = get_tenant_quota_lock(db_path, caller.tenant_id)
    with q_lock:
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, q_type),
            ).fetchone()
            if not row:
                conn.rollback()
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
        except Exception:
            if conn.in_transaction:
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
    """在本租户两个配额池之间调拨额度（须保证总额守恒、余额非负且高并发双向调拨零死锁）。"""
    require_admin(caller)
    amt = parse_strict_int(amount, "amount", min_val=1)
    src_q = str(from_quota or "").strip()
    dst_q = str(to_quota or "").strip()
    if not src_q or not dst_q or src_q == dst_q:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    q_lock = get_tenant_quota_lock(db_path, caller.tenant_id)
    with q_lock:
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            # 按字典序读取并更新两个配额桶以维持严格的确定性访问偏序
            first_q, second_q = (src_q, dst_q) if src_q < dst_q else (dst_q, src_q)
            r1 = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, first_q),
            ).fetchone()
            r2 = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, second_q),
            ).fetchone()
            if not r1 or not r2:
                conn.rollback()
                raise LookupError("Source or destination quota pool not found")

            src_row = r1 if first_q == src_q else r2
            dst_row = r2 if first_q == src_q else r1

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
        except Exception:
            if conn.in_transaction:
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
    """核销单次使用的风控应急放行令牌（BEGIN IMMEDIATE + 条件原子更新确保并发仅核销一次）。"""
    tok = str(token_id or "").strip()
    ref = str(tx_ref or "").strip()
    if not tok:
        raise ValueError("token_id is required")
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT token_id, tenant_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
            (tok, caller.tenant_id),
        ).fetchone()
        if not row:
            conn.rollback()
            raise LookupError("Override token not found")
        if int(row["used"]) != 0:
            conn.rollback()
            return {
                "redeemed": False,
                "token_id": tok,
                "reason": "TOKEN_ALREADY_USED",
            }

        cur = conn.execute(
            "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? WHERE token_id = ? AND tenant_id = ? AND used = 0",
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
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()
