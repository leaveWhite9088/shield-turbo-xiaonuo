# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池无死锁原子调拨（Quota Transfer）与单次应急放行令牌核销服务。"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .state import get_gateway_state
from .validation import parse_strict_int


def try_consume_realtime_alert_quota_in_tx(
    conn: sqlite3.Connection,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """在已开启的 BEGIN IMMEDIATE 事务内原子扣减 1 点 REALTIME_ALERT_POOL 配额。"""
    cur = conn.execute(
        "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
        "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
        (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
    )
    return cur.rowcount == 1


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额。"""
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(tenant_id)
    with t_state.quota_lock:
        with gw_state.pool.borrow() as conn:
            conn.execute("BEGIN IMMEDIATE")
            ok = try_consume_realtime_alert_quota_in_tx(conn, tenant_id, now_ts)
            conn.commit()
            return ok


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度（遵循 quota_lock -> BEGIN IMMEDIATE 锁序）。"""
    amt = parse_strict_int(amount, "amount", min_val=1)
    qtype = str(quota_type or "").strip()
    if not qtype:
        raise ValueError("quota_type is required")

    now_ts = int(caller.request_ts or int(time.time()))
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)

    with t_state.quota_lock:
        with gw_state.pool.borrow() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amt, now_ts, caller.tenant_id, qtype, amt),
            )
            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, qtype),
                ).fetchone()
                conn.rollback()
                if not row:
                    raise LookupError(f"Quota bucket not found: {qtype}")
                return {
                    "accepted": False,
                    "quota_type": qtype,
                    "remaining_quota": int(row["remaining_quota"]),
                    "reason": "QUOTA_EXHAUSTED",
                }

            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, qtype),
            ).fetchone()
            new_rem = int(row["remaining_quota"])
            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    amt,
                    now_ts,
                    json.dumps({"quota_type": qtype, "consumed": amt, "remaining": new_rem}),
                ),
            )
            conn.commit()
            return {
                "accepted": True,
                "quota_type": qtype,
                "consumed": amt,
                "remaining_quota": new_rem,
            }


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: int,
) -> dict[str, Any]:
    """在本租户两个配额池之间原子调拨额度（遵循 quota_lock -> BEGIN IMMEDIATE 偏序，零死锁）。"""
    require_admin(caller)
    amt = parse_strict_int(amount, "amount", min_val=1)
    src_q = str(from_quota or "").strip()
    dst_q = str(to_quota or "").strip()
    if not src_q or not dst_q or src_q == dst_q:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)

    with t_state.quota_lock:
        with gw_state.pool.borrow() as conn:
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
                conn.rollback()
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

            new_src = src_rem - amt
            new_dst = dst_rem + amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (amt, now_ts, caller.tenant_id, src_q),
            )
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota + ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (amt, now_ts, caller.tenant_id, dst_q),
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


def redeem_override_token(
    db_path: str,
    caller: CallerContext,
    *,
    token_id: str,
    tx_ref: str,
) -> dict[str, Any]:
    """核销单次使用的风控应急放行令牌（BEGIN IMMEDIATE 条件更新防并发双花）。"""
    tid = str(token_id or "").strip()
    if not tid:
        raise ValueError("token_id is required")
    now_ts = int(caller.request_ts or int(time.time()))
    gw_state = get_gateway_state(db_path)

    with gw_state.pool.borrow() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
            "WHERE token_id = ? AND tenant_id = ? AND used = 0",
            (caller.user_id, now_ts, tid, caller.tenant_id),
        )
        if cur.rowcount == 0:
            row = conn.execute(
                "SELECT used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (tid, caller.tenant_id),
            ).fetchone()
            conn.rollback()
            if not row:
                raise LookupError("Override token not found")
            return {
                "redeemed": False,
                "token_id": tid,
                "reason": "TOKEN_ALREADY_USED",
            }

        row = conn.execute(
            "SELECT purpose FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
            (tid, caller.tenant_id),
        ).fetchone()
        purpose = row["purpose"]
        conn.execute(
            "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
            "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
            (
                caller.tenant_id,
                caller.user_id,
                now_ts,
                json.dumps({"token_id": tid, "tx_ref": tx_ref, "purpose": purpose}),
            ),
        )
        conn.commit()
        return {
            "redeemed": True,
            "token_id": tid,
            "purpose": purpose,
            "tx_ref": tx_ref,
        }
