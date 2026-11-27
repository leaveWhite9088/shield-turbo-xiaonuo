# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池无死锁原子调拨（Quota Transfer）与单次应急放行令牌核销服务。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .middleware import INT64_MAX, parse_strict_int
from .runtime import get_runtime


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 原子扣减 1 点实时告警配额（严格遵守 Level 2 -> Level 3 锁序）。"""
    rt = get_runtime(db_path)
    with rt.acquire_quota_locks(tenant_id, (ALERT_QUOTA_BUCKET,)):
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= 1",
                (int(now_ts), tenant_id, ALERT_QUOTA_BUCKET),
            )
            return cur.rowcount == 1


def consume_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    quota_type: str,
    amount: int = 1,
) -> dict[str, Any]:
    """原子扣减租户指定类型的业务配额（严格防超扣与负数，遵守 Level 2 -> Level 3 锁序）。"""
    q_type = str(quota_type or "").strip()
    if not q_type or len(q_type) > 128:
        raise ValueError("Valid quota_type is required")
    amt = parse_strict_int(amount, "amount", min_val=1)
    now_ts = int(caller.request_ts or int(time.time()))

    rt = get_runtime(db_path)
    with rt.acquire_quota_locks(caller.tenant_id, (q_type,)):
        with rt.write_tx() as conn:
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, q_type),
            ).fetchone()
            if not row:
                raise LookupError(f"Quota bucket not found: {q_type}")

            current_rem = int(row["remaining_quota"])
            if current_rem < amt:
                return {
                    "accepted": False,
                    "quota_type": q_type,
                    "remaining_quota": current_rem,
                    "reason": "QUOTA_EXHAUSTED",
                }

            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amt, now_ts, caller.tenant_id, q_type, amt),
            )
            if cur.rowcount != 1:
                fresh = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, q_type),
                ).fetchone()
                return {
                    "accepted": False,
                    "quota_type": q_type,
                    "remaining_quota": int(fresh["remaining_quota"]) if fresh else 0,
                    "reason": "QUOTA_EXHAUSTED",
                }

            new_rem = current_rem - amt
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
            return {
                "accepted": True,
                "quota_type": q_type,
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
    """在本租户两个配额池间按字典序严格偏序加锁 + BEGIN IMMEDIATE 原子调拨额度（总额守恒、零死锁）。"""
    require_admin(caller)
    src_q = str(from_quota or "").strip()
    dst_q = str(to_quota or "").strip()
    if not src_q or not dst_q or src_q == dst_q or len(src_q) > 128 or len(dst_q) > 128:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")
    amt = parse_strict_int(amount, "amount", min_val=1)

    now_ts = int(caller.request_ts or int(time.time()))
    rt = get_runtime(db_path)
    # Level 2：按配额池名称字典序严格升序加锁 -> Level 3：BEGIN IMMEDIATE
    with rt.acquire_quota_locks(caller.tenant_id, (src_q, dst_q)):
        with rt.write_tx() as conn:
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
                return {
                    "transferred": False,
                    "from_quota": src_q,
                    "to_quota": dst_q,
                    "from_remaining": src_rem,
                    "to_remaining": dst_rem,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }
            if dst_rem > INT64_MAX - amt:
                raise ValueError("Transfer would overflow destination quota 64-bit integer bound")

            new_src = src_rem - amt
            new_dst = dst_rem + amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (new_src, now_ts, caller.tenant_id, src_q),
            )
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (new_dst, now_ts, caller.tenant_id, dst_q),
            )
            conn.execute(
                "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, caller.user_id, src_q, dst_q, amt, now_ts),
            )
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
    """原子核销单次使用的风控应急放行令牌（高并发下严格仅成功核销一次）。"""
    tok_id = str(token_id or "").strip()
    t_ref = str(tx_ref or "").strip()
    if not tok_id or len(tok_id) > 128 or len(t_ref) > 128:
        raise ValueError("Valid token_id and tx_ref are required")
    now_ts = int(caller.request_ts or int(time.time()))

    rt = get_runtime(db_path)
    with rt.write_tx() as conn:
        row = conn.execute(
            "SELECT token_id, tenant_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
            (tok_id, caller.tenant_id),
        ).fetchone()
        if not row:
            raise LookupError("Override token not found")
        if int(row["used"]) != 0:
            return {
                "redeemed": False,
                "token_id": tok_id,
                "reason": "TOKEN_ALREADY_USED",
            }

        cur = conn.execute(
            "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
            "WHERE token_id = ? AND tenant_id = ? AND used = 0",
            (caller.user_id, now_ts, tok_id, caller.tenant_id),
        )
        if cur.rowcount != 1:
            return {
                "redeemed": False,
                "token_id": tok_id,
                "reason": "TOKEN_ALREADY_USED",
            }

        conn.execute(
            "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
            "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
            (
                caller.tenant_id,
                caller.user_id,
                now_ts,
                json.dumps({"token_id": tok_id, "tx_ref": t_ref, "purpose": row["purpose"]}),
            ),
        )
        return {
            "redeemed": True,
            "token_id": tok_id,
            "purpose": row["purpose"],
            "tx_ref": t_ref,
        }
