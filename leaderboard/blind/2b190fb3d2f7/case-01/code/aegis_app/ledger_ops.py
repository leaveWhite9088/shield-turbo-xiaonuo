# -*- coding: utf-8 -*-
"""租户配额扣减、跨配额池无死锁原子调拨（Quota Transfer）与单次应急放行令牌核销服务。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .db import write_transaction
from .runtime_state import get_runtime, parse_strict_int


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试原子扣减 1 点实时告警配额（严格遵守 L2 -> L3 锁序）。"""
    tstate = get_runtime(db_path).get_tenant(tenant_id)
    with tstate.acquire_quota_locks(ALERT_QUOTA_BUCKET):
        with write_transaction(db_path) as conn:
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
    """扣减租户指定类型的业务配额并返回剩余额度（Level 2 桶锁 -> Level 3 BEGIN IMMEDIATE）。"""
    qty = parse_strict_int(amount, field_name="amount", min_val=1)
    qtype = str(quota_type or "").strip()
    if not qtype or len(qtype) > 128:
        raise ValueError("Valid quota_type is required")

    now_ts = int(caller.request_ts or int(time.time()))
    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.acquire_quota_locks(qtype):
        with write_transaction(db_path) as conn:
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (qty, now_ts, caller.tenant_id, qtype, qty),
            )
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, qtype),
            ).fetchone()
            if not row:
                raise LookupError(f"Quota bucket not found: {qtype}")

            rem = int(row["remaining_quota"])
            if cur.rowcount == 0:
                return {
                    "accepted": False,
                    "quota_type": qtype,
                    "remaining_quota": rem,
                    "reason": "QUOTA_EXHAUSTED",
                }

            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    qty,
                    now_ts,
                    json.dumps({"quota_type": qtype, "consumed": qty, "remaining": rem}),
                ),
            )
            return {
                "accepted": True,
                "quota_type": qtype,
                "consumed": qty,
                "remaining_quota": rem,
            }


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: int,
) -> dict[str, Any]:
    """在本租户两个配额池之间原子调拨额度（Level 2 字典序双桶锁 -> Level 3 BEGIN IMMEDIATE，零死锁、总额守恒）。"""
    require_admin(caller)
    qty = parse_strict_int(amount, field_name="amount", min_val=1)
    src_q = str(from_quota or "").strip()
    dst_q = str(to_quota or "").strip()
    if not src_q or not dst_q or src_q == dst_q:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.acquire_quota_locks(src_q, dst_q):
        with write_transaction(db_path) as conn:
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
            if src_rem < qty:
                return {
                    "transferred": False,
                    "from_quota": src_q,
                    "to_quota": dst_q,
                    "from_remaining": src_rem,
                    "to_remaining": dst_rem,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }

            new_src = src_rem - qty
            new_dst = dst_rem + qty
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
                (caller.tenant_id, caller.user_id, src_q, dst_q, qty, now_ts),
            )
            return {
                "transferred": True,
                "from_quota": src_q,
                "to_quota": dst_q,
                "amount": qty,
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
    """核销单次使用的风控应急放行令牌（BEGIN IMMEDIATE + WHERE used=0 严格单次核销）。"""
    tid = str(token_id or "").strip()
    tref = str(tx_ref or "").strip()
    if not tid or len(tid) > 128:
        raise ValueError("Valid token_id is required")

    now_ts = int(caller.request_ts or int(time.time()))
    with write_transaction(db_path) as conn:
        cur = conn.execute(
            "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
            "WHERE token_id = ? AND tenant_id = ? AND used = 0",
            (caller.user_id, now_ts, tid, caller.tenant_id),
        )
        row = conn.execute(
            "SELECT token_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
            (tid, caller.tenant_id),
        ).fetchone()
        if not row:
            raise LookupError("Override token not found")
        if cur.rowcount == 0:
            return {
                "redeemed": False,
                "token_id": tid,
                "reason": "TOKEN_ALREADY_USED",
            }

        conn.execute(
            "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
            "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
            (
                caller.tenant_id,
                caller.user_id,
                now_ts,
                json.dumps({"token_id": tid, "tx_ref": tref, "purpose": row["purpose"]}),
            ),
        )
        return {
            "redeemed": True,
            "token_id": tid,
            "purpose": row["purpose"],
            "tx_ref": tref,
        }
