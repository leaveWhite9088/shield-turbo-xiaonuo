# -*- coding: utf-8 -*-
"""租户配额扣减、统一锁偏序跨配额池调拨（Quota Transfer）与单次应急放行令牌原子核销服务。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET
from .runtime import GatewayRuntime, get_runtime
from .validation import strict_int


def try_consume_realtime_alert_quota(
    db_path: str,
    tenant_id: str,
    now_ts: int,
    *,
    runtime: GatewayRuntime | None = None,
) -> bool:
    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试原子扣减 1 点实时告警配额。"""
    rt = runtime or get_runtime(db_path)
    with rt.quota_lock(tenant_id, ALERT_QUOTA_BUCKET):
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """扣减租户指定类型的业务配额并返回剩余额度（原子条件更新防并发超扣）。"""
    clean_qtype = str(quota_type or "").strip()
    if not clean_qtype:
        raise ValueError("quota_type is required")
    amt = strict_int(amount, "amount", min_val=1)
    now_ts = int(caller.request_ts or int(time.time()))
    rt = runtime or get_runtime(db_path)

    with rt.quota_lock(caller.tenant_id, clean_qtype):
        with rt.write_tx() as conn:
            cur = conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amt, now_ts, caller.tenant_id, clean_qtype, amt),
            )
            row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, clean_qtype),
            ).fetchone()
            if not row:
                raise LookupError(f"Quota bucket not found: {clean_qtype}")
            current_rem = int(row["remaining_quota"])
            if cur.rowcount == 0:
                return {
                    "accepted": False,
                    "quota_type": clean_qtype,
                    "remaining_quota": current_rem,
                    "reason": "QUOTA_EXHAUSTED",
                }

            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'QUOTA_CONSUME', 'MEDIUM', ?, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    amt,
                    now_ts,
                    json.dumps({"quota_type": clean_qtype, "consumed": amt, "remaining": current_rem}),
                ),
            )
            return {
                "accepted": True,
                "quota_type": clean_qtype,
                "consumed": amt,
                "remaining_quota": current_rem,
            }


def transfer_tenant_quota(
    db_path: str,
    caller: CallerContext,
    *,
    from_quota: str,
    to_quota: str,
    amount: int,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """按统一字典序配额锁 + BEGIN IMMEDIATE 在本租户两个配额池间原子调拨额度。"""
    require_admin(caller)
    from_q = str(from_quota or "").strip()
    to_q = str(to_quota or "").strip()
    amt = strict_int(amount, "amount", min_val=1)
    if not from_q or not to_q or from_q == to_q:
        raise ValueError("Distinct non-empty from_quota and to_quota are required")

    now_ts = int(caller.request_ts or int(time.time()))
    rt = runtime or get_runtime(db_path)

    with rt.quota_pair_locks(caller.tenant_id, from_q, to_q):
        with rt.write_tx() as conn:
            src_row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, from_q),
            ).fetchone()
            dst_row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, to_q),
            ).fetchone()
            if not src_row or not dst_row:
                raise LookupError("Source or destination quota pool not found")

            src_rem = int(src_row["remaining_quota"])
            dst_rem = int(dst_row["remaining_quota"])
            if src_rem < amt:
                return {
                    "transferred": False,
                    "from_quota": from_q,
                    "to_quota": to_q,
                    "from_remaining": src_rem,
                    "to_remaining": dst_rem,
                    "reason": "INSUFFICIENT_SOURCE_QUOTA",
                }

            new_src = src_rem - amt
            new_dst = dst_rem + amt
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                (amt, now_ts, caller.tenant_id, from_q, amt),
            )
            conn.execute(
                "UPDATE tenant_quotas SET remaining_quota = remaining_quota + ?, updated_at = ? "
                "WHERE tenant_id = ? AND quota_type = ?",
                (amt, now_ts, caller.tenant_id, to_q),
            )
            conn.execute(
                "INSERT INTO quota_transfers(tenant_id, actor_id, from_quota, to_quota, amount, ts) VALUES (?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, caller.user_id, from_q, to_q, amt, now_ts),
            )
            return {
                "transferred": True,
                "from_quota": from_q,
                "to_quota": to_q,
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """原子核销单次使用的风控应急放行令牌（高并发下严格仅成功一次）。"""
    clean_tok = str(token_id or "").strip()
    clean_tx_ref = str(tx_ref or "").strip()
    if not clean_tok:
        raise ValueError("token_id is required")

    now_ts = int(caller.request_ts or int(time.time()))
    rt = runtime or get_runtime(db_path)

    with rt.token_lock(caller.tenant_id, clean_tok):
        with rt.write_tx() as conn:
            row = conn.execute(
                "SELECT token_id, tenant_id, purpose, used FROM override_tokens WHERE token_id = ? AND tenant_id = ?",
                (clean_tok, caller.tenant_id),
            ).fetchone()
            if not row:
                raise LookupError("Override token not found")
            if int(row["used"]) != 0:
                return {
                    "redeemed": False,
                    "token_id": clean_tok,
                    "reason": "TOKEN_ALREADY_USED",
                }

            cur = conn.execute(
                "UPDATE override_tokens SET used = 1, used_by = ?, used_at = ? "
                "WHERE token_id = ? AND tenant_id = ? AND used = 0",
                (caller.user_id, now_ts, clean_tok, caller.tenant_id),
            )
            if cur.rowcount == 0:
                return {
                    "redeemed": False,
                    "token_id": clean_tok,
                    "reason": "TOKEN_ALREADY_USED",
                }

            conn.execute(
                "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json) "
                "VALUES (?, ?, 'OVERRIDE_REDEEM', 'HIGH', 0, '****0000', ?, ?)",
                (
                    caller.tenant_id,
                    caller.user_id,
                    now_ts,
                    json.dumps({"token_id": clean_tok, "tx_ref": clean_tx_ref, "purpose": row["purpose"]}),
                ),
            )
            return {
                "redeemed": True,
                "token_id": clean_tok,
                "purpose": row["purpose"],
                "tx_ref": clean_tx_ref,
            }
