# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    CHANNEL_RISK_WEIGHTS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import compute_sanction_contagion_hop
from .db import open_connection
from .ledger_ops import try_consume_realtime_alert_quota
from .legacy_compat import apply_sovereign_settlement_adjustment
from .window_stats import compute_exact_median_cents

PARTNER_EMAIL_PATTERN = re.compile(
    r"^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)$"
)


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, "
            "velocity_amount_cents, counterparty_fanout_limit, review_threshold, "
            "reject_threshold, custom_rules_json, updated_at "
            "FROM tenant_policies WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if not row:
            raise LookupError(f"Policy configuration missing for {tenant_id}")
        policy = dict(row)
        policy["custom_rules"] = json.loads(policy["custom_rules_json"])
        return policy
    finally:
        conn.close()


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = int(updates.get("high_amount_cents", current["high_amount_cents"]))
    vel_tx = int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]))
    vel_amt = int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]))
    fanout = int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]))
    rev_th = int(updates.get("review_threshold", current["review_threshold"]))
    rej_th = int(updates.get("reject_threshold", current["reject_threshold"]))
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")

    new_ver = int(current["policy_version"]) + 1
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute(
            "UPDATE tenant_policies SET policy_version = ?, high_amount_cents = ?, "
            "velocity_tx_limit = ?, velocity_amount_cents = ?, counterparty_fanout_limit = ?, "
            "review_threshold = ?, reject_threshold = ?, custom_rules_json = ?, updated_at = ? "
            "WHERE tenant_id = ?",
            (
                new_ver,
                high_amt,
                vel_tx,
                vel_amt,
                fanout,
                rev_th,
                rej_th,
                json.dumps(custom_rules),
                now_ts,
                caller.tenant_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    bonus = int(node.get("bonus_score") or 0)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")

        child_results = [eval_rule_node(ch, tx) for ch in children]
        if op == "AND":
            matched = all(r[0] for r in child_results)
        elif op == "OR":
            matched = any(r[0] for r in child_results)
        else:
            if len(child_results) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            matched = not child_results[0][0]

        if not matched:
            return False, 0, []

        total_bonus = bonus
        reasons: list[str] = []
        for child_ok, child_score, child_reasons in child_results:
            if child_ok and op != "NOT":
                total_bonus += child_score
                reasons.extend(child_reasons)
        if reason:
            reasons.append(reason)
        return True, total_bonus, reasons

    field_name = str(node.get("field") or "")
    if not field_name:
        raise ValueError("Leaf rule node missing 'field'")
    actual = _extract_field(tx, field_name)
    target = node.get("value")

    matched = False
    if op == "EQ":
        matched = actual == target
    elif op == "NEQ":
        matched = actual != target
    elif op == "GT":
        matched = actual is not None and float(actual) > float(target)
    elif op == "GTE":
        matched = actual is not None and float(actual) >= float(target)
    elif op == "LT":
        matched = actual is not None and float(actual) < float(target)
    elif op == "LTE":
        matched = actual is not None and float(actual) <= float(target)
    elif op == "IN":
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            matched = re.search(target, actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
    matched, bonus_score, reasons = eval_rule_node(rule_tree, sample_tx)
    return {
        "matched": matched,
        "bonus_score": bonus_score,
        "reasons": reasons,
    }


def compute_single_tx_decision(
    tx: dict[str, Any],
    policy: dict[str, Any],
    *,
    win_tx_count: int,
    win_amount_cents: int,
    win_unique_cps: int,
    win_median_cents: int,
    sanction_hop: int,
) -> tuple[int, str, list[str]]:
    """根据滑动窗口四维指标、三跳制裁传染等级、主权结算兼容规则与自定义规则树计算风险分。"""
    score = 0
    reasons: list[str] = []

    amount_cents = int(tx["amount_cents"])
    channel = str(tx.get("channel") or "POS_CHIP")

    raw_ch_weight = CHANNEL_RISK_WEIGHTS.get(channel, 8)
    adj_ch_weight, exempt_fanout, compat_tag = apply_sovereign_settlement_adjustment(
        tx,
        policy,
        raw_ch_weight,
    )
    score += adj_ch_weight
    if compat_tag:
        reasons.append(compat_tag)

    high_amt = int(policy["high_amount_cents"])
    if amount_cents >= high_amt:
        score += 25
        reasons.append("HIGH_SINGLE_AMOUNT")
    elif amount_cents >= high_amt // 2:
        score += 12
        reasons.append("ELEVATED_SINGLE_AMOUNT")

    if win_tx_count > int(policy["velocity_tx_limit"]):
        over_cnt = min(win_tx_count - int(policy["velocity_tx_limit"]), 6)
        score += 10 + over_cnt * 4
        reasons.append("VELOCITY_COUNT_SPIKE")

    if win_amount_cents > int(policy["velocity_amount_cents"]):
        score += 18
        reasons.append("VELOCITY_AMOUNT_SPIKE")

    if not exempt_fanout and win_unique_cps > int(policy["counterparty_fanout_limit"]):
        score += 14
        reasons.append("COUNTERPARTY_FANOUT")

    # 动态中位数突变检测：窗口满 3 笔且当前交易金额达到窗口中位数的 3 倍及以上
    if win_tx_count >= 3 and win_median_cents > 0 and amount_cents >= 3 * win_median_cents:
        score += 11
        reasons.append("MEDIAN_DEVIATION_SPIKE")

    # 三跳受制裁实体传染加分
    if sanction_hop in SANCTION_HOP_SCORES:
        score += SANCTION_HOP_SCORES[sanction_hop]
        reasons.append(f"SANCTION_HOP_{sanction_hop}")

    custom_tree = policy.get("custom_rules")
    if isinstance(custom_tree, dict) and custom_tree:
        matched, bonus, rule_reasons = eval_rule_node(custom_tree, tx)
        if matched:
            score += bonus
            reasons.extend(rule_reasons)

    final_score = max(0, min(100, int(score)))
    if final_score >= int(policy["reject_threshold"]):
        decision = "REJECT"
    elif final_score >= int(policy["review_threshold"]):
        decision = "REVIEW"
    else:
        decision = "ALLOW"

    if not reasons:
        reasons.append("NORMAL_FLOW")
    return final_score, decision, reasons


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次并持久化交易及风控决策记录。"""
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")

    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

    for item in transactions:
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        amount_cents = int(item.get("amount_cents") or 0)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        ts = int(item.get("ts") or 0)
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        policy = load_tenant_policy(db_path, caller.tenant_id)
        sanction_hop = compute_sanction_contagion_hop(
            db_path,
            caller.tenant_id,
            account_id,
            counterparty_id,
            ts,
        )

        conn = open_connection(db_path)
        try:
            hist_rows = conn.execute(
                "SELECT tx_id, account_id, counterparty_id, amount_cents, ts, metadata_json "
                "FROM transactions WHERE tenant_id = ?",
                (caller.tenant_id,),
            ).fetchall()
        finally:
            conn.close()

        win_start = ts - SLIDING_WINDOW_SECONDS
        win_tx_count = 1
        win_amount_cents = amount_cents
        win_amounts_list: list[int] = [amount_cents]
        cp_list: list[str] = [counterparty_id]

        for hr in hist_rows:
            _ = json.loads(hr["metadata_json"])
            if hr["account_id"] == account_id and win_start <= int(hr["ts"]) <= ts:
                h_amt = int(hr["amount_cents"])
                win_tx_count += 1
                win_amount_cents += h_amt
                win_amounts_list.append(h_amt)
                if hr["counterparty_id"] not in cp_list:
                    cp_list.append(hr["counterparty_id"])

        win_unique_cps = len(cp_list)
        win_median_cents = compute_exact_median_cents(win_amounts_list)

        tx_eval_obj = {
            "tx_id": tx_id,
            "account_id": account_id,
            "counterparty_id": counterparty_id,
            "amount_cents": amount_cents,
            "currency": currency,
            "channel": channel,
            "contact_email": contact_email,
            "ts": ts,
            "metadata": metadata,
        }
        risk_score, decision, reasons = compute_single_tx_decision(
            tx_eval_obj,
            policy,
            win_tx_count=win_tx_count,
            win_amount_cents=win_amount_cents,
            win_unique_cps=win_unique_cps,
            win_median_cents=win_median_cents,
            sanction_hop=sanction_hop,
        )

        alert_dispatched = False
        if decision == "REJECT":
            if try_consume_realtime_alert_quota(db_path, caller.tenant_id, ts):
                alert_dispatched = True
                reasons.append("ALERT_QUOTA_CONSUMED")
            else:
                reasons.append("ALERT_POOL_DEPLETED")

        decision_id = f"dec_{tx_id}"
        conn = open_connection(db_path)
        try:
            conn.execute(
                "INSERT INTO transactions("
                "tx_id, tenant_id, batch_id, account_id, counterparty_id, amount_cents, "
                "currency, channel, contact_email, ts, metadata_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tx_id,
                    caller.tenant_id,
                    batch_id,
                    account_id,
                    counterparty_id,
                    amount_cents,
                    currency,
                    channel,
                    contact_email,
                    ts,
                    json.dumps(metadata, sort_keys=True),
                ),
            )
            conn.execute(
                "INSERT INTO risk_decisions("
                "decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
                "sanction_hop, reasons_json, evaluated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision_id,
                    tx_id,
                    caller.tenant_id,
                    account_id,
                    risk_score,
                    decision,
                    win_tx_count,
                    win_amount_cents,
                    win_unique_cps,
                    win_median_cents,
                    sanction_hop,
                    json.dumps(reasons),
                    ts,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        counts[decision] += 1
        results.append(
            {
                "decision_id": decision_id,
                "tx_id": tx_id,
                "account_id": account_id,
                "risk_score": risk_score,
                "decision": decision,
                "sanction_hop": sanction_hop,
                "alert_dispatched": alert_dispatched,
                "window": {
                    "tx_count": win_tx_count,
                    "amount_cents": win_amount_cents,
                    "unique_counterparties": win_unique_cps,
                    "median_cents": win_median_cents,
                },
                "reasons": reasons,
            }
        )

    return {
        "tenant_id": caller.tenant_id,
        "batch_id": batch_id,
        "evaluated_count": len(results),
        "decision_counts": counts,
        "results": results,
    }


def get_risk_decision_detail(
    db_path: str,
    caller: CallerContext,
    decision_id: str,
) -> dict[str, Any]:
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if not row:
            raise LookupError(f"Decision record not found: {decision_id}")
        reasons_list = json.loads(row["reasons_json"])
        return {
            "decision_id": row["decision_id"],
            "tx_id": row["tx_id"],
            "tenant_id": row["tenant_id"],
            "account_id": row["account_id"],
            "risk_score": int(row["risk_score"]),
            "decision": row["decision"],
            "sanction_hop": int(row["sanction_hop"]),
            "alert_dispatched": "ALERT_QUOTA_CONSUMED" in reasons_list,
            "window": {
                "tx_count": int(row["win_tx_count"]),
                "amount_cents": int(row["win_amount_cents"]),
                "unique_counterparties": int(row["win_unique_counterparties"]),
                "median_cents": int(row["win_median_cents"]),
            },
            "reasons": reasons_list,
            "evaluated_at": int(row["evaluated_at"]),
        }
    finally:
        conn.close()
