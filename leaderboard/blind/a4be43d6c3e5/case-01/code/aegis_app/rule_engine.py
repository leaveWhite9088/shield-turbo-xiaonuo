# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、双堆滑窗中位数、四重强原子批处理与自定义规则树引擎。"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import CHANNEL_RISK_WEIGHTS, SANCTION_HOP_SCORES
from .contagion_graph import compute_hop_from_graph, get_or_load_risk_graph
from .ledger_ops import try_consume_realtime_alert_quota_in_tx
from .legacy_compat import apply_sovereign_settlement_adjustment
from .state import get_gateway_state
from .validation import (
    MAX_REGEX_SUBJECT_LEN,
    compile_safe_regex,
    parse_strict_int,
    parse_strict_number,
)
from .window_stats import AccountWindowTracker

PARTNER_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)
MAX_EMAIL_LEN = 254
MAX_RULE_DEPTH = 16
MAX_RULE_NODES = 128
MAX_RULE_CHILDREN = 32


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > MAX_EMAIL_LEN:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(tenant_id)
    cached = t_state.policy_cache
    if cached is not None and t_state.policy_cache_epoch == t_state.policy_epoch:
        return cached
    with t_state.policy_lock:
        cached = t_state.policy_cache
        if cached is not None and t_state.policy_cache_epoch == t_state.policy_epoch:
            return cached
        epoch = t_state.policy_epoch
        with gw_state.pool.borrow() as conn:
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
        t_state.policy_cache = policy
        t_state.policy_cache_epoch = epoch
        return policy


def _validate_rule_tree(node: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    if depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree depth exceeds maximum ({MAX_RULE_DEPTH})")
    counter[0] += 1
    if counter[0] > MAX_RULE_NODES:
        raise ValueError(f"Rule tree node count exceeds maximum ({MAX_RULE_NODES})")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if not node:
        return

    op = str(node.get("op") or "").upper()
    if node.get("bonus_score") is not None:
        parse_strict_int(node.get("bonus_score"), "bonus_score")

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if len(children) > MAX_RULE_CHILDREN:
            raise ValueError(f"Rule children count exceeds maximum ({MAX_RULE_CHILDREN})")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")
        for ch in children:
            _validate_rule_tree(ch, depth + 1, counter)
        return

    field_name = str(node.get("field") or "")
    if not field_name:
        raise ValueError("Leaf rule node missing 'field'")
    if op == "REGEX":
        target = node.get("value")
        if isinstance(target, str):
            compile_safe_regex(target)
    elif op in ("GT", "GTE", "LT", "LTE"):
        parse_strict_number(node.get("value"), "rule target")
    elif op not in ("EQ", "NEQ", "IN", "CONTAINS"):
        raise ValueError(f"Unsupported rule operator: {op}")


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    with t_state.policy_lock:
        current = load_tenant_policy(db_path, caller.tenant_id)
        high_amt = parse_strict_int(updates.get("high_amount_cents", current["high_amount_cents"]), "high_amount_cents", min_val=1)
        vel_tx = parse_strict_int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]), "velocity_tx_limit", min_val=1)
        vel_amt = parse_strict_int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]), "velocity_amount_cents", min_val=0)
        fanout = parse_strict_int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]), "counterparty_fanout_limit", min_val=0)
        rev_th = parse_strict_int(updates.get("review_threshold", current["review_threshold"]), "review_threshold", min_val=1)
        rej_th = parse_strict_int(updates.get("reject_threshold", current["reject_threshold"]), "reject_threshold", min_val=rev_th)
        custom_rules = updates.get("custom_rules", current["custom_rules"])

        if not isinstance(custom_rules, dict):
            raise ValueError("custom_rules must be a JSON object")
        if custom_rules:
            _validate_rule_tree(custom_rules)

        new_ver = int(current["policy_version"]) + 1
        now_ts = int(caller.request_ts or int(time.time()))
        with gw_state.pool.borrow() as conn:
            conn.execute("BEGIN IMMEDIATE")
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
        t_state.policy_epoch += 1
    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def eval_rule_node(
    node: dict[str, Any],
    tx: dict[str, Any],
    *,
    _depth: int = 0,
    _counter: list[int] | None = None,
) -> tuple[bool, int, list[str]]:
    if _counter is None:
        _counter = [0]
    if _depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree depth exceeds maximum ({MAX_RULE_DEPTH})")
    _counter[0] += 1
    if _counter[0] > MAX_RULE_NODES:
        raise ValueError(f"Rule tree node count exceeds maximum ({MAX_RULE_NODES})")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    raw_bonus = node.get("bonus_score")
    bonus = parse_strict_int(raw_bonus if raw_bonus is not None else 0, "bonus_score")
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if len(children) > MAX_RULE_CHILDREN:
            raise ValueError(f"Rule children count exceeds maximum ({MAX_RULE_CHILDREN})")

        child_results = [
            eval_rule_node(ch, tx, _depth=_depth + 1, _counter=_counter)
            for ch in children
        ]
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
    elif op in ("GT", "GTE", "LT", "LTE"):
        if actual is not None:
            a_num = parse_strict_number(actual, field_name)
            t_num = parse_strict_number(target, "rule target")
            if op == "GT":
                matched = a_num > t_num
            elif op == "GTE":
                matched = a_num >= t_num
            elif op == "LT":
                matched = a_num < t_num
            else:
                matched = a_num <= t_num
    elif op == "IN":
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            if len(actual) > MAX_REGEX_SUBJECT_LEN:
                raise ValueError("Regex subject exceeds maximum length")
            compiled = compile_safe_regex(target)
            matched = compiled.search(actual) is not None
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

    if win_tx_count >= 3 and win_median_cents > 0 and amount_cents >= 3 * win_median_cents:
        score += 11
        reasons.append("MEDIAN_DEVIATION_SPIKE")

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
    """按输入顺序逐笔评估实时交易批次（遵循 risk_lock -> quota_lock -> BEGIN IMMEDIATE 四重强原子提交/回滚）。"""
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")

    # 1. 预校验整批字段与严格数值类型，杜绝半截入库
    parsed_txs: list[dict[str, Any]] = []
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction must be a JSON object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        amount_cents = parse_strict_int(item.get("amount_cents"), "amount_cents", min_val=1)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        ts = parse_strict_int(item.get("ts"), "ts", min_val=1)
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if not tx_id or not account_id or not counterparty_id:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        parsed_txs.append(
            {
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
        )

    gw_state = get_gateway_state(db_path)
    t_state = gw_state.tenant(caller.tenant_id)
    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

    # 2. 严格全局锁偏序：risk_lock -> quota_lock -> SQLite BEGIN IMMEDIATE
    with t_state.risk_lock:
        with t_state.quota_lock:
            policy = load_tenant_policy(db_path, caller.tenant_id)
            rg = get_or_load_risk_graph(gw_state, t_state)

            undo_win: list[tuple[AccountWindowTracker, tuple[int, int, int, str]]] = []
            undo_edges: list[tuple[str, str, int]] = []

            with gw_state.pool.borrow() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for tx_obj in parsed_txs:
                        tx_id = tx_obj["tx_id"]
                        account_id = tx_obj["account_id"]
                        counterparty_id = tx_obj["counterparty_id"]
                        amount_cents = tx_obj["amount_cents"]
                        ts = tx_obj["ts"]

                        sanction_hop = compute_hop_from_graph(
                            rg.sanctioned,
                            rg.adj,
                            account_id,
                            counterparty_id,
                            ts,
                        )
                        tracker = rg.accounts.get(account_id)
                        if tracker is None:
                            tracker = AccountWindowTracker()
                            rg.accounts[account_id] = tracker

                        win_tx_count, win_amount_cents, win_unique_cps, win_median_cents, undo_rec = (
                            tracker.push_and_query(ts, amount_cents, counterparty_id)
                        )
                        undo_win.append((tracker, undo_rec))
                        rg.add_edge(account_id, counterparty_id, ts)
                        undo_edges.append((account_id, counterparty_id, ts))

                        risk_score, decision, reasons = compute_single_tx_decision(
                            tx_obj,
                            policy,
                            win_tx_count=win_tx_count,
                            win_amount_cents=win_amount_cents,
                            win_unique_cps=win_unique_cps,
                            win_median_cents=win_median_cents,
                            sanction_hop=sanction_hop,
                        )

                        alert_dispatched = False
                        if decision == "REJECT":
                            if try_consume_realtime_alert_quota_in_tx(conn, caller.tenant_id, ts):
                                alert_dispatched = True
                                reasons.append("ALERT_QUOTA_CONSUMED")
                            else:
                                reasons.append("ALERT_POOL_DEPLETED")

                        decision_id = f"dec_{tx_id}"
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
                                tx_obj["currency"],
                                tx_obj["channel"],
                                tx_obj["contact_email"],
                                ts,
                                json.dumps(tx_obj["metadata"], sort_keys=True),
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

                    conn.commit()
                except Exception:
                    conn.rollback()
                    rg.rollback_edges(undo_edges)
                    by_tracker: dict[int, tuple[AccountWindowTracker, list[tuple[int, int, int, str]]]] = {}
                    for trk, rec in undo_win:
                        tid = id(trk)
                        if tid not in by_tracker:
                            by_tracker[tid] = (trk, [])
                        by_tracker[tid][1].append(rec)
                    for trk, recs in by_tracker.values():
                        trk.rollback_records(recs)
                    raise

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
    gw_state = get_gateway_state(db_path)
    with gw_state.pool.borrow() as conn:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
            (decision_id, caller.tenant_id),
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
