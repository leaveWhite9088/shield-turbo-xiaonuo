# -*- coding: utf-8 -*-
"""四位一体原子风控批次、增量滑窗/传染图与有界安全规则树。"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import ALERT_QUOTA_BUCKET, CHANNEL_RISK_WEIGHTS, SANCTION_HOP_SCORES, SLIDING_WINDOW_SECONDS
from .contagion_graph import TemporalContagionGraph
from .db import open_connection
from .ledger_ops import consume_alert_quota_conn
from .legacy_compat import apply_sovereign_settlement_adjustment
from .runtime import (
    MAX_BATCH_SIZE,
    MAX_SQLITE_INT,
    bounded_text,
    finite_number,
    strict_int,
    tenant_write_lock,
)
from .safe_regex import safe_regex_search
from .window_stats import SlidingAccountWindow


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > 320 or email.count("@") != 1:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return False
    previous_separator = True
    for char in local:
        if char.isascii() and char.isalnum():
            previous_separator = False
        elif char in "._-" and not previous_separator:
            previous_separator = True
        else:
            return False
    if previous_separator:
        return False
    labels = domain.split(".")
    return all(label and all(char.isascii() and (char.isalnum() or char == "-") for char in label) for label in labels)


def _json_loads(raw: str) -> Any:
    return json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite number forbidden")))


def _load_policy_conn(conn: Any, tenant_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, velocity_amount_cents, "
        "counterparty_fanout_limit, review_threshold, reject_threshold, custom_rules_json, updated_at "
        "FROM tenant_policies WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()
    if not row:
        raise LookupError("Policy configuration missing")
    policy = dict(row)
    policy["custom_rules"] = _json_loads(policy["custom_rules_json"])
    validate_rule_tree(policy["custom_rules"])
    return policy


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    conn = open_connection(db_path)
    try:
        return _load_policy_conn(conn, tenant_id)
    finally:
        conn.close()


def validate_rule_tree(rule_tree: Any) -> None:
    if not isinstance(rule_tree, dict):
        raise ValueError("custom_rules must be a JSON object")
    stack: list[tuple[Any, int]] = [(rule_tree, 1)]
    visited = 0
    logical = {"AND", "OR", "NOT"}
    leaves = {"EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"}
    while stack:
        node, depth = stack.pop()
        visited += 1
        if visited > 256 or depth > 16 or not isinstance(node, dict):
            raise ValueError("Rule tree exceeds depth/node safety budget")
        op = str(node.get("op") or "").upper()
        bonus = node.get("bonus_score", 0)
        strict_int(bonus, "bonus_score", minimum=-100_000, maximum=100_000)
        reason = node.get("reason", "")
        if not isinstance(reason, str) or len(reason) > 256:
            raise ValueError("Rule reason is invalid or too long")
        if op in logical:
            children = node.get("children")
            if not isinstance(children, list) or not children or len(children) > 32:
                raise ValueError(f"Logical operator {op} requires 1..32 children")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            stack.extend((child, depth + 1) for child in children)
        elif op in leaves:
            field = node.get("field")
            if not isinstance(field, str) or not field or len(field) > 96 or field.count(".") > 1:
                raise ValueError("Leaf rule has an invalid field")
            if field.startswith("metadata.") and len(field) == len("metadata."):
                raise ValueError("Metadata field cannot be empty")
            target = node.get("value")
            if op == "IN" and (not isinstance(target, list) or len(target) > 128):
                raise ValueError("IN rule requires a bounded list")
            if op == "REGEX":
                if not isinstance(target, str) or len(target) > 256:
                    raise ValueError("REGEX rule requires a bounded pattern")
                # 保存时即编译验证，恶意表达式在毫秒级拒绝。
                safe_regex_search(target, "")
            if op in ("GT", "GTE", "LT", "LTE"):
                finite_number(target, "rule value")
        else:
            raise ValueError(f"Unsupported rule operator: {op}")


def update_tenant_policy(db_path: str, caller: CallerContext, updates: dict[str, Any]) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy updates must be an object")
    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            current = _load_policy_conn(conn, caller.tenant_id)
            names = (
                "high_amount_cents", "velocity_tx_limit", "velocity_amount_cents",
                "counterparty_fanout_limit", "review_threshold", "reject_threshold",
            )
            values = {name: strict_int(updates.get(name, current[name]), name) for name in names}
            custom_rules = updates.get("custom_rules", current["custom_rules"])
            validate_rule_tree(custom_rules)
            if (
                values["high_amount_cents"] <= 0 or values["velocity_tx_limit"] <= 0
                or values["velocity_amount_cents"] <= 0 or values["counterparty_fanout_limit"] <= 0
                or values["review_threshold"] <= 0
                or values["reject_threshold"] < values["review_threshold"]
            ):
                raise ValueError("Invalid policy threshold values")
            new_version = strict_int(current["policy_version"], "policy_version", maximum=MAX_SQLITE_INT - 1) + 1
            now_ts = int(caller.request_ts or int(time.time()))
            conn.execute(
                "UPDATE tenant_policies SET policy_version = ?, high_amount_cents = ?, velocity_tx_limit = ?, "
                "velocity_amount_cents = ?, counterparty_fanout_limit = ?, review_threshold = ?, reject_threshold = ?, "
                "custom_rules_json = ?, updated_at = ? WHERE tenant_id = ?",
                (new_version, *(values[name] for name in names), json.dumps(custom_rules, allow_nan=False),
                 now_ts, caller.tenant_id),
            )
            conn.commit()
            return _load_policy_conn(conn, caller.tenant_id)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        metadata = tx.get("metadata") or {}
        return metadata.get(field_path.split(".", 1)[1])
    return tx.get(field_path)


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    op = str(node.get("op") or "").upper()
    bonus = strict_int(node.get("bonus_score", 0), "bonus_score", minimum=-100_000, maximum=100_000)
    reason = str(node.get("reason") or "").strip()
    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        child_results = [eval_rule_node(child, tx) for child in children]
        if op == "AND":
            matched = all(result[0] for result in child_results)
        elif op == "OR":
            matched = any(result[0] for result in child_results)
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

    actual = _extract_field(tx, str(node.get("field") or ""))
    target = node.get("value")
    if op == "EQ":
        matched = actual == target
    elif op == "NEQ":
        matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        if actual is None:
            matched = False
        else:
            left, right = finite_number(actual, "transaction field"), finite_number(target, "rule value")
            matched = {"GT": left > right, "GTE": left >= right, "LT": left < right, "LTE": left <= right}[op]
    elif op == "IN":
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and target in actual
    elif op == "REGEX":
        matched = isinstance(actual, str) and isinstance(target, str) and safe_regex_search(target, actual)
    else:
        raise ValueError(f"Unsupported rule operator: {op}")
    return (True, bonus, [reason] if reason else []) if matched else (False, 0, [])


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    validate_rule_tree(rule_tree)
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(email):
        raise ValueError("Invalid contact_email format in sample_tx")
    matched, bonus_score, reasons = eval_rule_node(rule_tree, sample_tx)
    return {"matched": matched, "bonus_score": bonus_score, "reasons": reasons}


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
    score = 0
    reasons: list[str] = []
    amount_cents = int(tx["amount_cents"])
    channel = str(tx.get("channel") or "POS_CHIP")
    raw_weight = CHANNEL_RISK_WEIGHTS.get(channel, 8)
    adjusted_weight, exempt_fanout, compat_tag = apply_sovereign_settlement_adjustment(tx, policy, raw_weight)
    score += adjusted_weight
    if compat_tag:
        reasons.append(compat_tag)
    high_amount = int(policy["high_amount_cents"])
    if amount_cents >= high_amount:
        score += 25
        reasons.append("HIGH_SINGLE_AMOUNT")
    elif amount_cents >= high_amount // 2:
        score += 12
        reasons.append("ELEVATED_SINGLE_AMOUNT")
    if win_tx_count > int(policy["velocity_tx_limit"]):
        score += 10 + min(win_tx_count - int(policy["velocity_tx_limit"]), 6) * 4
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


def _normalize_transaction(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("Each transaction must be an object")
    tx = {
        "tx_id": bounded_text(item.get("tx_id") or "", "tx_id", 128),
        "account_id": bounded_text(item.get("account_id") or "", "account_id", 128),
        "counterparty_id": bounded_text(item.get("counterparty_id") or "", "counterparty_id", 128),
        "amount_cents": strict_int(item.get("amount_cents"), "amount_cents", minimum=1),
        "currency": bounded_text(item.get("currency") or "USD", "currency", 16),
        "channel": bounded_text(item.get("channel") or "POS_CHIP", "channel", 32),
        "contact_email": bounded_text(item.get("contact_email") or "", "contact_email", 320),
        "ts": strict_int(item.get("ts"), "ts", minimum=1),
        "metadata": item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
    }
    if not validate_contact_email(tx["contact_email"]):
        raise ValueError(f"Invalid contact_email in transaction {tx['tx_id']}")
    encoded_metadata = json.dumps(tx["metadata"], sort_keys=True, allow_nan=False)
    if len(encoded_metadata) > 16_384:
        raise ValueError("Transaction metadata exceeds size budget")
    tx["metadata_json"] = encoded_metadata
    return tx


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    batch_id = bounded_text(batch_id, "batch_id", 128)
    if not isinstance(transactions, list) or not 1 <= len(transactions) <= MAX_BATCH_SIZE:
        raise ValueError(f"transactions must contain 1..{MAX_BATCH_SIZE} entries")
    normalized = [_normalize_transaction(item) for item in transactions]
    if len({tx["tx_id"] for tx in normalized}) != len(normalized):
        raise ValueError("Duplicate tx_id within batch")
    min_ts = min(tx["ts"] for tx in normalized)
    max_ts = max(tx["ts"] for tx in normalized)

    with tenant_write_lock(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            policy = _load_policy_conn(conn, caller.tenant_id)
            sanctioned = {
                str(row["entity_id"]) for row in conn.execute(
                    "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                    (caller.tenant_id,),
                )
            }
            history_rows = conn.execute(
                "SELECT tx_id, account_id, counterparty_id, amount_cents, ts FROM transactions "
                "WHERE tenant_id = ? AND ts BETWEEN ? AND ?",
                (caller.tenant_id, min_ts - SLIDING_WINDOW_SECONDS, max_ts),
            ).fetchall()
            histories: dict[str, list[tuple[int, int, str]]] = {}
            for row in history_rows:
                histories.setdefault(str(row["account_id"]), []).append(
                    (int(row["ts"]), int(row["amount_cents"]), str(row["counterparty_id"]))
                )
            windows = {
                account: SlidingAccountWindow(rows) for account, rows in histories.items()
            }
            graph = TemporalContagionGraph(history_rows)
            results: list[dict[str, Any]] = []
            counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

            for tx in normalized:
                window = windows.setdefault(tx["account_id"], SlidingAccountWindow(()))
                count, total, unique_cps, median = window.evaluate(
                    tx["ts"], tx["amount_cents"], tx["counterparty_id"]
                )
                if not 0 <= total <= MAX_SQLITE_INT:
                    raise ValueError("Window amount exceeds signed 64-bit storage")
                hop = graph.hop(tx["account_id"], tx["counterparty_id"], tx["ts"], sanctioned)
                risk_score, decision, reasons = compute_single_tx_decision(
                    tx, policy, win_tx_count=count, win_amount_cents=total,
                    win_unique_cps=unique_cps, win_median_cents=median, sanction_hop=hop,
                )
                alert = False
                if decision == "REJECT":
                    alert = consume_alert_quota_conn(conn, caller.tenant_id, tx["ts"])
                    reasons.append("ALERT_QUOTA_CONSUMED" if alert else "ALERT_POOL_DEPLETED")
                decision_id = f"dec_{tx['tx_id']}"
                conn.execute(
                    "INSERT INTO transactions(tx_id, tenant_id, batch_id, account_id, counterparty_id, amount_cents, "
                    "currency, channel, contact_email, ts, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (tx["tx_id"], caller.tenant_id, batch_id, tx["account_id"], tx["counterparty_id"],
                     tx["amount_cents"], tx["currency"], tx["channel"], tx["contact_email"], tx["ts"], tx["metadata_json"]),
                )
                conn.execute(
                    "INSERT INTO risk_decisions(decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                    "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, sanction_hop, reasons_json, evaluated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (decision_id, tx["tx_id"], caller.tenant_id, tx["account_id"], risk_score, decision,
                     count, total, unique_cps, median, hop, json.dumps(reasons), tx["ts"]),
                )
                graph.add_edge(tx["account_id"], tx["counterparty_id"], tx["ts"])
                counts[decision] += 1
                results.append({
                    "decision_id": decision_id, "tx_id": tx["tx_id"], "account_id": tx["account_id"],
                    "risk_score": risk_score, "decision": decision, "sanction_hop": hop,
                    "alert_dispatched": alert,
                    "window": {"tx_count": count, "amount_cents": total,
                               "unique_counterparties": unique_cps, "median_cents": median},
                    "reasons": reasons,
                })
            conn.commit()
            return {
                "tenant_id": caller.tenant_id, "batch_id": batch_id,
                "evaluated_count": len(results), "decision_counts": counts, "results": results,
            }
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise ValueError("Transaction or decision already exists") from exc
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def get_risk_decision_detail(db_path: str, caller: CallerContext, decision_id: str) -> dict[str, Any]:
    decision_id = bounded_text(decision_id, "decision_id", 256)
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, win_tx_count, "
            "win_amount_cents, win_unique_counterparties, win_median_cents, sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE tenant_id = ? AND decision_id = ?",
            (caller.tenant_id, decision_id),
        ).fetchone()
        if not row:
            raise LookupError("Decision record not found")
        reasons = _json_loads(row["reasons_json"])
        return {
            "decision_id": row["decision_id"], "tx_id": row["tx_id"], "tenant_id": caller.tenant_id,
            "account_id": row["account_id"], "risk_score": int(row["risk_score"]),
            "decision": row["decision"], "sanction_hop": int(row["sanction_hop"]),
            "alert_dispatched": "ALERT_QUOTA_CONSUMED" in reasons,
            "window": {"tx_count": int(row["win_tx_count"]), "amount_cents": int(row["win_amount_cents"]),
                       "unique_counterparties": int(row["win_unique_counterparties"]),
                       "median_cents": int(row["win_median_cents"])},
            "reasons": reasons, "evaluated_at": int(row["evaluated_at"]),
        }
    finally:
        conn.close()
