# -*- coding: utf-8 -*-
"""单事务批次风控、增量时间窗/资金图、严格规则树与告警配额联动。"""
from __future__ import annotations

import json
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import CHANNEL_RISK_WEIGHTS, SANCTION_HOP_SCORES, SLIDING_WINDOW_SECONDS
from .contagion_graph import TemporalContagionGraph
from .db import open_connection
from .ledger_ops import _try_consume_alert_conn
from .legacy_compat import apply_sovereign_settlement_adjustment
from .runtime import RUNTIME
from .security import (
    bounded_text,
    finite_number,
    safe_regex_search,
    strict_int,
    validate_contact_email,
    validate_json_value,
)
from .window_stats import AccountWindow, compute_exact_median_cents


def validate_contact_email_format(email: str) -> bool:
    return validate_contact_email(email)


def validate_rule_tree(rule_tree: Any, *, max_depth: int = 12, max_nodes: int = 256) -> None:
    if not isinstance(rule_tree, dict):
        raise ValueError("Rule tree must be an object")
    stack: list[tuple[Any, int]] = [(rule_tree, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > max_nodes or depth > max_depth or not isinstance(node, dict):
            raise ValueError("Rule tree exceeds depth/node budget")
        op = str(node.get("op") or "").upper()
        if op in ("AND", "OR", "NOT"):
            children = node.get("children")
            if not isinstance(children, list) or not children or len(children) > 32:
                raise ValueError("Invalid logical rule children")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            stack.extend((child, depth + 1) for child in children)
        elif op not in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"):
            raise ValueError(f"Unsupported rule operator: {op}")
        if op == "REGEX":
            # 空 actual 也执行 AST 静态检查，确保保存策略时即熔断危险模式。
            safe_regex_search(node.get("value"), "")
        if "bonus_score" in node:
            strict_int(node.get("bonus_score") or 0, "bonus_score", minimum=-1_000_000, maximum=1_000_000)
        if "reason" in node:
            bounded_text(node.get("reason") or "", "reason", max_length=256, allow_empty=True)
        if "field" in node:
            bounded_text(node.get("field") or "", "field", max_length=128)


def _load_policy_conn(conn: Any, tenant_id: str) -> dict[str, Any]:
    row = conn.execute(
        "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, velocity_amount_cents, "
        "counterparty_fanout_limit, review_threshold, reject_threshold, custom_rules_json, updated_at "
        "FROM tenant_policies WHERE tenant_id = ?", (tenant_id,),
    ).fetchone()
    if not row:
        raise LookupError("Policy configuration missing for tenant")
    policy = dict(row)
    try:
        policy["custom_rules"] = json.loads(policy["custom_rules_json"])
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Stored policy rule tree is invalid") from exc
    if policy["custom_rules"]:
        validate_rule_tree(policy["custom_rules"])
    return policy


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    conn = open_connection(db_path)
    try:
        return _load_policy_conn(conn, tenant_id)
    finally:
        conn.close()


def update_tenant_policy(db_path: str, caller: CallerContext, updates: dict[str, Any]) -> dict[str, Any]:
    require_admin(caller)
    with RUNTIME.tenant_write(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            current = _load_policy_conn(conn, caller.tenant_id)
            high = strict_int(updates.get("high_amount_cents", current["high_amount_cents"]), "high_amount_cents", minimum=1)
            velocity_tx = strict_int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]), "velocity_tx_limit", minimum=1)
            velocity_amount = strict_int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]), "velocity_amount_cents")
            fanout = strict_int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]), "counterparty_fanout_limit")
            review = strict_int(updates.get("review_threshold", current["review_threshold"]), "review_threshold", minimum=1)
            reject = strict_int(updates.get("reject_threshold", current["reject_threshold"]), "reject_threshold")
            custom = updates.get("custom_rules", current["custom_rules"])
            if reject < review:
                raise ValueError("reject_threshold must not be below review_threshold")
            validate_rule_tree(custom)
            version = int(current["policy_version"]) + 1
            now_ts = caller.request_ts or int(time.time())
            serialized = json.dumps(custom, allow_nan=False, separators=(",", ":"))
            if len(serialized) > 262_144:
                raise ValueError("Custom rule tree exceeds storage budget")
            conn.execute(
                "UPDATE tenant_policies SET policy_version = ?, high_amount_cents = ?, velocity_tx_limit = ?, "
                "velocity_amount_cents = ?, counterparty_fanout_limit = ?, review_threshold = ?, reject_threshold = ?, "
                "custom_rules_json = ?, updated_at = ? WHERE tenant_id = ?",
                (version, high, velocity_tx, velocity_amount, fanout, review, reject,
                 serialized, now_ts, caller.tenant_id),
            )
            conn.commit()
            policy = dict(current)
            policy.update({
                "policy_version": version, "high_amount_cents": high, "velocity_tx_limit": velocity_tx,
                "velocity_amount_cents": velocity_amount, "counterparty_fanout_limit": fanout,
                "review_threshold": review, "reject_threshold": reject, "custom_rules": custom,
                "custom_rules_json": serialized, "updated_at": now_ts,
            })
            return policy
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        metadata = tx.get("metadata") or {}
        return metadata.get(field_path.split(".", 1)[1]) if isinstance(metadata, dict) else None
    return tx.get(field_path)


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any], _depth: int = 0) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict) or _depth > 12:
        raise ValueError("Rule node must be an object within depth budget")
    op = str(node.get("op") or "").upper()
    bonus = strict_int(node.get("bonus_score") or 0, "bonus_score", minimum=-1_000_000, maximum=1_000_000)
    reason = str(node.get("reason") or "").strip()
    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children or len(children) > 32:
            raise ValueError(f"Logical operator {op} requires valid children")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")
        results = [eval_rule_node(child, tx, _depth + 1) for child in children]
        if op == "AND":
            matched = all(result[0] for result in results)
        elif op == "OR":
            matched = any(result[0] for result in results)
        else:
            matched = not results[0][0]
        if not matched:
            return False, 0, []
        total_bonus = bonus
        reasons: list[str] = []
        if op != "NOT":
            for child_ok, child_score, child_reasons in results:
                if child_ok:
                    total_bonus += child_score
                    reasons.extend(child_reasons)
        if reason:
            reasons.append(reason)
        return True, total_bonus, reasons

    field = str(node.get("field") or "")
    if not field:
        raise ValueError("Leaf rule node missing 'field'")
    actual = _extract_field(tx, field)
    target = node.get("value")
    if op == "EQ":
        matched = actual == target
    elif op == "NEQ":
        matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        if actual is None:
            matched = False
        else:
            left = finite_number(actual, "rule actual")
            right = finite_number(target, "rule target")
            matched = left > right if op == "GT" else left >= right if op == "GTE" else left < right if op == "LT" else left <= right
    elif op == "IN":
        matched = isinstance(target, list) and len(target) <= 256 and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and len(actual) <= 4096 and target in actual
    elif op == "REGEX":
        matched = safe_regex_search(target, actual)
    else:
        raise ValueError(f"Unsupported rule operator: {op}")
    return (True, bonus, [reason] if reason else []) if matched else (False, 0, [])


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    validate_json_value(sample_tx, max_depth=16, max_nodes=2048)
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(email):
        raise ValueError("Invalid contact_email format in sample_tx")
    validate_rule_tree(rule_tree)
    matched, bonus, reasons = eval_rule_node(rule_tree, sample_tx)
    return {"matched": matched, "bonus_score": bonus, "reasons": reasons}


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
    amount = int(tx["amount_cents"])
    channel = str(tx.get("channel") or "POS_CHIP")
    channel_weight, exempt_fanout, compat_tag = apply_sovereign_settlement_adjustment(
        tx, policy, CHANNEL_RISK_WEIGHTS.get(channel, 8),
    )
    score += channel_weight
    if compat_tag:
        reasons.append(compat_tag)
    high = int(policy["high_amount_cents"])
    if amount >= high:
        score += 25
        reasons.append("HIGH_SINGLE_AMOUNT")
    elif amount >= high // 2:
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
    if win_tx_count >= 3 and win_median_cents > 0 and amount >= 3 * win_median_cents:
        score += 11
        reasons.append("MEDIAN_DEVIATION_SPIKE")
    if sanction_hop in SANCTION_HOP_SCORES:
        score += SANCTION_HOP_SCORES[sanction_hop]
        reasons.append(f"SANCTION_HOP_{sanction_hop}")
    custom = policy.get("custom_rules")
    if isinstance(custom, dict) and custom:
        matched, bonus, rule_reasons = eval_rule_node(custom, tx)
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
    tx_id = bounded_text(item.get("tx_id"), "tx_id", max_length=128)
    account_id = bounded_text(item.get("account_id"), "account_id", max_length=128)
    counterparty_id = bounded_text(item.get("counterparty_id"), "counterparty_id", max_length=128)
    amount = strict_int(item.get("amount_cents"), "amount_cents", minimum=1)
    ts = strict_int(item.get("ts"), "ts", minimum=1)
    currency = bounded_text(item.get("currency") or "USD", "currency", max_length=16)
    channel = bounded_text(item.get("channel") or "POS_CHIP", "channel", max_length=32)
    email = bounded_text(item.get("contact_email"), "contact_email", max_length=254)
    metadata = item.get("metadata") if item.get("metadata") is not None else {}
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    validate_json_value(metadata, max_depth=12, max_nodes=1024)
    if not validate_contact_email(email):
        raise ValueError(f"Invalid contact_email in transaction {tx_id}")
    return {
        "tx_id": tx_id, "account_id": account_id, "counterparty_id": counterparty_id,
        "amount_cents": amount, "currency": currency, "channel": channel,
        "contact_email": email, "ts": ts, "metadata": metadata,
    }


class _BatchTemporalState:
    """前向时间流 O(log W) 增量；乱序输入精确重建，杜绝单调窗口近似。"""

    def __init__(self, tenant_id: str, history: list[Any], sanctioned: set[str]) -> None:
        self.tenant_id = tenant_id
        self.history = sorted(history, key=lambda row: (int(row["ts"]), str(row["tx_id"])))
        self.sanctioned = sanctioned
        self.current_ts: int | None = None
        self.pointer = 0
        self.windows: dict[str, AccountWindow] = {}
        self.graph = TemporalContagionGraph(tenant_id, sanctioned)
        self.added_batch: set[int] = set()

    def _add(self, record: Any) -> None:
        self.graph.add(record)
        account = str(record["account_id"])
        self.windows.setdefault(account, AccountWindow()).add(record)

    def _reset(self, ts: int, prior: list[dict[str, Any]]) -> None:
        self.current_ts = ts
        self.pointer = 0
        self.windows = {}
        self.graph = TemporalContagionGraph(self.tenant_id, self.sanctioned)
        self.added_batch.clear()
        start = ts - SLIDING_WINDOW_SECONDS
        for row in self.history:
            if int(row["ts"]) > ts:
                break
            self.pointer += 1
            if int(row["ts"]) >= start:
                self._add(row)
        eligible = [(index, tx) for index, tx in enumerate(prior) if start <= tx["ts"] <= ts]
        for index, tx in sorted(eligible, key=lambda pair: (pair[1]["ts"], pair[1]["tx_id"])):
            self._add(tx)
            self.added_batch.add(index)

    def prepare(self, ts: int, prior: list[dict[str, Any]]) -> None:
        if self.current_ts is None or ts < self.current_ts:
            self._reset(ts, prior)
            return
        for row in self.history[self.pointer:]:
            if int(row["ts"]) > ts:
                break
            self._add(row)
            self.pointer += 1
        pending = [
            (index, tx) for index, tx in enumerate(prior)
            if index not in self.added_batch and tx["ts"] <= ts
        ]
        for index, tx in sorted(pending, key=lambda pair: (pair[1]["ts"], pair[1]["tx_id"])):
            self._add(tx)
            self.added_batch.add(index)
        start = ts - SLIDING_WINDOW_SECONDS
        self.graph.expire(start)
        for window in self.windows.values():
            window.expire(start)
        self.current_ts = ts


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    batch_id = bounded_text(batch_id, "batch_id", max_length=128)
    if not isinstance(transactions, list) or not transactions or len(transactions) > 128:
        raise ValueError("transactions must contain 1..128 entries")
    normalized = [_normalize_transaction(item) for item in transactions]
    if len({tx["tx_id"] for tx in normalized}) != len(normalized):
        raise ValueError("Duplicate tx_id within batch")
    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

    # 数据库、账户滑窗、传染图、告警配额共享同一个线性化写临界区。
    with RUNTIME.tenant_write(db_path, caller.tenant_id):
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            policy = _load_policy_conn(conn, caller.tenant_id)
            sanctioned = {
                str(row["entity_id"]) for row in conn.execute(
                    "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
                    (caller.tenant_id,),
                ).fetchall()
            }
            minimum = min(tx["ts"] for tx in normalized) - SLIDING_WINDOW_SECONDS
            maximum = max(tx["ts"] for tx in normalized)
            history = conn.execute(
                "SELECT tx_id, account_id, counterparty_id, amount_cents, ts FROM transactions "
                "WHERE tenant_id = ? AND ts >= ? AND ts <= ? ORDER BY ts ASC, tx_id ASC",
                (caller.tenant_id, minimum, maximum),
            ).fetchall()
            state = _BatchTemporalState(caller.tenant_id, list(history), sanctioned)

            for index, tx in enumerate(normalized):
                state.prepare(tx["ts"], normalized[:index])
                window = state.windows.get(tx["account_id"], AccountWindow())
                win_count, win_amount, win_unique, win_median = window.stats_with(
                    tx["amount_cents"], tx["counterparty_id"],
                )
                hop = state.graph.hop_for(tx["account_id"], tx["counterparty_id"])
                score, decision, reasons = compute_single_tx_decision(
                    tx, policy, win_tx_count=win_count, win_amount_cents=win_amount,
                    win_unique_cps=win_unique, win_median_cents=win_median, sanction_hop=hop,
                )
                alert = False
                if decision == "REJECT":
                    alert = _try_consume_alert_conn(conn, caller.tenant_id, tx["ts"])
                    reasons.append("ALERT_QUOTA_CONSUMED" if alert else "ALERT_POOL_DEPLETED")
                decision_id = f"dec_{tx['tx_id']}"
                conn.execute(
                    "INSERT INTO transactions(tx_id, tenant_id, batch_id, account_id, counterparty_id, "
                    "amount_cents, currency, channel, contact_email, ts, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (tx["tx_id"], caller.tenant_id, batch_id, tx["account_id"], tx["counterparty_id"],
                     tx["amount_cents"], tx["currency"], tx["channel"], tx["contact_email"], tx["ts"],
                     json.dumps(tx["metadata"], sort_keys=True, allow_nan=False)),
                )
                conn.execute(
                    "INSERT INTO risk_decisions(decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                    "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, sanction_hop, "
                    "reasons_json, evaluated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (decision_id, tx["tx_id"], caller.tenant_id, tx["account_id"], score, decision,
                     win_count, win_amount, win_unique, win_median, hop, json.dumps(reasons), tx["ts"]),
                )
                counts[decision] += 1
                results.append({
                    "decision_id": decision_id, "tx_id": tx["tx_id"], "account_id": tx["account_id"],
                    "risk_score": score, "decision": decision, "sanction_hop": hop,
                    "alert_dispatched": alert,
                    "window": {
                        "tx_count": win_count, "amount_cents": win_amount,
                        "unique_counterparties": win_unique, "median_cents": win_median,
                    },
                    "reasons": reasons,
                })
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            # results/counts 与 state 都是本批次局部对象，异常后直接丢弃，无内存污染。
            raise
        finally:
            conn.close()
    return {
        "tenant_id": caller.tenant_id, "batch_id": batch_id, "evaluated_count": len(results),
        "decision_counts": counts, "results": results,
    }


def get_risk_decision_detail(db_path: str, caller: CallerContext, decision_id: str) -> dict[str, Any]:
    decision_id = bounded_text(decision_id, "decision_id", max_length=256)
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, win_tx_count, "
            "win_amount_cents, win_unique_counterparties, win_median_cents, sanction_hop, reasons_json, "
            "evaluated_at FROM risk_decisions WHERE tenant_id = ? AND decision_id = ?",
            (caller.tenant_id, decision_id),
        ).fetchone()
        if not row:
            raise LookupError("Decision record not found")
        reasons = json.loads(row["reasons_json"])
        return {
            "decision_id": row["decision_id"], "tx_id": row["tx_id"], "tenant_id": row["tenant_id"],
            "account_id": row["account_id"], "risk_score": int(row["risk_score"]),
            "decision": row["decision"], "sanction_hop": int(row["sanction_hop"]),
            "alert_dispatched": "ALERT_QUOTA_CONSUMED" in reasons,
            "window": {
                "tx_count": int(row["win_tx_count"]), "amount_cents": int(row["win_amount_cents"]),
                "unique_counterparties": int(row["win_unique_counterparties"]),
                "median_cents": int(row["win_median_cents"]),
            },
            "reasons": reasons, "evaluated_at": int(row["evaluated_at"]),
        }
    finally:
        conn.close()
