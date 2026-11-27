# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。

纵深加固要点：

* **规则树预算**：节点总数、树深度、正则模式长度与匹配输入长度均有硬上限，
  膨胀规则树与恶意回溯正则在毫秒级被拒绝；
* **严格数值类型守卫**：拒绝 ``bool`` 冒充整数、超 64 位整数、``NaN``/``Inf``，
  杜绝类型混淆导致的比较异常与静默失真；
* **四位一体强原子批次**：数据库写入、滑动窗口、传染图与 ``REALTIME_ALERT_POOL``
  配额扣减同处一个 ``BEGIN IMMEDIATE`` 事务，任一笔非法或主键冲突则整批回滚，
  零半截落盘、零配额泄漏。
"""
from __future__ import annotations

import json
import math
import re
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import compute_sanction_contagion_hop
from .db import open_connection, write_transaction
from .ledger_ops import try_consume_realtime_alert_quota
from .legacy_compat import apply_sovereign_settlement_adjustment
from .locks import tenant_write_scope
from .state import DOMAIN_POLICY
from .tenant_cache import load_policy_snapshot
from .window_stats import compute_exact_median_cents

PARTNER_EMAIL_PATTERN = re.compile(
    r"^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)$"
)

# ---- 复杂度与类型硬预算（毫秒级熔断阈值）---------------------------------
MAX_RULE_NODES = 2000
MAX_RULE_DEPTH = 24
MAX_REGEX_PATTERN_LEN = 200
MAX_REGEX_INPUT_LEN = 4096
MAX_BATCH_TRANSACTIONS = 500
MAX_METADATA_BYTES = 64 * 1024
MAX_INT64 = 2**63 - 1

# 灾难性回溯特征：嵌套量词（(a+)+ / (a*)*）与被量词修饰的交替分支（(a|a)*）。
_CATASTROPHIC_NESTED = re.compile(r"\([^()]*(\+|\*|\{\d+[^()]*\})[^()]*\)\s*(\+|\*|\{\d+)")
_CATASTROPHIC_ALT = re.compile(r"\([^()]*\|[^()]*\)\s*(\+|\*)")


class RuleBudget:
    """规则树求值预算（节点数 / 深度）。"""

    __slots__ = ("nodes",)

    def __init__(self) -> None:
        self.nodes = 0


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email:
        return False
    if len(email) > 320:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def _to_number(value: Any) -> float:
    """严格数值归一化：拒绝 bool、超 64 位整数、NaN/Inf 与非数值对象。"""
    if isinstance(value, bool):
        raise ValueError("Boolean values are not accepted in numeric rule comparisons")
    if isinstance(value, int):
        if value > MAX_INT64 or value < -MAX_INT64 - 1:
            raise ValueError("Integer value exceeds the 64-bit range")
        return float(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/Infinity values are not accepted in numeric rule comparisons")
        return value
    if isinstance(value, str):
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Non-numeric value in rule comparison") from exc
        if math.isnan(parsed) or math.isinf(parsed):
            raise ValueError("NaN/Infinity values are not accepted in numeric rule comparisons")
        return parsed
    raise ValueError("Unsupported value type in rule comparison")


def _require_int(value: Any, field_name: str) -> int:
    """严格整数校验：仅接受 int / 整数字符串 / 整数值的浮点。"""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, float):
        if not value.is_integer():
            raise ValueError(f"{field_name} must be an integer")
        parsed = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text or not (text.isdigit() or (text[0] == "-" and text[1:].isdigit())):
            raise ValueError(f"{field_name} must be an integer")
        parsed = int(text)
    else:
        raise ValueError(f"{field_name} must be an integer")
    if parsed > MAX_INT64 or parsed < -MAX_INT64 - 1:
        raise ValueError(f"{field_name} exceeds the 64-bit range")
    return parsed


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    return load_policy_snapshot(db_path, tenant_id)


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
    _validate_rule_tree_shape(custom_rules)

    new_ver = int(current["policy_version"]) + 1
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        with write_transaction(conn):
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
    finally:
        conn.close()

    from .state import get_runtime_state

    get_runtime_state(db_path).bump(caller.tenant_id, DOMAIN_POLICY)
    return load_tenant_policy(db_path, caller.tenant_id)


def _validate_rule_tree_shape(tree: Any, budget: RuleBudget | None = None, depth: int = 0) -> None:
    """规则树结构预算校验（节点总数与深度）。"""
    if budget is None:
        budget = RuleBudget()
    if depth > MAX_RULE_DEPTH:
        raise ValueError("Rule tree nesting depth exceeds the allowed limit")
    budget.nodes += 1
    if budget.nodes > MAX_RULE_NODES:
        raise ValueError("Rule tree node count exceeds the allowed limit")
    if not isinstance(tree, dict):
        raise ValueError("Rule node must be an object")
    children = tree.get("children")
    if isinstance(children, list):
        if len(children) > 64:
            raise ValueError("Rule node children count exceeds the allowed limit")
        for child in children:
            _validate_rule_tree_shape(child, budget, depth + 1)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    """正则安全闸门：长度上限 + 灾难性回溯特征拒绝 + 预编译。"""
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("REGEX rule requires a non-empty pattern")
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        raise ValueError("REGEX pattern exceeds the maximum length")
    if _CATASTROPHIC_NESTED.search(pattern) or _CATASTROPHIC_ALT.search(pattern):
        raise ValueError("REGEX pattern contains unsafe nested quantifiers")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError("Invalid REGEX pattern") from exc


def _eval_rule_node(node: dict[str, Any], tx: dict[str, Any], budget: RuleBudget, depth: int = 0) -> tuple[bool, int, list[str]]:
    if depth > MAX_RULE_DEPTH:
        raise ValueError("Rule tree nesting depth exceeds the allowed limit")
    budget.nodes += 1
    if budget.nodes > MAX_RULE_NODES:
        raise ValueError("Rule tree node count exceeds the allowed limit")

    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    bonus = int(node.get("bonus_score") or 0)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if len(children) > 64:
            raise ValueError("Rule node children count exceeds the allowed limit")

        child_results = [_eval_rule_node(ch, tx, budget, depth + 1) for ch in children]
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
    if len(field_name) > 128:
        raise ValueError("Leaf rule node field name exceeds the maximum length")
    actual = _extract_field(tx, field_name)
    target = node.get("value")

    matched = False
    if op == "EQ":
        matched = actual == target
    elif op == "NEQ":
        matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        if actual is None:
            matched = False
        else:
            left = _to_number(actual)
            right = _to_number(target)
            if op == "GT":
                matched = left > right
            elif op == "GTE":
                matched = left >= right
            elif op == "LT":
                matched = left < right
            else:
                matched = left <= right
    elif op == "IN":
        if not isinstance(target, list):
            matched = False
        else:
            if len(target) > 1000:
                raise ValueError("IN rule target list exceeds the allowed size")
            matched = actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            if len(actual) > MAX_REGEX_INPUT_LEN:
                raise ValueError("REGEX input exceeds the maximum length")
            compiled = _compile_safe_regex(target)
            matched = compiled.search(actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    """求值单棵规则树（保留历史对外签名，内部带预算闸门）。"""
    return _eval_rule_node(node, tx, RuleBudget())


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
    _validate_rule_tree_shape(rule_tree)
    matched, bonus_score, reasons = _eval_rule_node(rule_tree, sample_tx, RuleBudget())
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
        matched, bonus, rule_reasons = _eval_rule_node(custom_tree, tx, RuleBudget())
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
    """按输入顺序逐笔评估实时交易批次并持久化交易及风控决策记录（整批强原子）。"""
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > MAX_BATCH_TRANSACTIONS:
        raise ValueError(f"Batch exceeds the maximum size of {MAX_BATCH_TRANSACTIONS} transactions")

    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
    policy = load_tenant_policy(db_path, caller.tenant_id)

    conn = open_connection(db_path)
    try:
        # 锁偏序：先租户锁 → 再配额池锁（升序）→ 最后数据库写锁。
        with tenant_write_scope(caller.tenant_id, ALERT_QUOTA_BUCKET):
            with write_transaction(conn):
                for item in transactions:
                    if not isinstance(item, dict):
                        raise ValueError("Each transaction must be an object")
                    tx_id = str(item.get("tx_id") or "").strip()
                    account_id = str(item.get("account_id") or "").strip()
                    counterparty_id = str(item.get("counterparty_id") or "").strip()
                    amount_cents = _require_int(item.get("amount_cents"), "amount_cents")
                    currency = str(item.get("currency") or "USD").strip()
                    channel = str(item.get("channel") or "POS_CHIP").strip()
                    contact_email = str(item.get("contact_email") or "").strip()
                    ts = _require_int(item.get("ts"), "ts")
                    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

                    if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
                        raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
                    if len(tx_id) > 128 or len(account_id) > 128 or len(counterparty_id) > 128:
                        raise ValueError(f"Transaction identifier fields exceed the maximum length for tx_id={tx_id!r}")
                    if len(currency) > 16 or len(channel) > 32:
                        raise ValueError(f"Transaction currency/channel exceeds the maximum length for tx_id={tx_id!r}")
                    if not validate_contact_email(contact_email):
                        raise ValueError(f"Invalid contact_email in transaction {tx_id}")
                    if len(json.dumps(metadata, sort_keys=True)) > MAX_METADATA_BYTES:
                        raise ValueError(f"Transaction metadata exceeds the maximum size for tx_id={tx_id}")

                    sanction_hop = compute_sanction_contagion_hop(
                        db_path,
                        caller.tenant_id,
                        account_id,
                        counterparty_id,
                        ts,
                        conn=conn,
                    )

                    # 滑动窗口四维统计：同批先序交易在同一连接内已可见，天然纳入本次窗口。
                    win_start = ts - SLIDING_WINDOW_SECONDS
                    hist_rows = conn.execute(
                        "SELECT amount_cents, counterparty_id FROM transactions "
                        "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ?",
                        (caller.tenant_id, account_id, win_start, ts),
                    ).fetchall()

                    win_tx_count = 1
                    win_amount_cents = amount_cents
                    win_amounts_list: list[int] = [amount_cents]
                    cp_set: set[str] = {counterparty_id}

                    for hr in hist_rows:
                        h_amt = int(hr["amount_cents"])
                        win_tx_count += 1
                        win_amount_cents += h_amt
                        win_amounts_list.append(h_amt)
                        cp_set.add(str(hr["counterparty_id"]))

                    win_unique_cps = len(cp_set)
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
                        if try_consume_realtime_alert_quota(db_path, caller.tenant_id, ts, conn=conn):
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
    finally:
        conn.close()

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
    finally:
        conn.close()
