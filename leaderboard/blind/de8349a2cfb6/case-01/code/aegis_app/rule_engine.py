# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。"""
from __future__ import annotations

import json
import math
import pathlib
import re
import threading
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    MAX_BATCH_TX_COUNT,
    MAX_RULE_TREE_DEPTH,
    MAX_RULE_TREE_NODES,
    SANCTION_HOP_SCORES,
    parse_strict_int,
)
from .contagion_graph import compute_sanction_contagion_hop, get_tenant_tx_engine
from .db import (
    bump_domain_epoch,
    get_domain_epoch,
    get_tenant_quota_lock,
    open_connection,
)
from .legacy_compat import apply_sovereign_settlement_adjustment
from .window_stats import AccountWindowTracker


def validate_contact_email(email: str) -> bool:
    """线性时间 O(N) 确定性邮箱格式校验（彻底消除嵌套量词回溯 ReDoS）。"""
    if not isinstance(email, str) or not email or len(email) > 254:
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain or len(local) > 64:
        return False
    for part in local.split("."):
        if not part:
            return False
        for sub in part.split("_"):
            if not sub:
                return False
            for seg in sub.split("-"):
                if not seg or not seg.isalnum() or not seg.isascii():
                    return False
    dom_parts = domain.split(".")
    if len(dom_parts) < 2:
        return False
    for dp in dom_parts:
        if not dp or dp.startswith("-") or dp.endswith("-"):
            return False
        for ch in dp:
            if not (ch.isalnum() and ch.isascii()) and ch != "-":
                return False
    return True


_BACKREF_RE = re.compile(r"\\[1-9]")
_BRACE_BOUND_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")
_QUANT_TOKENS = frozenset({"*", "+", "?", "}"})


def _validate_safe_regex_pattern(pattern: str) -> None:
    """拦截嵌套量词、分支重叠量词、反向引用与花括号大上界（> 64）等 ReDoS 正则炸弹。"""
    if not isinstance(pattern, str) or len(pattern) > 128:
        raise ValueError("Regex pattern exceeds maximum length or is invalid")
    if _BACKREF_RE.search(pattern):
        raise ValueError("Backreferences are forbidden in custom rule regex")
    if "(?" in pattern:
        raise ValueError("Advanced regex group constructs are forbidden")

    for m in _BRACE_BOUND_RE.finditer(pattern):
        low_s, high_s = m.group(1), m.group(2)
        if int(low_s) > 64:
            raise ValueError("Regex quantifier bound exceeds limit (64)")
        if high_s is None:
            continue
        if high_s == "":
            raise ValueError("Unbounded brace quantifier is forbidden")
        if int(high_s) > 64 or int(high_s) < int(low_s):
            raise ValueError("Regex quantifier upper bound invalid or exceeds limit (64)")

    # 扫描括号分组内是否含重复量词或分支，且分组外紧跟量词
    group_stack: list[dict[str, bool]] = []
    i = 0
    n = len(pattern)
    prev_was_quant = False
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            prev_was_quant = False
            continue
        if ch == "(":
            group_stack.append({"has_quant": False, "has_alt": False})
            prev_was_quant = False
        elif ch == ")":
            if not group_stack:
                raise ValueError("Unbalanced parentheses in regex")
            grp = group_stack.pop()
            next_ch = pattern[i + 1] if (i + 1 < n) else ""
            is_followed_by_quant = next_ch in ("*", "+", "?", "{")
            if is_followed_by_quant and (grp["has_quant"] or grp["has_alt"]):
                raise ValueError("Nested or alternation quantifier in regex is forbidden (ReDoS risk)")
            if group_stack and (grp["has_quant"] or is_followed_by_quant):
                group_stack[-1]["has_quant"] = True
            prev_was_quant = is_followed_by_quant
        elif ch == "|":
            if group_stack:
                group_stack[-1]["has_alt"] = True
            prev_was_quant = False
        elif ch in ("*", "+", "?"):
            if prev_was_quant:
                raise ValueError("Consecutive quantifiers in regex are forbidden")
            if group_stack:
                group_stack[-1]["has_quant"] = True
            prev_was_quant = True
        elif ch == "{":
            close_idx = pattern.find("}", i + 1)
            if close_idx != -1:
                if prev_was_quant:
                    raise ValueError("Consecutive quantifiers in regex are forbidden")
                if group_stack:
                    group_stack[-1]["has_quant"] = True
                prev_was_quant = True
                i = close_idx
        else:
            prev_was_quant = False
        i += 1


def _validate_rule_tree_budget(root: dict[str, Any]) -> None:
    """预检自定义规则树节点总数（<= 64）、最大深度（<= 12）及所有 REGEX 叶子节点的安全性。"""
    if not isinstance(root, dict):
        raise ValueError("Rule tree must be a JSON object")
    if not root:
        return

    node_count = 0
    stack: list[tuple[dict[str, Any], int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, dict):
            raise ValueError("Rule node must be an object")
        node_count += 1
        if node_count > MAX_RULE_TREE_NODES:
            raise ValueError(f"Rule tree exceeds maximum allowed nodes ({MAX_RULE_TREE_NODES})")
        if depth > MAX_RULE_TREE_DEPTH:
            raise ValueError(f"Rule tree exceeds maximum allowed depth ({MAX_RULE_TREE_DEPTH})")

        op = str(node.get("op") or "").upper()
        if "bonus_score" in node and node["bonus_score"] is not None:
            parse_strict_int(node["bonus_score"], "bonus_score", min_val=-100, max_val=100)

        if op in ("AND", "OR", "NOT"):
            children = node.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            for ch in children:
                if not isinstance(ch, dict):
                    raise ValueError("Rule child node must be an object")
                stack.append((ch, depth + 1))
        elif op in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"):
            field_name = str(node.get("field") or "").strip()
            if not field_name:
                raise ValueError("Leaf rule node missing 'field'")
            target = node.get("value")
            if op in ("GT", "GTE", "LT", "LTE"):
                if isinstance(target, bool) or not isinstance(target, (int, float)):
                    raise ValueError(f"Numeric operator {op} requires numeric target value")
                if math.isnan(float(target)) or math.isinf(float(target)):
                    raise ValueError("NaN or Inf not allowed in rule target")
            elif op == "IN":
                if not isinstance(target, list) or len(target) > 128:
                    raise ValueError("IN operator requires a list of at most 128 items")
            elif op == "REGEX":
                if not isinstance(target, str):
                    raise ValueError("REGEX operator requires a string pattern")
                _validate_safe_regex_pattern(target)
                try:
                    re.compile(target)
                except re.error as exc:
                    raise ValueError(f"Invalid regex pattern: {exc}") from exc
        else:
            raise ValueError(f"Unsupported rule operator: {op}")


_POLICY_CACHE_LOCK = threading.Lock()
_POLICY_CACHES: dict[str, tuple[int, dict[str, Any]]] = {}


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    db_key = str(pathlib.Path(db_path).resolve())
    cache_key = f"{db_key}::{tenant_id}"
    cur_epoch = get_domain_epoch(db_key, tenant_id, "policy")
    with _POLICY_CACHE_LOCK:
        cached = _POLICY_CACHES.get(cache_key)
        if cached is not None and cached[0] == cur_epoch:
            return dict(cached[1])

    conn = open_connection(db_key)
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
    finally:
        conn.close()

    with _POLICY_CACHE_LOCK:
        if len(_POLICY_CACHES) > 256:
            _POLICY_CACHES.pop(next(iter(_POLICY_CACHES)), None)
        _POLICY_CACHES[cache_key] = (cur_epoch, policy)
    return dict(policy)


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = parse_strict_int(updates.get("high_amount_cents", current["high_amount_cents"]), "high_amount_cents", min_val=1)
    vel_tx = parse_strict_int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]), "velocity_tx_limit", min_val=1)
    vel_amt = parse_strict_int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]), "velocity_amount_cents", min_val=1)
    fanout = parse_strict_int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]), "counterparty_fanout_limit", min_val=1)
    rev_th = parse_strict_int(updates.get("review_threshold", current["review_threshold"]), "review_threshold", min_val=1, max_val=100)
    rej_th = parse_strict_int(updates.get("reject_threshold", current["reject_threshold"]), "reject_threshold", min_val=1, max_val=100)
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    _validate_rule_tree_budget(custom_rules)

    new_ver = int(current["policy_version"]) + 1
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
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
    finally:
        conn.close()

    bump_domain_epoch(db_path, caller.tenant_id, "policy")
    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata")
        if not isinstance(meta, dict):
            return None
        return meta.get(sub_key)
    return tx.get(field_path)


def _is_valid_number(val: Any) -> bool:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return False
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return False
    return True


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any], _depth: int = 1) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if _depth > MAX_RULE_TREE_DEPTH:
        raise ValueError("Rule tree depth limit exceeded")

    op = str(node.get("op") or "").upper()
    raw_bonus = node.get("bonus_score", 0)
    bonus = parse_strict_int(raw_bonus if raw_bonus is not None else 0, "bonus_score", min_val=-100, max_val=100)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")

        child_results = [eval_rule_node(ch, tx, _depth + 1) for ch in children]
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
        if isinstance(actual, bool) != isinstance(target, bool):
            matched = False
        else:
            matched = actual == target
    elif op == "NEQ":
        if isinstance(actual, bool) != isinstance(target, bool):
            matched = True
        else:
            matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        if not _is_valid_number(target):
            raise ValueError(f"Invalid numeric target in {op}")
        if _is_valid_number(actual):
            act_f = float(actual)
            tgt_f = float(target)
            if op == "GT":
                matched = act_f > tgt_f
            elif op == "GTE":
                matched = act_f >= tgt_f
            elif op == "LT":
                matched = act_f < tgt_f
            else:
                matched = act_f <= tgt_f
        else:
            matched = False
    elif op == "IN":
        if not isinstance(target, list):
            raise ValueError("IN operator target must be a list")
        matched = any((type(actual) is type(item) or (isinstance(actual, (int, float)) and not isinstance(actual, bool) and isinstance(item, (int, float)) and not isinstance(item, bool))) and actual == item for item in target)
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if not isinstance(target, str):
            raise ValueError("REGEX operator target must be a string")
        _validate_safe_regex_pattern(target)
        if isinstance(actual, str) and len(actual) <= 4096:
            matched = re.search(target, actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    if not isinstance(rule_tree, dict) or not rule_tree:
        raise ValueError("rule_tree must be a non-empty object")
    _validate_rule_tree_budget(rule_tree)
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
    if "amount_cents" in sample_tx and sample_tx["amount_cents"] is not None:
        parse_strict_int(sample_tx["amount_cents"], "amount_cents", min_val=0)
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
    """按输入顺序逐笔评估实时交易批次，并保证数据库、滑动窗口、三跳传染图与告警配额池的四位一体强原子提交/回滚。"""
    b_id = str(batch_id or "").strip()
    if not b_id or len(b_id) > 128 or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > MAX_BATCH_TX_COUNT:
        raise ValueError(f"Batch size exceeds maximum allowed ({MAX_BATCH_TX_COUNT})")

    # 第一阶段：零副作用前置校验全部交易字段、严格整数边界、批次内 tx_id 唯一性及邮箱格式
    validated_txs: list[dict[str, Any]] = []
    seen_batch_tx_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be an object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        if not tx_id or not account_id or not counterparty_id:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if len(tx_id) > 128 or len(account_id) > 128 or len(counterparty_id) > 128:
            raise ValueError("Transaction identifier exceeds maximum length")
        if tx_id in seen_batch_tx_ids:
            raise ValueError(f"Duplicate tx_id in batch: {tx_id}")
        seen_batch_tx_ids.add(tx_id)

        amount_cents = parse_strict_int(item.get("amount_cents"), "amount_cents", min_val=1)
        ts = parse_strict_int(item.get("ts"), "ts", min_val=1)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        raw_meta = item.get("metadata")
        if raw_meta is not None and not isinstance(raw_meta, dict):
            raise ValueError("metadata must be a JSON object")
        metadata = raw_meta if isinstance(raw_meta, dict) else {}

        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        validated_txs.append(
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

    policy = load_tenant_policy(db_path, caller.tenant_id)
    tx_engine = get_tenant_tx_engine(db_path, caller.tenant_id)
    q_lock = get_tenant_quota_lock(db_path, caller.tenant_id)

    # 第二阶段：按全局统一锁偏序（tx_engine.lock -> tenant_quota_lock -> BEGIN IMMEDIATE）执行评估与原子写入
    with tx_engine.lock:
        with q_lock:
            conn = open_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")

                # 预检数据库中是否已存在相同 tx_id 或 decision_id（避免半途主键冲突）
                placeholders = ",".join("?" for _ in validated_txs)
                tx_ids_tuple = tuple(t["tx_id"] for t in validated_txs)
                dup_row = conn.execute(
                    f"SELECT tx_id FROM transactions WHERE tx_id IN ({placeholders}) LIMIT 1",
                    tx_ids_tuple,
                ).fetchone()
                if dup_row:
                    conn.rollback()
                    raise ValueError(f"Transaction ID already exists: {dup_row['tx_id']}")

                q_row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, ALERT_QUOTA_BUCKET),
                ).fetchone()
                avail_alert_quota = int(q_row["remaining_quota"]) if q_row else 0
                consumed_alert_quota = 0
                last_reject_ts = 0

                results: list[dict[str, Any]] = []
                counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
                tx_insert_rows: list[tuple[Any, ...]] = []
                dec_insert_rows: list[tuple[Any, ...]] = []

                try:
                    for tx_obj in validated_txs:
                        tx_id = tx_obj["tx_id"]
                        account_id = tx_obj["account_id"]
                        counterparty_id = tx_obj["counterparty_id"]
                        amount_cents = tx_obj["amount_cents"]
                        currency = tx_obj["currency"]
                        channel = tx_obj["channel"]
                        contact_email = tx_obj["contact_email"]
                        ts = tx_obj["ts"]
                        metadata = tx_obj["metadata"]

                        sanction_hop = tx_engine.compute_hop_and_record_edge(
                            db_path,
                            account_id,
                            counterparty_id,
                            ts,
                        )

                        tracker = tx_engine.accounts.get(account_id)
                        if tracker is None:
                            tracker = AccountWindowTracker()
                            tx_engine.accounts[account_id] = tracker

                        win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                            tracker.evaluate_and_record(ts, amount_cents, counterparty_id)
                        )

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
                            if avail_alert_quota > 0:
                                avail_alert_quota -= 1
                                consumed_alert_quota += 1
                                last_reject_ts = ts
                                alert_dispatched = True
                                reasons.append("ALERT_QUOTA_CONSUMED")
                            else:
                                reasons.append("ALERT_POOL_DEPLETED")

                        decision_id = f"dec_{tx_id}"
                        tx_insert_rows.append(
                            (
                                tx_id,
                                caller.tenant_id,
                                b_id,
                                account_id,
                                counterparty_id,
                                amount_cents,
                                currency,
                                channel,
                                contact_email,
                                ts,
                                json.dumps(metadata, sort_keys=True),
                            )
                        )
                        dec_insert_rows.append(
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
                            )
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

                    if consumed_alert_quota > 0:
                        conn.execute(
                            "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                            "WHERE tenant_id = ? AND quota_type = ?",
                            (avail_alert_quota, last_reject_ts, caller.tenant_id, ALERT_QUOTA_BUCKET),
                        )

                    conn.executemany(
                        "INSERT INTO transactions("
                        "tx_id, tenant_id, batch_id, account_id, counterparty_id, amount_cents, "
                        "currency, channel, contact_email, ts, metadata_json"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        tx_insert_rows,
                    )
                    conn.executemany(
                        "INSERT INTO risk_decisions("
                        "decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                        "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
                        "sanction_hop, reasons_json, evaluated_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        dec_insert_rows,
                    )
                    conn.commit()
                except Exception:
                    if conn.in_transaction:
                        conn.rollback()
                    # 从已回滚的干净数据库状态重建内存滑窗与三跳传染图，确保四位一体零内存污染
                    tx_engine.build_from_db(db_path)
                    raise
            finally:
                conn.close()

    return {
        "tenant_id": caller.tenant_id,
        "batch_id": b_id,
        "evaluated_count": len(results),
        "decision_counts": counts,
        "results": results,
    }


def get_risk_decision_detail(
    db_path: str,
    caller: CallerContext,
    decision_id: str,
) -> dict[str, Any]:
    if not decision_id:
        raise ValueError("decision_id is required")
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE tenant_id = ? AND decision_id = ?",
            (caller.tenant_id, decision_id),
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
