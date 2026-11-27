# -*- coding: utf-8 -*-
"""实时交易风控评分、增量滑窗动态中位数、三跳制裁传染耦合与四位一体强原子批处理引擎。"""
from __future__ import annotations

from functools import lru_cache
import json
import re
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import (
    TenantContagionGraph,
    compute_hop_out_of_order,
    get_active_sanctions,
)
from .db import borrow_connection, write_transaction
from .legacy_compat import apply_sovereign_settlement_adjustment
from .runtime_state import (
    get_runtime,
    parse_strict_int,
    parse_strict_number,
    validate_safe_regex,
)
from .window_stats import AccountSlidingWindow, compute_exact_median_cents

# 线性时间无回溯邮箱正则（彻底消除原嵌套量词 ReDoS）
PARTNER_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)

_MAX_EMAIL_LEN = 254
_MAX_RULE_DEPTH = 16
_MAX_RULE_NODES = 128
_MAX_RULE_CHILDREN = 64
_MAX_REGEX_TARGET_TEXT_LEN = 512
_MAX_BATCH_SIZE = 1000


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > _MAX_EMAIL_LEN:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


@lru_cache(maxsize=256)
def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    validate_safe_regex(pattern)
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern: {exc}") from exc


def validate_rule_tree(node: dict[str, Any]) -> None:
    """在策略保存或规则试算前校验规则树深度、节点总数、操作符与正则安全性。"""
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if not node:
        return

    stack: list[tuple[dict[str, Any], int]] = [(node, 1)]
    count = 0
    while stack:
        curr, depth = stack.pop()
        if not isinstance(curr, dict):
            raise ValueError("Rule node must be an object")
        if depth > _MAX_RULE_DEPTH:
            raise ValueError("Rule tree depth exceeds limit")
        count += 1
        if count > _MAX_RULE_NODES:
            raise ValueError("Rule tree node count exceeds limit")

        op = str(curr.get("op") or "").upper()
        if "bonus_score" in curr and curr["bonus_score"] is not None:
            parse_strict_int(curr["bonus_score"], field_name="bonus_score", min_val=-1000, max_val=1000)

        if op in ("AND", "OR", "NOT"):
            children = curr.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if len(children) > _MAX_RULE_CHILDREN:
                raise ValueError("Rule node children exceed limit")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            for ch in children:
                stack.append((ch, depth + 1))
        elif op in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"):
            field_name = str(curr.get("field") or "")
            if not field_name:
                raise ValueError("Leaf rule node missing 'field'")
            val = curr.get("value")
            if op in ("GT", "GTE", "LT", "LTE"):
                parse_strict_number(val, field_name="rule.value")
            elif op == "REGEX":
                if not isinstance(val, str):
                    raise ValueError("REGEX value must be a string")
                _compile_safe_regex(val)
        else:
            raise ValueError(f"Unsupported rule operator: {op}")


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    tstate = get_runtime(db_path).get_tenant(tenant_id)
    cached = tstate.policy_cache
    if cached is not None and tstate.policy_cache_epoch == tstate.policy_epoch:
        return cached

    with tstate.meta_lock:
        if tstate.policy_cache is not None and tstate.policy_cache_epoch == tstate.policy_epoch:
            return tstate.policy_cache
        target_epoch = tstate.policy_epoch
        with borrow_connection(db_path) as conn:
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
        tstate.policy_cache = policy
        tstate.policy_cache_epoch = target_epoch
        return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)
    with tstate.meta_lock:
        current = load_tenant_policy(db_path, caller.tenant_id)
        high_amt = parse_strict_int(
            updates.get("high_amount_cents", current["high_amount_cents"]),
            field_name="high_amount_cents",
            min_val=1,
        )
        vel_tx = parse_strict_int(
            updates.get("velocity_tx_limit", current["velocity_tx_limit"]),
            field_name="velocity_tx_limit",
            min_val=1,
        )
        vel_amt = parse_strict_int(
            updates.get("velocity_amount_cents", current["velocity_amount_cents"]),
            field_name="velocity_amount_cents",
            min_val=0,
        )
        fanout = parse_strict_int(
            updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]),
            field_name="counterparty_fanout_limit",
            min_val=0,
        )
        rev_th = parse_strict_int(
            updates.get("review_threshold", current["review_threshold"]),
            field_name="review_threshold",
            min_val=1,
            max_val=100,
        )
        rej_th = parse_strict_int(
            updates.get("reject_threshold", current["reject_threshold"]),
            field_name="reject_threshold",
            min_val=1,
            max_val=100,
        )
        custom_rules = updates.get("custom_rules", current["custom_rules"])

        if rej_th < rev_th:
            raise ValueError("Invalid policy threshold values")
        if not isinstance(custom_rules, dict):
            raise ValueError("custom_rules must be a JSON object")
        validate_rule_tree(custom_rules)

        new_ver = int(current["policy_version"]) + 1
        now_ts = int(caller.request_ts or int(time.time()))
        with write_transaction(db_path) as conn:
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
        tstate.policy_epoch += 1
        tstate.policy_cache = None

    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def _eval_rule_node_bounded(
    node: dict[str, Any],
    tx: dict[str, Any],
    *,
    depth: int,
    budget: list[int],
) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if depth > _MAX_RULE_DEPTH:
        raise ValueError("Rule tree depth exceeds limit")
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("Rule tree node count exceeds limit")

    op = str(node.get("op") or "").upper()
    raw_bonus = node.get("bonus_score")
    bonus = 0 if raw_bonus is None else parse_strict_int(raw_bonus, field_name="bonus_score", min_val=-1000, max_val=1000)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if len(children) > _MAX_RULE_CHILDREN:
            raise ValueError("Rule node children exceed limit")

        child_results = [
            _eval_rule_node_bounded(ch, tx, depth=depth + 1, budget=budget)
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
        t_num = parse_strict_number(target, field_name="rule.value")
        if actual is not None:
            a_num = parse_strict_number(actual, field_name=field_name)
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
        if not isinstance(target, str):
            raise ValueError("REGEX value must be a string")
        compiled = _compile_safe_regex(target)
        if isinstance(actual, str):
            if len(actual) > _MAX_REGEX_TARGET_TEXT_LEN:
                raise ValueError("REGEX target text exceeds maximum length")
            matched = compiled.search(actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    return _eval_rule_node_bounded(node, tx, depth=1, budget=[_MAX_RULE_NODES])


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
    validate_rule_tree(rule_tree)
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


def _ensure_tenant_risk_state_loaded(
    conn: sqlite3.Connection,
    tstate: Any,
    tenant_id: str,
) -> tuple[dict[str, AccountSlidingWindow], TenantContagionGraph]:
    """在持有 risk_lock 与数据库事务下，懒加载单租户的历史活跃滑窗与三跳传染图。"""
    if tstate.risk_loaded and tstate.risk_windows is not None and tstate.contagion_graph is not None:
        return tstate.risk_windows, tstate.contagion_graph

    windows: dict[str, AccountSlidingWindow] = {}
    graph = TenantContagionGraph()
    rows = conn.execute(
        "SELECT account_id, counterparty_id, amount_cents, ts "
        "FROM transactions WHERE tenant_id = ? ORDER BY ts ASC",
        (tenant_id,),
    ).fetchall()
    for r in rows:
        acct = str(r["account_id"])
        cp = str(r["counterparty_id"])
        amt = int(r["amount_cents"])
        r_ts = int(r["ts"])
        win = windows.get(acct)
        if win is None:
            win = AccountSlidingWindow()
            windows[acct] = win
        win.add_monotonic(r_ts, amt, cp)
        graph.add_edge_monotonic(r_ts, acct, cp)

    tstate.risk_windows = windows
    tstate.contagion_graph = graph
    tstate.risk_loaded = True
    return windows, graph


def _compute_window_out_of_order(
    conn: sqlite3.Connection,
    tenant_id: str,
    account_id: str,
    ts: int,
    amount_cents: int,
    counterparty_id: str,
    staged_for_acct: list[tuple[int, int, str]],
) -> tuple[int, int, int, int]:
    """乱序时间戳精确窗口回退：使用 (tenant_id, account_id, ts) 复合索引 + 批次已暂存交易精确计算。"""
    win_start = ts - SLIDING_WINDOW_SECONDS
    rows = conn.execute(
        "SELECT counterparty_id, amount_cents FROM transactions "
        "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ?",
        (tenant_id, account_id, win_start, ts),
    ).fetchall()
    amounts: list[int] = [amount_cents]
    total_amt = amount_cents
    cps: set[str] = {counterparty_id}
    for r in rows:
        amt = int(r["amount_cents"])
        amounts.append(amt)
        total_amt += amt
        cps.add(str(r["counterparty_id"]))
    for s_ts, s_amt, s_cp in staged_for_acct:
        if win_start <= s_ts <= ts:
            amounts.append(s_amt)
            total_amt += s_amt
            cps.add(s_cp)
    return len(amounts), total_amt, len(cps), compute_exact_median_cents(amounts)


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次（严格 L1 risk_lock -> L2 REALTIME_ALERT_POOL -> L3 BEGIN IMMEDIATE，四位一体强原子提交/回滚）。"""
    bid = str(batch_id or "").strip()
    if not bid or len(bid) > 128 or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > _MAX_BATCH_SIZE:
        raise ValueError(f"Batch size exceeds limit ({_MAX_BATCH_SIZE})")

    # 阶段 1：无锁前置全量合法性校验（任何一笔非法直接拦截，零数据库/内存/配额污染）
    parsed_items: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction must be a JSON object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        amount_cents = parse_strict_int(item.get("amount_cents"), field_name="amount_cents", min_val=1)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        ts = parse_strict_int(item.get("ts"), field_name="ts", min_val=1)
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if not tx_id or not account_id or not counterparty_id:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if tx_id in seen_tx_ids:
            raise ValueError(f"Duplicate tx_id in batch: {tx_id}")
        seen_tx_ids.add(tx_id)
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        parsed_items.append(
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
    sanctioned = get_active_sanctions(db_path, caller.tenant_id)
    tstate = get_runtime(db_path).get_tenant(caller.tenant_id)

    # 阶段 2：严格遵守全局锁偏序 L1(risk_lock) -> L2(quota_lock[REALTIME_ALERT_POOL]) -> L3(BEGIN IMMEDIATE)
    with tstate.risk_lock:
        with tstate.acquire_quota_locks(ALERT_QUOTA_BUCKET):
            try:
                with write_transaction(db_path) as conn:
                    windows, graph = _ensure_tenant_risk_state_loaded(conn, tstate, caller.tenant_id)

                    q_row = conn.execute(
                        "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                        (caller.tenant_id, ALERT_QUOTA_BUCKET),
                    ).fetchone()
                    alert_rem = int(q_row["remaining_quota"]) if q_row else 0
                    alert_consumed = 0
                    last_alert_ts = 0

                    results: list[dict[str, Any]] = []
                    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
                    tx_insert_rows: list[tuple[Any, ...]] = []
                    dec_insert_rows: list[tuple[Any, ...]] = []

                    staged_edges: list[tuple[int, str, str]] = []
                    staged_by_acct: dict[str, list[tuple[int, int, str]]] = {}

                    for tx_obj in parsed_items:
                        tx_id = tx_obj["tx_id"]
                        account_id = tx_obj["account_id"]
                        counterparty_id = tx_obj["counterparty_id"]
                        amount_cents = tx_obj["amount_cents"]
                        ts = tx_obj["ts"]

                        # 三跳受制裁实体传染计算（单调快路径 / 乱序精确回退）
                        if ts >= graph.max_ts:
                            sanction_hop = graph.compute_hop_monotonic(
                                sanctioned, account_id, counterparty_id, ts
                            )
                            graph.add_edge_monotonic(ts, account_id, counterparty_id)
                        else:
                            sanction_hop = compute_hop_out_of_order(
                                conn,
                                caller.tenant_id,
                                sanctioned,
                                account_id,
                                counterparty_id,
                                ts,
                                staged_edges,
                            )
                            graph.insert_edge_out_of_order(ts, account_id, counterparty_id)
                        staged_edges.append((ts, account_id, counterparty_id))

                        # 四维滑动窗口动态中位数（单调 O(log W) 快路径 / 乱序精确回退）
                        win = windows.get(account_id)
                        if win is None:
                            win = AccountSlidingWindow()
                            windows[account_id] = win

                        if ts >= win.max_ts:
                            win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                                win.add_monotonic(ts, amount_cents, counterparty_id)
                            )
                        else:
                            win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                                _compute_window_out_of_order(
                                    conn,
                                    caller.tenant_id,
                                    account_id,
                                    ts,
                                    amount_cents,
                                    counterparty_id,
                                    staged_by_acct.get(account_id, []),
                                )
                            )
                            win.insert_out_of_order(ts, amount_cents, counterparty_id)
                        staged_by_acct.setdefault(account_id, []).append((ts, amount_cents, counterparty_id))

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
                            if alert_rem >= 1:
                                alert_rem -= 1
                                alert_consumed += 1
                                last_alert_ts = ts
                                alert_dispatched = True
                                reasons.append("ALERT_QUOTA_CONSUMED")
                            else:
                                reasons.append("ALERT_POOL_DEPLETED")

                        decision_id = f"dec_{tx_id}"
                        tx_insert_rows.append(
                            (
                                tx_id,
                                caller.tenant_id,
                                bid,
                                account_id,
                                counterparty_id,
                                amount_cents,
                                tx_obj["currency"],
                                tx_obj["channel"],
                                tx_obj["contact_email"],
                                ts,
                                json.dumps(tx_obj["metadata"], sort_keys=True),
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
                    if alert_consumed > 0:
                        cur = conn.execute(
                            "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                            "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                            (alert_consumed, last_alert_ts, caller.tenant_id, ALERT_QUOTA_BUCKET, alert_consumed),
                        )
                        if cur.rowcount != 1:
                            raise RuntimeError("Alert quota state inconsistency during batch commit")

                return {
                    "tenant_id": caller.tenant_id,
                    "batch_id": bid,
                    "evaluated_count": len(results),
                    "decision_counts": counts,
                    "results": results,
                }
            except sqlite3.IntegrityError as exc:
                # 四位一体强原子回滚：SQLite 已自动 ROLLBACK（含事务表与告警配额），同时清空内存滑窗与传染图
                tstate.invalidate_risk_state()
                raise ValueError(f"Transaction batch integrity conflict: {exc}") from exc
            except Exception:
                tstate.invalidate_risk_state()
                raise


def get_risk_decision_detail(
    db_path: str,
    caller: CallerContext,
    decision_id: str,
) -> dict[str, Any]:
    """按租户隔离查询单笔风控决策详情（严防跨租户 IDOR）。"""
    with borrow_connection(db_path) as conn:
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
