# -*- coding: utf-8 -*-
"""高性能风控引擎：零回溯邮箱校验、全变体正则/规则预算熔断、O(log W) 滑窗中位数、3跳传染与单事务强原子提交。"""
from __future__ import annotations

import functools
import json
import math
import re
import sqlite3
import threading
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    MAX_BATCH_TXS,
    MAX_REGEX_PATTERN_LEN,
    MAX_REGEX_QUANTIFIER,
    MAX_RULE_DEPTH,
    MAX_RULE_NODES,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import eval_3hop_from_window_adj, get_active_sanctioned_entities
from .db import (
    acquire_ordered_striped_locks,
    bump_tenant_epoch,
    get_striped_lock,
    get_tenant_epochs,
    get_thread_connection,
    normalize_db_key,
    register_cache_reset_hook,
    require_strict_int,
)
from .legacy_compat import apply_sovereign_settlement_adjustment
from .window_stats import SlidingAccountWindow

# 拦截嵌套重复量词、重叠分支重复、反向引用、前瞻/后顾断言、多段通配符链与超大花括号重复上界
_UNSAFE_NESTED_QUANT = re.compile(r"(\+|\*|\{[0-9,]+\})\s*\)\s*(\+|\*|\?|\{[0-9,]+\})|\(\?[<=!P]|\\[1-9]")
_UNSAFE_ALT_REPEAT = re.compile(r"\([^)]*\|[^)]*\)\s*(\+|\*|\{[0-9,]+\})")
_WILDCARD_CHAIN = re.compile(r"(?:\.|\[[^\]]+\]|\(\\w\)|\\w|\\S)[\*\+]")
_BRACE_QUANT_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")

_POLICY_CACHE_LOCK = threading.Lock()
_POLICY_CACHE: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}


def _clear_policy_cache(db_key: str) -> None:
    with _POLICY_CACHE_LOCK:
        for k in [k for k in _POLICY_CACHE if k[0] == db_key]:
            _POLICY_CACHE.pop(k, None)


register_cache_reset_hook(_clear_policy_cache)


class BatchConflictError(ValueError):
    """交易批次内部或与已落盘记录发生主键冲突。"""


def _is_alnum_ascii(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9")


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    n = len(email)
    if n < 5 or n > 254:
        return False
    at_idx = email.find("@")
    if at_idx <= 0 or at_idx != email.rfind("@") or at_idx > 64:
        return False

    local = email[:at_idx]
    domain = email[at_idx + 1:]
    if not local or len(domain) < 3 or "." not in domain:
        return False

    for seg in re.split(r"[._-]", local):
        if not seg or not all(_is_alnum_ascii(c) for c in seg):
            return False

    dom_parts = domain.split(".")
    if len(dom_parts) < 2:
        return False
    for label in dom_parts:
        if not label or len(label) > 63:
            return False
        if not all(_is_alnum_ascii(c) or c == "-" for c in label):
            return False
    return True


@functools.lru_cache(maxsize=256)
def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        raise ValueError(f"Regex pattern exceeds maximum length {MAX_REGEX_PATTERN_LEN}")
    if _UNSAFE_NESTED_QUANT.search(pattern) or _UNSAFE_ALT_REPEAT.search(pattern):
        raise ValueError("Unsafe backtracking regex construct rejected")
    if len(_WILDCARD_CHAIN.findall(pattern)) > 1:
        raise ValueError("Multiple unbounded wildcard chains rejected")
    for m in _BRACE_QUANT_RE.finditer(pattern):
        low_b = int(m.group(1))
        high_s = m.group(2)
        if high_s == "":
            raise ValueError("Unbounded brace quantifier rejected")
        high_b = int(high_s) if high_s is not None else low_b
        if low_b > MAX_REGEX_QUANTIFIER or high_b > MAX_REGEX_QUANTIFIER or high_b < low_b:
            raise ValueError(f"Brace quantifier exceeds safe limit {MAX_REGEX_QUANTIFIER}")
    if pattern.count("(") > 3 or (pattern.count("+") + pattern.count("*") + pattern.count("{")) > 3:
        raise ValueError("Regex complexity budget exceeded")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex syntax: {exc}") from exc


def _to_finite_number(val: Any, label: str) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"{label} must be a finite number")
    fval = float(val)
    if not math.isfinite(fval):
        raise ValueError(f"{label} cannot be NaN or Infinity")
    return fval


def validate_rule_tree_budget(root: dict[str, Any]) -> None:
    if not isinstance(root, dict):
        raise ValueError("Rule tree root must be an object")
    if not root:
        return

    node_count = 0
    stack: list[tuple[Any, int]] = [(root, 1)]

    while stack:
        curr, depth = stack.pop()
        if not isinstance(curr, dict):
            raise ValueError("Rule node must be an object")
        if depth > MAX_RULE_DEPTH:
            raise ValueError(f"Rule tree exceeds maximum depth {MAX_RULE_DEPTH}")
        node_count += 1
        if node_count > MAX_RULE_NODES:
            raise ValueError(f"Rule tree exceeds maximum node budget {MAX_RULE_NODES}")

        raw_bonus = curr.get("bonus_score", 0)
        if raw_bonus is not None:
            require_strict_int(raw_bonus, "bonus_score", min_val=-100, max_val=100)

        op = str(curr.get("op") or "").upper()
        if op in ("AND", "OR", "NOT"):
            children = curr.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            if len(children) > 24:
                raise ValueError("Rule node fanout exceeds limit")
            for ch in children:
                stack.append((ch, depth + 1))
        elif op == "REGEX":
            pat = curr.get("value")
            if not isinstance(pat, str):
                raise ValueError("REGEX operator value must be a string")
            _compile_safe_regex(pat)
        elif op in ("GT", "GTE", "LT", "LTE"):
            _to_finite_number(curr.get("value"), "rule threshold value")
        elif op in ("EQ", "NEQ", "IN", "CONTAINS"):
            if op == "IN":
                val = curr.get("value")
                if not isinstance(val, list) or len(val) > 64:
                    raise ValueError("IN operator requires a bounded list (<=64)")
            elif op == "CONTAINS":
                val = curr.get("value")
                if not isinstance(val, str) or len(val) > 256:
                    raise ValueError("CONTAINS value must be a bounded string")
        else:
            raise ValueError(f"Unsupported rule operator: {op}")


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    db_key = normalize_db_key(db_path)
    eps = get_tenant_epochs(db_path, tenant_id)
    tk = (db_key, tenant_id)
    with _POLICY_CACHE_LOCK:
        cached = _POLICY_CACHE.get(tk)
        if cached is not None and cached[0] == eps.policy:
            return cached[1]

    conn = get_thread_connection(db_path)
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
    with _POLICY_CACHE_LOCK:
        live_eps = get_tenant_epochs(db_path, tenant_id)
        if live_eps.policy == eps.policy:
            _POLICY_CACHE[tk] = (eps.policy, policy)
    return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = require_strict_int(updates.get("high_amount_cents", current["high_amount_cents"]), "high_amount_cents", min_val=1)
    vel_tx = require_strict_int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]), "velocity_tx_limit", min_val=1, max_val=100000)
    vel_amt = require_strict_int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]), "velocity_amount_cents", min_val=1)
    fanout = require_strict_int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]), "counterparty_fanout_limit", min_val=1, max_val=100000)
    rev_th = require_strict_int(updates.get("review_threshold", current["review_threshold"]), "review_threshold", min_val=1, max_val=100)
    rej_th = require_strict_int(updates.get("reject_threshold", current["reject_threshold"]), "reject_threshold", min_val=rev_th, max_val=100)
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    if custom_rules:
        validate_rule_tree_budget(custom_rules)

    now_ts = int(caller.request_ts or int(time.time()))
    lock = get_striped_lock(db_path, caller.tenant_id, "policy")
    with lock:
        conn = get_thread_connection(db_path)
        ver_row = conn.execute(
            "SELECT policy_version FROM tenant_policies WHERE tenant_id = ?",
            (caller.tenant_id,),
        ).fetchone()
        new_ver = int(ver_row["policy_version"]) + 1 if ver_row else int(current["policy_version"]) + 1
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
        bump_tenant_epoch(db_path, caller.tenant_id, "policy")

    return dict(load_tenant_policy(db_path, caller.tenant_id))


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key) if isinstance(meta, dict) else None
    return tx.get(field_path)


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any], _depth: int = 1) -> tuple[bool, int, list[str]]:
    if _depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree exceeds maximum depth {MAX_RULE_DEPTH}")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    bonus = int(node.get("bonus_score") or 0)
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
        matched = (
            (
                type(actual) is type(target)
                or (
                    isinstance(actual, (int, float))
                    and isinstance(target, (int, float))
                    and not isinstance(actual, bool)
                    and not isinstance(target, bool)
                )
            )
            and (actual == target)
        )
    elif op == "NEQ":
        matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        ft = _to_finite_number(target, "target")
        if actual is not None:
            fa = _to_finite_number(actual, field_name)
            if op == "GT":
                matched = fa > ft
            elif op == "GTE":
                matched = fa >= ft
            elif op == "LT":
                matched = fa < ft
            else:
                matched = fa <= ft
    elif op == "IN":
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and len(actual) <= 1024 and (target in actual)
    elif op == "REGEX":
        if not isinstance(target, str):
            raise ValueError("REGEX target must be a string")
        compiled = _compile_safe_regex(target)
        if isinstance(actual, str):
            if len(actual) > 256:
                raise ValueError("REGEX input text exceeds maximum safe length")
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
    validate_rule_tree_budget(rule_tree)
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
    if not isinstance(batch_id, str) or not batch_id.strip() or len(batch_id) > 128:
        raise ValueError("Valid batch_id is required")
    if not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("Non-empty transactions list is required")
    if len(transactions) > MAX_BATCH_TXS:
        raise ValueError(f"Batch size exceeds limit {MAX_BATCH_TXS}")

    parsed_items: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()
    min_ts: int | None = None
    max_ts: int | None = None
    account_set: set[str] = set()

    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be an object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        amount_cents = require_strict_int(item.get("amount_cents"), "amount_cents", min_val=1)
        ts = require_strict_int(item.get("ts"), "ts", min_val=1, max_val=9_999_999_999)

        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        metadata = item.get("metadata") if item.get("metadata") is not None else {}
        if not isinstance(metadata, dict):
            raise ValueError("Transaction metadata must be an object")

        if (
            not tx_id
            or len(tx_id) > 128
            or not account_id
            or len(account_id) > 128
            or not counterparty_id
            or len(counterparty_id) > 128
            or len(currency) > 16
            or len(channel) > 32
        ):
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if tx_id in seen_tx_ids:
            raise BatchConflictError(f"Duplicate tx_id within batch: {tx_id}")
        seen_tx_ids.add(tx_id)

        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        account_set.add(account_id)
        min_ts = ts if min_ts is None else min(min_ts, ts)
        max_ts = ts if max_ts is None else max(max_ts, ts)
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
    sanctioned_set = get_active_sanctioned_entities(db_path, caller.tenant_id)
    earliest_win = int(min_ts) - SLIDING_WINDOW_SECONDS
    latest_ts = int(max_ts)
    acct_list = sorted(account_set)
    tx_id_list = [t["tx_id"] for t in parsed_items]

    # 全局统一偏序加锁（按分片号升序一次性锁住 risk_eval 与 REALTIME_ALERT_POOL，再进 BEGIN IMMEDIATE），根除与跨池调拨交叉竞争死锁
    with acquire_ordered_striped_locks(db_path, caller.tenant_id, "risk_eval", f"quota:{ALERT_QUOTA_BUCKET}"):
        conn = get_thread_connection(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            for i0 in range(0, len(tx_id_list), 400):
                sub_ids = tx_id_list[i0: i0 + 400]
                ph = ",".join("?" for _ in sub_ids)
                dup_row = conn.execute(
                    f"SELECT tx_id FROM transactions WHERE tx_id IN ({ph}) LIMIT 1",
                    tuple(sub_ids),
                ).fetchone()
                if dup_row:
                    conn.rollback()
                    raise BatchConflictError(f"Transaction already exists: {dup_row['tx_id']}")

            q_row = conn.execute(
                "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                (caller.tenant_id, ALERT_QUOTA_BUCKET),
            ).fetchone()
            initial_alert_quota = int(q_row["remaining_quota"]) if q_row else 0
            avail_alert_quota = initial_alert_quota
            last_alert_ts = latest_ts

            acct_init_rows: dict[str, list[tuple[int, int, str]]] = {a: [] for a in acct_list}
            for start_i in range(0, len(acct_list), 400):
                sub_accts = acct_list[start_i: start_i + 400]
                placeholders = ",".join("?" for _ in sub_accts)
                rows = conn.execute(
                    f"SELECT account_id, ts, amount_cents, counterparty_id FROM transactions "
                    f"WHERE tenant_id = ? AND account_id IN ({placeholders}) AND ts >= ? AND ts <= ?",
                    (caller.tenant_id, *sub_accts, earliest_win, latest_ts),
                ).fetchall()
                for r in rows:
                    acct_init_rows[str(r[0])].append((int(r[1]), int(r[2]), str(r[3])))

            acct_windows = {
                acct: SlidingAccountWindow(init_list)
                for acct, init_list in acct_init_rows.items()
            }

            adj_by_node: dict[str, list[tuple[int, str]]] = {}
            if sanctioned_set:
                edge_rows = conn.execute(
                    "SELECT ts, account_id, counterparty_id FROM transactions "
                    "WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
                    (caller.tenant_id, earliest_win, latest_ts),
                ).fetchall()
                for er in edge_rows:
                    e_ts = int(er[0])
                    u = str(er[1])
                    v = str(er[2])
                    adj_by_node.setdefault(u, []).append((e_ts, v))
                    adj_by_node.setdefault(v, []).append((e_ts, u))

            results: list[dict[str, Any]] = []
            counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
            tx_insert_rows = []
            dec_insert_rows = []

            for tx_obj in parsed_items:
                tx_id = tx_obj["tx_id"]
                acct_id = tx_obj["account_id"]
                cp_id = tx_obj["counterparty_id"]
                amt = tx_obj["amount_cents"]
                ts = tx_obj["ts"]
                win_start = ts - SLIDING_WINDOW_SECONDS

                if sanctioned_set:
                    sanction_hop = eval_3hop_from_window_adj(
                        sanctioned_set,
                        adj_by_node,
                        acct_id,
                        cp_id,
                        win_start,
                        ts,
                    )
                    adj_by_node.setdefault(acct_id, []).append((ts, cp_id))
                    adj_by_node.setdefault(cp_id, []).append((ts, acct_id))
                else:
                    sanction_hop = 0

                win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                    acct_windows[acct_id].eval_and_record(
                        ts=ts,
                        amount_cents=amt,
                        counterparty_id=cp_id,
                        window_seconds=SLIDING_WINDOW_SECONDS,
                    )
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
                    if avail_alert_quota >= 1:
                        avail_alert_quota -= 1
                        alert_dispatched = True
                        last_alert_ts = ts
                        reasons.append("ALERT_QUOTA_CONSUMED")
                    else:
                        reasons.append("ALERT_POOL_DEPLETED")

                decision_id = f"dec_{tx_id}"
                tx_insert_rows.append(
                    (
                        tx_id,
                        caller.tenant_id,
                        batch_id,
                        acct_id,
                        cp_id,
                        amt,
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
                        acct_id,
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
                        "account_id": acct_id,
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

            if avail_alert_quota != initial_alert_quota and q_row is not None:
                conn.execute(
                    "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                    "WHERE tenant_id = ? AND quota_type = ?",
                    (avail_alert_quota, last_alert_ts, caller.tenant_id, ALERT_QUOTA_BUCKET),
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
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction:
                conn.rollback()
            raise BatchConflictError("Transaction primary key conflict") from exc
        except Exception:
            if conn.in_transaction:
                conn.rollback()
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
    if not decision_id or len(decision_id) > 128:
        raise ValueError("Invalid decision_id")
    conn = get_thread_connection(db_path)
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
