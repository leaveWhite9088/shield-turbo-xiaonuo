# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数、四位一体强原子事务与抗复杂度炸弹规则树引擎。"""
from __future__ import annotations

import copy
import json
import math
import re
import time
from typing import Any, Callable

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    INT64_MAX,
    MAX_BATCH_TX_COUNT,
    MAX_REGEX_LENGTH,
    MAX_REGEX_QUANTIFIER,
    MAX_RULE_TREE_DEPTH,
    MAX_RULE_TREE_NODES,
    SANCTION_HOP_SCORES,
)
from .contagion_graph import get_or_load_contagion_graph
from .db import (
    acquire_quota_locks,
    bump_policy_epoch,
    get_tenant_epochs,
    get_tenant_risk_lock,
    normalize_db_key,
    open_connection,
    register_reset_callback,
)
from .legacy_compat import apply_sovereign_settlement_adjustment
from .middleware import strict_int
from .window_stats import get_or_load_tenant_window_state

# 消除嵌套量词回溯的线性时间 DFA 等价邮箱校验正则
PARTNER_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)

_BACKREF_RE = re.compile(r"\\[1-9]|\\g<|\(\?P=")
_BRACE_QUANT_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")
_ALLOWED_RULE_OPS = frozenset(
    {"AND", "OR", "NOT", "EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"}
)


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > 254:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def validate_safe_regex_pattern(pattern: Any) -> re.Pattern[str]:
    """拦截嵌套量词、分支重叠量词、超大花括号重复上界与反向引用等 ReDoS 正则炸弹。"""
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError("Regex pattern must be a non-empty string within length budget")
    if _BACKREF_RE.search(pattern):
        raise ValueError("Regex backreferences are not permitted")

    for m in _BRACE_QUANT_RE.finditer(pattern):
        low_s, high_s = m.group(1), m.group(2)
        low_v = int(low_s)
        if low_v > MAX_REGEX_QUANTIFIER:
            raise ValueError(f"Regex quantifier lower bound exceeds {MAX_REGEX_QUANTIFIER}")
        if high_s is not None:
            if high_s == "":
                if low_v > 8:
                    raise ValueError("Unbounded brace quantifier with large minimum is not permitted")
            else:
                high_v = int(high_s)
                if high_v > MAX_REGEX_QUANTIFIER or high_v < low_v:
                    raise ValueError(f"Regex quantifier upper bound exceeds {MAX_REGEX_QUANTIFIER}")

    # 扫描括号分组栈，拒绝含内部量词或内部或分支 '|' 的分组再次被外部量词修饰
    group_stack: list[list[bool]] = []  # [has_inner_quantifier, has_alternation]
    last_closed_group: list[bool] | None = None
    prev_was_quantifier = False
    in_char_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            last_closed_group = None
            prev_was_quantifier = False
            continue
        if in_char_class:
            if ch == "]":
                in_char_class = False
            i += 1
            continue
        if ch == "[":
            in_char_class = True
            last_closed_group = None
            prev_was_quantifier = False
            i += 1
            continue
        if ch == "(":
            if pattern[i : i + 4] in ("(?<=", "(?<!"):
                raise ValueError("Lookbehind assertions in custom regex are not permitted")
            group_stack.append([False, False])
            last_closed_group = None
            prev_was_quantifier = False
            i += 1
            continue
        if ch == ")":
            if not group_stack:
                raise ValueError("Unbalanced parenthesis in regex pattern")
            last_closed_group = group_stack.pop()
            prev_was_quantifier = False
            i += 1
            continue
        if ch == "|":
            if group_stack:
                group_stack[-1][1] = True
            last_closed_group = None
            prev_was_quantifier = False
            i += 1
            continue
        if ch in ("*", "+", "?") or (ch == "{" and _BRACE_QUANT_RE.match(pattern, i)):
            if prev_was_quantifier and ch not in ("?",):
                raise ValueError("Chained quantifiers are not permitted")
            if last_closed_group is not None:
                if last_closed_group[0] or last_closed_group[1]:
                    raise ValueError("Nested quantifier or quantified alternation group is not permitted")
            for g in group_stack:
                g[0] = True
            prev_was_quantifier = True
            last_closed_group = None
            if ch == "{":
                m_brace = _BRACE_QUANT_RE.match(pattern, i)
                i = m_brace.end() if m_brace else i + 1
            else:
                i += 1
            continue

        last_closed_group = None
        prev_was_quantifier = False
        i += 1

    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex syntax: {exc}") from exc


def validate_rule_tree(
    node: Any,
    *,
    max_depth: int = MAX_RULE_TREE_DEPTH,
    max_nodes: int = MAX_RULE_TREE_NODES,
) -> None:
    """校验自定义布尔规则树的深度、总节点数、扇出、严格数值类型与正则安全性。"""
    if not isinstance(node, dict) or not node:
        raise ValueError("Rule tree must be a non-empty JSON object")

    counter = [0]

    def _walk(curr: Any, depth: int, path_ids: set[int]) -> None:
        if not isinstance(curr, dict):
            raise ValueError("Rule node must be an object")
        if depth > max_depth:
            raise ValueError(f"Rule tree depth exceeds maximum limit ({max_depth})")
        obj_id = id(curr)
        if obj_id in path_ids:
            raise ValueError("Cyclic reference detected in rule tree")
        counter[0] += 1
        if counter[0] > max_nodes:
            raise ValueError(f"Rule tree total node count exceeds maximum limit ({max_nodes})")

        op = str(curr.get("op") or "").strip().upper()
        if op not in _ALLOWED_RULE_OPS:
            raise ValueError(f"Unsupported rule operator: {op}")

        if "bonus_score" in curr and curr["bonus_score"] is not None:
            strict_int(curr["bonus_score"], "bonus_score", min_val=-1000, max_val=1000)
        reason = curr.get("reason")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 128):
            raise ValueError("Invalid rule reason field")

        if op in ("AND", "OR", "NOT"):
            children = curr.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if len(children) > 32:
                raise ValueError("Logical rule node children fanout exceeds limit (32)")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            next_path = path_ids | {obj_id}
            for ch in children:
                _walk(ch, depth + 1, next_path)
            return

        field_name = curr.get("field")
        if not isinstance(field_name, str) or not field_name.strip() or len(field_name) > 64:
            raise ValueError("Leaf rule node requires a valid 'field' string")
        target = curr.get("value")
        if op in ("GT", "GTE", "LT", "LTE"):
            if isinstance(target, bool) or not isinstance(target, (int, float)) or not math.isfinite(float(target)):
                raise ValueError(f"Operator {op} requires a finite numeric target value")
            if isinstance(target, int) and (target < -INT64_MAX or target > INT64_MAX):
                raise ValueError(f"Operator {op} integer target exceeds 64-bit bounds")
        elif op == "IN":
            if not isinstance(target, list) or len(target) > 64:
                raise ValueError("IN operator requires a list of at most 64 items")
        elif op == "CONTAINS":
            if not isinstance(target, str) or len(target) > 256:
                raise ValueError("CONTAINS operator requires a string target value")
        elif op == "REGEX":
            validate_safe_regex_pattern(target)

    _walk(node, 1, set())


_MAX_POLICY_CACHE = 128
_POLICY_CACHE: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}


def _reset_policy_cache(db_key: str) -> None:
    for k in [k for k in _POLICY_CACHE if k[0] == db_key]:
        _POLICY_CACHE.pop(k, None)


register_reset_callback(_reset_policy_cache)


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    db_key = normalize_db_key(db_path)
    cur_ep = get_tenant_epochs(db_path, tenant_id).policy_epoch
    cache_key = (db_key, tenant_id)
    cached = _POLICY_CACHE.get(cache_key)
    if cached is not None and cached[0] == cur_ep:
        return copy.deepcopy(cached[1])

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
    finally:
        conn.close()

    if len(_POLICY_CACHE) >= _MAX_POLICY_CACHE and cache_key not in _POLICY_CACHE:
        _POLICY_CACHE.pop(next(iter(_POLICY_CACHE)), None)
    _POLICY_CACHE[cache_key] = (cur_ep, copy.deepcopy(policy))
    return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy updates must be a JSON object")

    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = strict_int(
        updates.get("high_amount_cents", current["high_amount_cents"]),
        "high_amount_cents",
        min_val=1,
        max_val=INT64_MAX // 4,
    )
    vel_tx = strict_int(
        updates.get("velocity_tx_limit", current["velocity_tx_limit"]),
        "velocity_tx_limit",
        min_val=1,
        max_val=1000000,
    )
    vel_amt = strict_int(
        updates.get("velocity_amount_cents", current["velocity_amount_cents"]),
        "velocity_amount_cents",
        min_val=1,
        max_val=INT64_MAX // 4,
    )
    fanout = strict_int(
        updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]),
        "counterparty_fanout_limit",
        min_val=1,
        max_val=1000000,
    )
    rev_th = strict_int(
        updates.get("review_threshold", current["review_threshold"]),
        "review_threshold",
        min_val=1,
        max_val=100,
    )
    rej_th = strict_int(
        updates.get("reject_threshold", current["reject_threshold"]),
        "reject_threshold",
        min_val=1,
        max_val=100,
    )
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or vel_amt <= 0 or fanout <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    if custom_rules:
        validate_rule_tree(custom_rules)

    with get_tenant_risk_lock(db_path, caller.tenant_id):
        current = load_tenant_policy(db_path, caller.tenant_id)
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
        bump_policy_epoch(db_path, caller.tenant_id)
        return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata")
        return meta.get(sub_key) if isinstance(meta, dict) else None
    return tx.get(field_path)


def _is_valid_number(val: Any) -> bool:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return False
    if isinstance(val, float) and not math.isfinite(val):
        return False
    if isinstance(val, int) and (val < -INT64_MAX or val > INT64_MAX):
        return False
    return True


def eval_rule_node(
    node: dict[str, Any],
    tx: dict[str, Any],
    _depth: int = 1,
    _counter: list[int] | None = None,
) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if _depth > MAX_RULE_TREE_DEPTH:
        raise ValueError("Rule tree evaluation depth exceeded")
    cnt = _counter if _counter is not None else [0]
    cnt[0] += 1
    if cnt[0] > MAX_RULE_TREE_NODES:
        raise ValueError("Rule tree evaluation node count exceeded")

    op = str(node.get("op") or "").strip().upper()
    bonus = (
        strict_int(node.get("bonus_score"), "bonus_score", min_val=-1000, max_val=1000)
        if node.get("bonus_score") is not None
        else 0
    )
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children or len(children) > 32:
            raise ValueError(f"Logical operator {op} requires 1..32 children")

        child_results = [eval_rule_node(ch, tx, _depth + 1, cnt) for ch in children]
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

    field_name = str(node.get("field") or "").strip()
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
            raise ValueError(f"Invalid numeric target in {op} rule")
        if actual is not None and _is_valid_number(actual):
            a_val = float(actual)
            t_val = float(target)
            if op == "GT":
                matched = a_val > t_val
            elif op == "GTE":
                matched = a_val >= t_val
            elif op == "LT":
                matched = a_val < t_val
            else:
                matched = a_val <= t_val
        else:
            matched = False
    elif op == "IN":
        if not isinstance(target, list) or len(target) > 64:
            raise ValueError("IN operator requires a bounded list")
        matched = any(
            (isinstance(actual, bool) == isinstance(item, bool)) and (actual == item)
            for item in target
        )
    elif op == "CONTAINS":
        if not isinstance(target, str) or len(target) > 256:
            raise ValueError("CONTAINS operator requires a string target")
        matched = isinstance(actual, str) and (target in actual)
    elif op == "REGEX":
        compiled = validate_safe_regex_pattern(target)
        if isinstance(actual, str) and len(actual) <= 512:
            matched = compiled.search(actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    validate_rule_tree(rule_tree)
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
    if "amount_cents" in sample_tx and sample_tx["amount_cents"] is not None:
        strict_int(sample_tx["amount_cents"], "amount_cents", min_val=0, max_val=INT64_MAX // 4)
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
    """按输入顺序逐笔评估实时交易批次，实现数据库、滑动窗口、三跳传染图与告警配额池的四位一体强原子提交/回滚。"""
    clean_batch_id = str(batch_id or "").strip()
    if not clean_batch_id or len(clean_batch_id) > 128:
        raise ValueError("Valid batch_id is required")
    if not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("non-empty transactions list is required")
    if len(transactions) > MAX_BATCH_TX_COUNT:
        raise ValueError(f"Batch size exceeds maximum limit ({MAX_BATCH_TX_COUNT})")

    # 第一阶段：全批次严格预校验（拦截任一笔非法字段、畸形邮箱、布尔/超大整数或批内主键冲突）
    normalized_txs: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be an object")
        raw_tx_id = item.get("tx_id")
        raw_acct_id = item.get("account_id")
        raw_cp_id = item.get("counterparty_id")
        raw_email = item.get("contact_email")
        if (
            not isinstance(raw_tx_id, str)
            or not isinstance(raw_acct_id, str)
            or not isinstance(raw_cp_id, str)
            or not isinstance(raw_email, str)
        ):
            raise ValueError("tx_id, account_id, counterparty_id, and contact_email must be strings")

        tx_id = raw_tx_id.strip()
        account_id = raw_acct_id.strip()
        counterparty_id = raw_cp_id.strip()
        contact_email = raw_email.strip()
        if not tx_id or not account_id or not counterparty_id:
            raise ValueError("tx_id, account_id, and counterparty_id cannot be empty")
        if len(tx_id) > 128 or len(account_id) > 128 or len(counterparty_id) > 128:
            raise ValueError("Transaction identifier length exceeds limit")
        if tx_id in seen_tx_ids:
            raise ValueError(f"Duplicate tx_id within batch: {tx_id}")
        seen_tx_ids.add(tx_id)

        amount_cents = strict_int(item.get("amount_cents"), "amount_cents", min_val=1, max_val=INT64_MAX // 4)
        ts = strict_int(item.get("ts"), "ts", min_val=1, max_val=INT64_MAX // 4)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        if not currency or len(currency) > 16 or not channel or len(channel) > 32:
            raise ValueError("Invalid currency or channel")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        raw_meta = item.get("metadata")
        if raw_meta is None:
            metadata: dict[str, Any] = {}
        elif isinstance(raw_meta, dict):
            metadata = raw_meta
        else:
            raise ValueError(f"metadata must be an object in transaction {tx_id}")

        normalized_txs.append(
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

    # 第二阶段：按全局严格锁偏序获取 Level-1 (tenant_risk_lock) -> Level-2 (quota_lock[REALTIME_ALERT_POOL]) -> Level-3 (BEGIN IMMEDIATE)
    with get_tenant_risk_lock(db_path, caller.tenant_id):
        with acquire_quota_locks(db_path, caller.tenant_id, ALERT_QUOTA_BUCKET):
            policy = load_tenant_policy(db_path, caller.tenant_id)
            win_state = get_or_load_tenant_window_state(db_path, caller.tenant_id)
            contagion_graph = get_or_load_contagion_graph(db_path, caller.tenant_id)

            conn = open_connection(db_path)
            undo_log: list[Callable[[], None]] = []
            try:
                conn.execute("BEGIN IMMEDIATE")

                # 预检数据库是否已存在相同 tx_id 或 decision_id，杜绝半批冲突
                tx_id_list = [t["tx_id"] for t in normalized_txs]
                dec_id_list = [f"dec_{tid}" for tid in tx_id_list]
                ph = ",".join("?" for _ in tx_id_list)
                dup_tx = conn.execute(
                    f"SELECT tx_id FROM transactions WHERE tx_id IN ({ph}) LIMIT 1",
                    tuple(tx_id_list),
                ).fetchone()
                if dup_tx is not None:
                    raise ValueError(f"Transaction tx_id already exists: {dup_tx['tx_id']}")
                dup_dec = conn.execute(
                    f"SELECT decision_id FROM risk_decisions WHERE decision_id IN ({ph}) LIMIT 1",
                    tuple(dec_id_list),
                ).fetchone()
                if dup_dec is not None:
                    raise ValueError(f"Decision record already exists: {dup_dec['decision_id']}")

                q_row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, ALERT_QUOTA_BUCKET),
                ).fetchone()
                initial_alert_quota = int(q_row["remaining_quota"]) if q_row else 0
                staged_alert_quota = initial_alert_quota
                last_alert_ts = 0

                results: list[dict[str, Any]] = []
                counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
                tx_rows_to_insert: list[tuple[Any, ...]] = []
                dec_rows_to_insert: list[tuple[Any, ...]] = []

                for tx_obj in normalized_txs:
                    tx_id = tx_obj["tx_id"]
                    account_id = tx_obj["account_id"]
                    counterparty_id = tx_obj["counterparty_id"]
                    amount_cents = tx_obj["amount_cents"]
                    currency = tx_obj["currency"]
                    channel = tx_obj["channel"]
                    contact_email = tx_obj["contact_email"]
                    ts = tx_obj["ts"]
                    metadata = tx_obj["metadata"]

                    sanction_hop = contagion_graph.stage_and_evaluate(
                        db_path,
                        account_id,
                        counterparty_id,
                        ts,
                        undo_log,
                    )
                    acct_tracker = win_state.get_or_create_account(account_id)
                    win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                        acct_tracker.stage_and_query(
                            ts,
                            amount_cents,
                            counterparty_id,
                            undo_log,
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
                        if staged_alert_quota >= 1:
                            staged_alert_quota -= 1
                            last_alert_ts = ts
                            alert_dispatched = True
                            reasons.append("ALERT_QUOTA_CONSUMED")
                        else:
                            reasons.append("ALERT_POOL_DEPLETED")

                    decision_id = f"dec_{tx_id}"
                    tx_rows_to_insert.append(
                        (
                            tx_id,
                            caller.tenant_id,
                            clean_batch_id,
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
                    dec_rows_to_insert.append(
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
                    tx_rows_to_insert,
                )
                conn.executemany(
                    "INSERT INTO risk_decisions("
                    "decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                    "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
                    "sanction_hop, reasons_json, evaluated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    dec_rows_to_insert,
                )
                if q_row is not None and staged_alert_quota != initial_alert_quota:
                    conn.execute(
                        "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                        "WHERE tenant_id = ? AND quota_type = ?",
                        (staged_alert_quota, last_alert_ts, caller.tenant_id, ALERT_QUOTA_BUCKET),
                    )
                conn.commit()
            except Exception:
                try:
                    if conn.in_transaction:
                        conn.rollback()
                except Exception:
                    pass
                for undo_fn in reversed(undo_log):
                    undo_fn()
                raise
            finally:
                conn.close()

    return {
        "tenant_id": caller.tenant_id,
        "batch_id": clean_batch_id,
        "evaluated_count": len(results),
        "decision_counts": counts,
        "results": results,
    }


def get_risk_decision_detail(
    db_path: str,
    caller: CallerContext,
    decision_id: str,
) -> dict[str, Any]:
    clean_id = str(decision_id or "").strip()
    if not clean_id or len(clean_id) > 128:
        raise ValueError("Valid decision_id is required")
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE decision_id = ?",
            (clean_id,),
        ).fetchone()
        if not row:
            raise LookupError(f"Decision record not found: {clean_id}")
        if str(row["tenant_id"]) != caller.tenant_id:
            raise PermissionError("Decision record belongs to another tenant")
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
