# -*- coding: utf-8 -*-
"""实时交易风控评分、安全规则树 AST 引擎、统一锁偏序与四位一体强原子批次事务模块。"""
from __future__ import annotations

import functools
import json
import math
import re
import sqlite3
import time
from typing import Any

try:
    import re._constants as _sre_constants  # type: ignore[import-not-found]
    import re._parser as _sre_parser  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    import sre_constants as _sre_constants  # type: ignore[no-redef]
    import sre_parse as _sre_parser  # type: ignore[no-redef]

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    MAX_BATCH_TX_COUNT,
    MAX_REGEX_LENGTH,
    MAX_REGEX_MATCH_INPUT_LEN,
    MAX_REGEX_QUANTIFIER,
    MAX_RULE_IN_ITEMS,
    MAX_RULE_TREE_DEPTH,
    MAX_RULE_TREE_NODES,
    SANCTION_HOP_SCORES,
    TX_AMOUNT_MAX_CENTS,
)
from .contagion_graph import ContagionBatchUndo, get_tenant_contagion_graph
from .db import DatabaseRuntime, get_db_runtime
from .legacy_compat import apply_sovereign_settlement_adjustment
from .middleware import strict_finite_number, strict_int
from .window_stats import WindowBatchUndo, get_tenant_window_manager

# 线性 O(L) 无嵌套量词回溯的等价邮箱校验正则
PARTNER_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)

_BACKREF_LEX_RE = re.compile(r"(?<!\\)(?:\\\\)*(?:\\[1-9]|\(\?P=)")
_LOOKAROUND_COND_RE = re.compile(r"(?<!\\)(?:\\\\)*\(\?(?:=|!|<=|<!|\()")
_BRACE_QUANT_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")

_REPEAT_OPS = frozenset({_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT})
if hasattr(_sre_constants, "POSSESSIVE_REPEAT"):
    _REPEAT_OPS = _REPEAT_OPS | {_sre_constants.POSSESSIVE_REPEAT}


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > 254:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def _inspect_regex_ast(
    subpattern: Any,
    *,
    in_repeat: bool = False,
    unbounded_counter: list[int] | None = None,
) -> None:
    """递归审计正则语法树：拦截嵌套量词、重叠分支重复、大上界花括号量词与反向引用。"""
    if unbounded_counter is None:
        unbounded_counter = [0]

    for op, av in subpattern:
        if op == _sre_constants.GROUPREF or op == getattr(_sre_constants, "GROUPREF_EXISTS", None):
            raise ValueError("Backreferences are forbidden in custom regex rules")
        if op in (
            getattr(_sre_constants, "ASSERT", None),
            getattr(_sre_constants, "ASSERT_NOT", None),
        ):
            raise ValueError("Lookaround assertions are forbidden in custom regex rules")

        if op in _REPEAT_OPS:
            min_rep, max_rep, inner = av
            if min_rep > MAX_REGEX_QUANTIFIER:
                raise ValueError(f"Regex quantifier lower bound exceeds {MAX_REGEX_QUANTIFIER}")
            if max_rep != _sre_constants.MAXREPEAT and max_rep > MAX_REGEX_QUANTIFIER:
                raise ValueError(f"Regex quantifier upper bound exceeds {MAX_REGEX_QUANTIFIER}")

            is_multi = (max_rep == _sre_constants.MAXREPEAT) or (max_rep > 1)
            if in_repeat and is_multi:
                raise ValueError("Nested quantifiers (ReDoS risk) are forbidden in custom regex")

            if max_rep == _sre_constants.MAXREPEAT:
                unbounded_counter[0] += 1
                if unbounded_counter[0] > 3:
                    raise ValueError("Too many unbounded quantifiers in custom regex")

            _inspect_regex_ast(
                inner,
                in_repeat=(in_repeat or is_multi),
                unbounded_counter=unbounded_counter,
            )

        elif op == _sre_constants.SUBPATTERN:
            # av = (group, add_flags, del_flags, p)
            inner_sub = av[-1]
            _inspect_regex_ast(
                inner_sub,
                in_repeat=in_repeat,
                unbounded_counter=unbounded_counter,
            )

        elif op == _sre_constants.BRANCH:
            # av = (None, [branch1, branch2, ...])
            branches = av[1]
            if len(branches) > 16:
                raise ValueError("Too many alternation branches in custom regex")
            if in_repeat:
                # 在重复体内部仅允许互不重叠的单字面字符分支，严防 (a|aa)+ / (ab|ac)+ 指数回溯
                seen_literals: set[int] = set()
                for br in branches:
                    if len(br) != 1 or br[0][0] != _sre_constants.LITERAL:
                        raise ValueError("Complex alternation inside repetition is forbidden (ReDoS risk)")
                    lit_code = int(br[0][1])
                    if lit_code in seen_literals:
                        raise ValueError("Duplicate alternation literal inside repetition (ReDoS risk)")
                    seen_literals.add(lit_code)
            for br in branches:
                _inspect_regex_ast(
                    br,
                    in_repeat=in_repeat,
                    unbounded_counter=unbounded_counter,
                )


@functools.lru_cache(maxsize=512)
def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError("Invalid or oversized regex pattern")
    if _BACKREF_LEX_RE.search(pattern):
        raise ValueError("Backreferences are forbidden in custom regex")
    if _LOOKAROUND_COND_RE.search(pattern):
        raise ValueError("Lookaround/conditional constructs are forbidden in custom regex")

    for m in _BRACE_QUANT_RE.finditer(pattern):
        lo = int(m.group(1))
        hi_s = m.group(2)
        if lo > MAX_REGEX_QUANTIFIER:
            raise ValueError("Regex brace quantifier exceeds safe limit")
        if hi_s is not None and hi_s != "":
            hi = int(hi_s)
            if hi < lo or hi > MAX_REGEX_QUANTIFIER:
                raise ValueError("Regex brace quantifier range invalid or exceeds safe limit")

    try:
        parsed = _sre_parser.parse(pattern)
    except re.error as exc:
        raise ValueError(f"Malformed regular expression: {exc}") from exc

    _inspect_regex_ast(parsed)
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Failed to compile regular expression: {exc}") from exc


def validate_rule_tree(tree: dict[str, Any]) -> None:
    """在保存或试算前静态校验整棵自定义规则树的深度、节点数、类型与正则安全性。"""
    if not isinstance(tree, dict):
        raise ValueError("Rule tree must be a JSON object")
    if not tree:
        return

    stack: list[tuple[Any, int]] = [(tree, 1)]
    node_count = 0

    while stack:
        node, depth = stack.pop()
        if not isinstance(node, dict):
            raise ValueError("Rule node must be an object")
        if depth > MAX_RULE_TREE_DEPTH:
            raise ValueError(f"Rule tree depth exceeds limit ({MAX_RULE_TREE_DEPTH})")
        node_count += 1
        if node_count > MAX_RULE_TREE_NODES:
            raise ValueError(f"Rule tree node count exceeds limit ({MAX_RULE_TREE_NODES})")

        raw_op = node.get("op")
        op = str(raw_op).upper() if isinstance(raw_op, str) else ""
        raw_bonus = node.get("bonus_score", 0)
        if raw_bonus is not None:
            strict_int(raw_bonus, "bonus_score", min_val=-10000, max_val=10000)

        raw_reason = node.get("reason")
        if raw_reason is not None and (not isinstance(raw_reason, str) or len(raw_reason) > 128):
            raise ValueError("Rule reason must be a string within 128 chars")

        if op in ("AND", "OR", "NOT"):
            children = node.get("children")
            if not isinstance(children, list) or not children or len(children) > 32:
                raise ValueError(f"Logical operator {op} requires 1..32 children")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            for ch in children:
                stack.append((ch, depth + 1))
        elif op in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"):
            field_name = node.get("field")
            if not isinstance(field_name, str) or not field_name.strip() or len(field_name) > 128:
                raise ValueError("Leaf rule node requires a valid 'field' string")
            target = node.get("value")
            if op in ("GT", "GTE", "LT", "LTE"):
                strict_finite_number(target, "rule.value")
            elif op == "IN":
                if not isinstance(target, list) or len(target) > MAX_RULE_IN_ITEMS:
                    raise ValueError(f"IN operator requires a list of at most {MAX_RULE_IN_ITEMS} items")
            elif op == "CONTAINS":
                if not isinstance(target, str) or len(target) > 256:
                    raise ValueError("CONTAINS operator requires a target string within 256 chars")
            elif op == "REGEX":
                if not isinstance(target, str):
                    raise ValueError("REGEX operator requires a string pattern")
                _compile_safe_regex(target)
        else:
            raise ValueError(f"Unsupported rule operator: {op!r}")


def _load_policy_from_db(rt: DatabaseRuntime, tenant_id: str) -> dict[str, Any]:
    with rt.read_conn() as conn:
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


def _get_cached_tenant_policy(rt: DatabaseRuntime, tenant_id: str) -> dict[str, Any]:
    cached = rt.policy_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.tenant_meta_lock(tenant_id):
        cached = rt.policy_cache.get(tenant_id)
        if cached is not None:
            return cached
        loaded = _load_policy_from_db(rt, tenant_id)
        rt.policy_cache.set(tenant_id, loaded)
        return loaded


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    rt = get_db_runtime(db_path)
    pol = _get_cached_tenant_policy(rt, tenant_id)
    return dict(pol)


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy updates must be an object")

    rt = get_db_runtime(db_path)
    with rt.tenant_meta_lock(caller.tenant_id):
        current = _get_cached_tenant_policy(rt, caller.tenant_id)

        high_amt = strict_int(
            updates["high_amount_cents"] if "high_amount_cents" in updates else current["high_amount_cents"],
            "high_amount_cents",
            min_val=1,
            max_val=TX_AMOUNT_MAX_CENTS,
        )
        vel_tx = strict_int(
            updates["velocity_tx_limit"] if "velocity_tx_limit" in updates else current["velocity_tx_limit"],
            "velocity_tx_limit",
            min_val=1,
            max_val=1_000_000,
        )
        vel_amt = strict_int(
            updates["velocity_amount_cents"] if "velocity_amount_cents" in updates else current["velocity_amount_cents"],
            "velocity_amount_cents",
            min_val=1,
            max_val=TX_AMOUNT_MAX_CENTS,
        )
        fanout = strict_int(
            updates["counterparty_fanout_limit"] if "counterparty_fanout_limit" in updates else current["counterparty_fanout_limit"],
            "counterparty_fanout_limit",
            min_val=1,
            max_val=1_000_000,
        )
        rev_th = strict_int(
            updates["review_threshold"] if "review_threshold" in updates else current["review_threshold"],
            "review_threshold",
            min_val=1,
            max_val=100,
        )
        rej_th = strict_int(
            updates["reject_threshold"] if "reject_threshold" in updates else current["reject_threshold"],
            "reject_threshold",
            min_val=1,
            max_val=100,
        )

        if rej_th < rev_th:
            raise ValueError("Invalid policy threshold values: reject_threshold < review_threshold")

        custom_rules = updates.get("custom_rules", current["custom_rules"])
        if not isinstance(custom_rules, dict):
            raise ValueError("custom_rules must be a JSON object")
        validate_rule_tree(custom_rules)

        new_ver = int(current["policy_version"]) + 1
        now_ts = int(caller.request_ts or int(time.time()))
        rules_json = json.dumps(custom_rules, allow_nan=False)

        with rt.write_tx() as conn:
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
                    rules_json,
                    now_ts,
                    caller.tenant_id,
                ),
            )

        updated_policy = {
            "tenant_id": caller.tenant_id,
            "policy_version": new_ver,
            "high_amount_cents": high_amt,
            "velocity_tx_limit": vel_tx,
            "velocity_amount_cents": vel_amt,
            "counterparty_fanout_limit": fanout,
            "review_threshold": rev_th,
            "reject_threshold": rej_th,
            "custom_rules_json": rules_json,
            "custom_rules": custom_rules,
            "updated_at": now_ts,
        }
        rt.policy_cache.set(caller.tenant_id, updated_policy)
        return dict(updated_policy)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata")
        return meta.get(sub_key) if isinstance(meta, dict) else None
    return tx.get(field_path)


def _safe_equals(actual: Any, target: Any) -> bool:
    if isinstance(actual, bool) != isinstance(target, bool):
        return False
    return actual == target


def _safe_numeric_pair(actual: Any, target: Any) -> tuple[float, float] | None:
    target_f = strict_finite_number(target, "rule.value")
    if actual is None or isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return None
    actual_f = float(actual)
    if not math.isfinite(actual_f):
        return None
    return actual_f, target_f


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any], _depth: int = 1) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if _depth > MAX_RULE_TREE_DEPTH:
        raise ValueError("Rule evaluation depth exceeded")

    raw_op = node.get("op")
    op = str(raw_op).upper() if isinstance(raw_op, str) else ""
    raw_bonus = node.get("bonus_score", 0)
    bonus = strict_int(raw_bonus if raw_bonus is not None else 0, "bonus_score", min_val=-10000, max_val=10000)
    raw_reason = node.get("reason")
    reason = str(raw_reason).strip() if isinstance(raw_reason, str) else ""

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children or len(children) > 32:
            raise ValueError(f"Logical operator {op} requires non-empty bounded children list")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")

        child_results = [eval_rule_node(ch, tx, _depth + 1) for ch in children]
        if op == "AND":
            matched = all(r[0] for r in child_results)
        elif op == "OR":
            matched = any(r[0] for r in child_results)
        else:
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

    field_name = node.get("field")
    if not isinstance(field_name, str) or not field_name:
        raise ValueError("Leaf rule node missing 'field'")
    actual = _extract_field(tx, field_name)
    target = node.get("value")

    matched = False
    if op == "EQ":
        matched = _safe_equals(actual, target)
    elif op == "NEQ":
        matched = not _safe_equals(actual, target)
    elif op in ("GT", "GTE", "LT", "LTE"):
        pair = _safe_numeric_pair(actual, target)
        if pair is not None:
            af, tf = pair
            if op == "GT":
                matched = af > tf
            elif op == "GTE":
                matched = af >= tf
            elif op == "LT":
                matched = af < tf
            else:
                matched = af <= tf
    elif op == "IN":
        if not isinstance(target, list) or len(target) > MAX_RULE_IN_ITEMS:
            raise ValueError("Invalid IN operator target list")
        matched = any(_safe_equals(actual, item) for item in target)
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if not isinstance(target, str):
            raise ValueError("REGEX operator requires a string pattern")
        compiled = _compile_safe_regex(target)
        if isinstance(actual, str):
            if len(actual) > MAX_REGEX_MATCH_INPUT_LEN:
                raise ValueError("Input string exceeds safe regex match budget")
            matched = compiled.search(actual) is not None
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
    validate_rule_tree(rule_tree)

    email = sample_tx.get("contact_email")
    if email is not None:
        if not isinstance(email, str) or not validate_contact_email(email):
            raise ValueError("Invalid contact_email format in sample_tx")
    if "amount_cents" in sample_tx and sample_tx["amount_cents"] is not None:
        strict_int(sample_tx["amount_cents"], "amount_cents", min_val=0, max_val=TX_AMOUNT_MAX_CENTS)

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


def _require_tx_str(val: Any, field_name: str, *, max_len: int = 128, default: str | None = None) -> str:
    if val is None:
        if default is not None:
            return default
        raise ValueError(f"Missing required string field: {field_name}")
    if not isinstance(val, str):
        raise ValueError(f"Field '{field_name}' must be a string")
    s = val.strip()
    if not s:
        if default is not None:
            return default
        raise ValueError(f"Field '{field_name}' cannot be empty")
    if len(s) > max_len:
        raise ValueError(f"Field '{field_name}' exceeds length limit")
    return s


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按统一锁偏序评估实时交易批次，实现数据库、滑窗、传染图与告警配额池的四位一体强原子提交/回滚。"""
    if not isinstance(batch_id, str) or not batch_id.strip() or len(batch_id.strip()) > 128:
        raise ValueError("Valid batch_id is required")
    norm_batch_id = batch_id.strip()

    if not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("transactions must be a non-empty list")
    if len(transactions) > MAX_BATCH_TX_COUNT:
        raise ValueError(f"Batch size exceeds maximum limit ({MAX_BATCH_TX_COUNT})")

    # 阶段 0：整批全量零副作用校验（拦截非法字段、bool/超大整数/NaN、恶意邮箱与批内重复 tx_id）
    normalized_txs: list[tuple[dict[str, Any], str]] = []
    seen_tx_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be an object")

        tx_id = _require_tx_str(item.get("tx_id"), "tx_id", max_len=128)
        if tx_id in seen_tx_ids:
            raise ValueError(f"Duplicate tx_id within batch: {tx_id}")
        seen_tx_ids.add(tx_id)

        account_id = _require_tx_str(item.get("account_id"), "account_id", max_len=128)
        counterparty_id = _require_tx_str(item.get("counterparty_id"), "counterparty_id", max_len=128)

        raw_amt = item.get("amount_cents")
        if raw_amt is None:
            raise ValueError(f"Missing amount_cents for tx_id={tx_id!r}")
        amount_cents = strict_int(raw_amt, "amount_cents", min_val=1, max_val=TX_AMOUNT_MAX_CENTS)

        raw_ts = item.get("ts")
        if raw_ts is None:
            raise ValueError(f"Missing ts for tx_id={tx_id!r}")
        ts = strict_int(raw_ts, "ts", min_val=1, max_val=10**13)

        currency = _require_tx_str(item.get("currency"), "currency", max_len=16, default="USD")
        channel = _require_tx_str(item.get("channel"), "channel", max_len=32, default="POS_CHIP")
        contact_email = _require_tx_str(item.get("contact_email"), "contact_email", max_len=254)
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        raw_meta = item.get("metadata")
        if raw_meta is None:
            metadata: dict[str, Any] = {}
        elif isinstance(raw_meta, dict):
            metadata = raw_meta
        else:
            raise ValueError(f"metadata must be an object in transaction {tx_id}")

        meta_json = json.dumps(metadata, sort_keys=True, allow_nan=False)
        if len(meta_json) > 16384:
            raise ValueError(f"metadata exceeds size budget in transaction {tx_id}")

        normalized_txs.append(
            (
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
                },
                meta_json,
            )
        )

    rt = get_db_runtime(db_path)

    # 阶段 1：严格遵循全局锁偏序 Layer 1 (risk_lock) -> Layer 2 (quota_lock) -> Layer 3 (BEGIN IMMEDIATE)
    with rt.acquire_risk_lock(caller.tenant_id):
        with rt.acquire_quota_locks(caller.tenant_id, ALERT_QUOTA_BUCKET):
            # 在进入 Layer 3 写事务前预热内存策略、滑窗与传染图快照（避免读写连接重入）
            policy = _get_cached_tenant_policy(rt, caller.tenant_id)
            window_mgr = get_tenant_window_manager(rt, caller.tenant_id)
            contagion_graph = get_tenant_contagion_graph(rt, caller.tenant_id)

            win_undo = WindowBatchUndo()
            cg_undo = ContagionBatchUndo()

            with rt.write_tx() as conn:
                q_row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, ALERT_QUOTA_BUCKET),
                ).fetchone()
                init_alert_quota = int(q_row["remaining_quota"]) if q_row and int(q_row["remaining_quota"]) > 0 else 0
                avail_alert_quota = init_alert_quota
                last_alert_ts = 0

                results: list[dict[str, Any]] = []
                counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
                tx_rows_to_insert: list[tuple[Any, ...]] = []
                dec_rows_to_insert: list[tuple[Any, ...]] = []

                try:
                    for tx_obj, meta_json in normalized_txs:
                        tx_id = tx_obj["tx_id"]
                        account_id = tx_obj["account_id"]
                        counterparty_id = tx_obj["counterparty_id"]
                        amount_cents = tx_obj["amount_cents"]
                        ts = tx_obj["ts"]

                        sanction_hop = contagion_graph.evaluate_and_record(
                            account_id,
                            counterparty_id,
                            ts,
                            cg_undo,
                        )
                        win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                            window_mgr.evaluate_and_record(
                                account_id,
                                counterparty_id,
                                amount_cents,
                                ts,
                                win_undo,
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
                                norm_batch_id,
                                account_id,
                                counterparty_id,
                                amount_cents,
                                tx_obj["currency"],
                                tx_obj["channel"],
                                tx_obj["contact_email"],
                                ts,
                                meta_json,
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
                    if avail_alert_quota != init_alert_quota and q_row is not None:
                        conn.execute(
                            "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                            "WHERE tenant_id = ? AND quota_type = ?",
                            (avail_alert_quota, last_alert_ts, caller.tenant_id, ALERT_QUOTA_BUCKET),
                        )
                except BaseException as exc:
                    window_mgr.rollback(win_undo)
                    contagion_graph.rollback(cg_undo)
                    if isinstance(exc, sqlite3.IntegrityError):
                        raise ValueError("Transaction primary key conflict during batch commit") from exc
                    raise

    return {
        "tenant_id": caller.tenant_id,
        "batch_id": norm_batch_id,
        "evaluated_count": len(results),
        "decision_counts": counts,
        "results": results,
    }


def get_risk_decision_detail(
    db_path: str,
    caller: CallerContext,
    decision_id: str,
) -> dict[str, Any]:
    if not isinstance(decision_id, str) or not decision_id.strip() or len(decision_id.strip()) > 128:
        raise ValueError("Valid decision_id is required")
    norm_dec_id = decision_id.strip()

    rt = get_db_runtime(db_path)
    with rt.read_conn() as conn:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
            (norm_dec_id, caller.tenant_id),
        ).fetchone()
        if not row:
            raise LookupError(f"Decision record not found: {norm_dec_id}")
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
