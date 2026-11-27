# -*- coding: utf-8 -*-
"""实时交易风控批次引擎：四位一体强原子提交/回滚、无回溯邮件/正则 AST 沙箱与规则树深度熔断。"""
from __future__ import annotations

from functools import lru_cache
import json
import math
import re
import re._constants as _re_const
import re._parser as _re_parser
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    INT64_MAX,
    MAX_BATCH_TX_COUNT,
    MAX_REGEX_LEN,
    MAX_REGEX_REPEAT_BOUND,
    MAX_RULE_DEPTH,
    MAX_RULE_IN_LIST,
    MAX_RULE_NODES,
    MAX_SAFE_TS,
    MAX_TX_AMOUNT_CENTS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import get_sanctioned_set, get_tenant_risk_state
from .db import borrow_connection, get_db_hub, write_transaction
from .legacy_compat import apply_sovereign_settlement_adjustment
from .middleware import strict_int
from .window_stats import AccountWindowTracker

# 消除嵌套量词灾难性回溯的线性时间邮箱校验正则（与原版接受语言 100% 等价）
PARTNER_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)

_FORBIDDEN_REGEX_OPS = frozenset(
    {
        _re_const.GROUPREF,
        _re_const.GROUPREF_EXISTS,
        _re_const.GROUPREF_IGNORE,
        _re_const.GROUPREF_LOC_IGNORE,
        _re_const.GROUPREF_UNI_IGNORE,
        _re_const.ASSERT,
        _re_const.ASSERT_NOT,
    }
)
_REPEAT_OPS = frozenset(
    {
        _re_const.MAX_REPEAT,
        _re_const.MIN_REPEAT,
        _re_const.POSSESSIVE_REPEAT,
    }
)
_LITERAL_OPS = frozenset(
    {
        _re_const.LITERAL,
        _re_const.LITERAL_IGNORE,
        _re_const.LITERAL_LOC_IGNORE,
        _re_const.LITERAL_UNI_IGNORE,
    }
)


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > 254:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def _inspect_regex_ast(subpattern: Any, *, in_repeat: bool = False) -> int:
    """递归审计正则语法树：拦截嵌套量词、零宽重复、反向引用、环视断言、超大花括号重复上界与歧义分支。"""
    unbounded_count = 0
    for op, av in subpattern:
        if op in _FORBIDDEN_REGEX_OPS:
            raise ValueError("Backreferences and lookaround assertions are forbidden in custom regex")

        if op in _REPEAT_OPS:
            if in_repeat:
                raise ValueError("Nested quantifiers are forbidden in custom regex")
            min_cnt, max_cnt, body = av
            if min_cnt > MAX_REGEX_REPEAT_BOUND or (
                max_cnt != _re_const.MAXREPEAT and max_cnt > MAX_REGEX_REPEAT_BOUND
            ):
                raise ValueError("Regex curly-brace repetition bound exceeds safe limit")
            lo_width, _ = body.getwidth()
            if lo_width == 0:
                raise ValueError("Zero-width repetition is forbidden in custom regex")
            if max_cnt == _re_const.MAXREPEAT or max_cnt > 4:
                unbounded_count += 1
                if unbounded_count > 4:
                    raise ValueError("Excessive chained quantifiers in custom regex")
            _inspect_regex_ast(body, in_repeat=True)

        elif op == _re_const.SUBPATTERN:
            _, _, _, inner = av
            unbounded_count += _inspect_regex_ast(inner, in_repeat=in_repeat)
            if unbounded_count > 4:
                raise ValueError("Excessive chained quantifiers in custom regex")

        elif op == _re_const.BRANCH:
            _, branches = av
            if len(branches) > 16:
                raise ValueError("Regex alternation branch count exceeds safe limit")
            if in_repeat:
                # 量词内部的交替分支必须以互不重叠的首字面量开头，防止 (a|aa)+ / (ab|ac)+ 指数回溯
                seen_first_chars: set[str] = set()
                for br in branches:
                    if not br:
                        raise ValueError("Empty branch inside regex quantifier")
                    first_op, first_av = br[0]
                    if first_op not in _LITERAL_OPS:
                        raise ValueError("Ambiguous non-literal branch inside regex quantifier")
                    ch_key = chr(int(first_av)).lower()
                    if ch_key in seen_first_chars:
                        raise ValueError("Overlapping alternation branches inside regex quantifier")
                    seen_first_chars.add(ch_key)
            for br in branches:
                unbounded_count += _inspect_regex_ast(br, in_repeat=in_repeat)
                if unbounded_count > 4:
                    raise ValueError("Excessive chained quantifiers in custom regex")

        elif op == _re_const.ATOMIC_GROUP:
            unbounded_count += _inspect_regex_ast(av, in_repeat=in_repeat)

    return unbounded_count


@lru_cache(maxsize=256)
def compile_safe_regex(pattern: str) -> re.Pattern[str]:
    if not isinstance(pattern, str) or len(pattern) > MAX_REGEX_LEN:
        raise ValueError("Regex pattern must be a string within length limit")
    try:
        parsed = _re_parser.parse(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}") from exc
    _inspect_regex_ast(parsed, in_repeat=False)
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}") from exc


def _is_valid_number(val: Any) -> bool:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return False
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return False
    if isinstance(val, int) and (val < -(1 << 63) or val > INT64_MAX):
        return False
    return True


def validate_rule_tree(root: dict[str, Any]) -> None:
    """校验自定义规则树：限制最大深度、总节点数、列表体积、严格数值类型与安全正则。"""
    if not isinstance(root, dict) or not root:
        raise ValueError("Rule node must be a non-empty object")

    total_nodes = 0

    def _walk(node: Any, depth: int) -> None:
        nonlocal total_nodes
        if not isinstance(node, dict):
            raise ValueError("Rule node must be an object")
        if depth > MAX_RULE_DEPTH:
            raise ValueError("Rule tree exceeds maximum nesting depth")
        total_nodes += 1
        if total_nodes > MAX_RULE_NODES:
            raise ValueError("Rule tree exceeds maximum node budget")

        raw_bonus = node.get("bonus_score", 0)
        if raw_bonus is not None:
            strict_int(raw_bonus, "bonus_score", min_val=-10000, max_val=10000)

        reason = node.get("reason")
        if reason is not None and (not isinstance(reason, str) or len(reason) > 128):
            raise ValueError("Invalid rule reason string")

        op = str(node.get("op") or "").upper()
        if op in ("AND", "OR", "NOT"):
            children = node.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            for ch in children:
                _walk(ch, depth + 1)
            return

        field_name = str(node.get("field") or "")
        if not field_name or len(field_name) > 128:
            raise ValueError("Leaf rule node missing valid 'field'")

        target = node.get("value")
        if op in ("EQ", "NEQ"):
            if isinstance(target, float) and (math.isnan(target) or math.isinf(target)):
                raise ValueError("NaN/Inf target is forbidden")
        elif op in ("GT", "GTE", "LT", "LTE"):
            if not _is_valid_number(target):
                raise ValueError(f"Numeric operator {op} requires finite numeric value")
        elif op == "IN":
            if not isinstance(target, list) or len(target) > MAX_RULE_IN_LIST:
                raise ValueError("IN operator requires a bounded list")
        elif op == "CONTAINS":
            if not isinstance(target, str) or len(target) > 512:
                raise ValueError("CONTAINS operator requires string value within limit")
        elif op == "REGEX":
            if not isinstance(target, str):
                raise ValueError("REGEX operator requires a string pattern")
            compile_safe_regex(target)
        else:
            raise ValueError(f"Unsupported rule operator: {op}")

    _walk(root, 1)


class PolicySnapshot:
    __slots__ = ("epoch", "policy")

    def __init__(self, epoch: int, policy: dict[str, Any]) -> None:
        self.epoch = epoch
        self.policy = policy


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    hub = get_db_hub(db_path)
    target_ep = hub.get_epochs(tenant_id).policy_epoch
    cached: PolicySnapshot | None = hub.policy_snapshots.get(tenant_id)
    if cached is not None and cached.epoch == target_ep:
        return cached.policy

    with hub.tenant_meta_lock(tenant_id):
        target_ep = hub.get_epochs(tenant_id).policy_epoch
        cached = hub.policy_snapshots.get(tenant_id)
        if cached is not None and cached.epoch == target_ep:
            return cached.policy

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
        hub.policy_snapshots.set(tenant_id, PolicySnapshot(target_ep, policy))
        return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy updates must be an object")

    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = (
        int(current["high_amount_cents"])
        if "high_amount_cents" not in updates
        else strict_int(updates["high_amount_cents"], "high_amount_cents", min_val=1, max_val=MAX_TX_AMOUNT_CENTS)
    )
    vel_tx = (
        int(current["velocity_tx_limit"])
        if "velocity_tx_limit" not in updates
        else strict_int(updates["velocity_tx_limit"], "velocity_tx_limit", min_val=1, max_val=1_000_000)
    )
    vel_amt = (
        int(current["velocity_amount_cents"])
        if "velocity_amount_cents" not in updates
        else strict_int(updates["velocity_amount_cents"], "velocity_amount_cents", min_val=1, max_val=INT64_MAX)
    )
    fanout = (
        int(current["counterparty_fanout_limit"])
        if "counterparty_fanout_limit" not in updates
        else strict_int(updates["counterparty_fanout_limit"], "counterparty_fanout_limit", min_val=0, max_val=1_000_000)
    )
    rev_th = (
        int(current["review_threshold"])
        if "review_threshold" not in updates
        else strict_int(updates["review_threshold"], "review_threshold", min_val=1, max_val=100)
    )
    rej_th = (
        int(current["reject_threshold"])
        if "reject_threshold" not in updates
        else strict_int(updates["reject_threshold"], "reject_threshold", min_val=1, max_val=100)
    )
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or vel_amt <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    if custom_rules:
        validate_rule_tree(custom_rules)

    rules_json = json.dumps(custom_rules, allow_nan=False)
    now_ts = int(caller.request_ts or int(time.time()))

    hub = get_db_hub(db_path)
    with hub.tenant_meta_lock(caller.tenant_id):
        with write_transaction(db_path) as conn:
            row = conn.execute(
                "SELECT policy_version FROM tenant_policies WHERE tenant_id = ?",
                (caller.tenant_id,),
            ).fetchone()
            if not row:
                raise LookupError(f"Policy configuration missing for {caller.tenant_id}")
            new_ver = int(row["policy_version"]) + 1
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
        hub.bump_policy_epoch(caller.tenant_id)

    return dict(load_tenant_policy(db_path, caller.tenant_id))


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata")
        return meta.get(sub_key) if isinstance(meta, dict) else None
    return tx.get(field_path)


def _eval_validated_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    op = str(node.get("op") or "").upper()
    raw_bonus = node.get("bonus_score")
    bonus = 0 if raw_bonus is None else int(raw_bonus)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node["children"]
        child_results = [_eval_validated_node(ch, tx) for ch in children]
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
        if op != "NOT":
            for child_ok, child_score, child_reasons in child_results:
                if child_ok:
                    total_bonus += child_score
                    reasons.extend(child_reasons)
        if reason:
            reasons.append(reason)
        return True, total_bonus, reasons

    field_name = str(node["field"])
    actual = _extract_field(tx, field_name)
    target = node.get("value")

    matched = False
    if op == "EQ":
        matched = (isinstance(actual, bool) == isinstance(target, bool)) and (actual == target)
    elif op == "NEQ":
        matched = not ((isinstance(actual, bool) == isinstance(target, bool)) and (actual == target))
    elif op in ("GT", "GTE", "LT", "LTE"):
        if _is_valid_number(actual) and _is_valid_number(target):
            if op == "GT":
                matched = actual > target
            elif op == "GTE":
                matched = actual >= target
            elif op == "LT":
                matched = actual < target
            else:
                matched = actual <= target
    elif op == "IN":
        if isinstance(target, list):
            actual_is_bool = isinstance(actual, bool)
            matched = any(
                (isinstance(item, bool) == actual_is_bool) and (actual == item)
                for item in target
            )
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            if len(actual) > 4096:
                raise ValueError("Target string too long for regex evaluation")
            compiled = compile_safe_regex(target)
            matched = compiled.search(actual) is not None

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    validate_rule_tree(node)
    return _eval_validated_node(node, tx)


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    if "amount_cents" in sample_tx and sample_tx["amount_cents"] is not None:
        strict_int(sample_tx["amount_cents"], "amount_cents", min_val=0, max_val=MAX_TX_AMOUNT_CENTS)
    if "ts" in sample_tx and sample_tx["ts"] is not None:
        strict_int(sample_tx["ts"], "ts", min_val=0, max_val=MAX_SAFE_TS)
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
    validate_rule_tree(rule_tree)
    matched, bonus_score, reasons = _eval_validated_node(rule_tree, sample_tx)
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
        matched, bonus, rule_reasons = _eval_validated_node(custom_tree, tx)
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
    """按严格全局锁偏序（Layer 1 -> Layer 2 -> Layer 3）执行整批评估与四位一体强原子提交/回滚。"""
    clean_batch_id = str(batch_id or "").strip()
    if (
        not clean_batch_id
        or len(clean_batch_id) > 128
        or not isinstance(transactions, list)
        or len(transactions) == 0
        or len(transactions) > MAX_BATCH_TX_COUNT
    ):
        raise ValueError("Valid batch_id and bounded non-empty transactions list are required")

    # 阶段 1（无锁纯 CPU 预检）：全量校验批次内每笔字段类型、边界、无回溯邮箱与批内重复主键
    normalized_txs: list[tuple[dict[str, Any], str]] = []
    seen_tx_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be an object")

        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()

        if (
            not tx_id
            or not account_id
            or not counterparty_id
            or len(tx_id) > 128
            or len(account_id) > 128
            or len(counterparty_id) > 128
            or len(currency) > 16
            or len(channel) > 64
        ):
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")

        if tx_id in seen_tx_ids:
            raise ValueError(f"Duplicate tx_id within batch: {tx_id}")
        seen_tx_ids.add(tx_id)

        amount_cents = strict_int(
            item.get("amount_cents"),
            "amount_cents",
            min_val=1,
            max_val=MAX_TX_AMOUNT_CENTS,
        )
        ts = strict_int(
            item.get("ts"),
            "ts",
            min_val=1,
            max_val=MAX_SAFE_TS,
        )
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        raw_meta = item.get("metadata")
        metadata = raw_meta if isinstance(raw_meta, dict) else {}
        meta_json = json.dumps(metadata, sort_keys=True, allow_nan=False)
        if len(meta_json) > 16384:
            raise ValueError("Transaction metadata exceeds size limit")

        tx_obj = {
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
        normalized_txs.append((tx_obj, meta_json))

    tenant_id = caller.tenant_id
    policy = load_tenant_policy(db_path, tenant_id)
    custom_tree = policy.get("custom_rules")
    if isinstance(custom_tree, dict) and custom_tree:
        validate_rule_tree(custom_tree)
    sanctioned = get_sanctioned_set(db_path, tenant_id)

    hub = get_db_hub(db_path)
    # 阶段 2（严格锁偏序）：Layer 1 tenant_risk_lock -> Layer 2 quota_locks(REALTIME_ALERT_POOL) -> Layer 3 write_transaction
    with hub.tenant_risk_lock(tenant_id):
        state = get_tenant_risk_state(db_path, tenant_id)
        with hub.quota_locks(tenant_id, ALERT_QUOTA_BUCKET):
            window_undo_log: list[tuple[AccountWindowTracker, int]] = []
            created_accounts: list[str] = []
            graph_undo_log: list[int] = []

            try:
                with write_transaction(db_path) as conn:
                    # 预检存量主键冲突，确保在修改前或冲突时零副作用回滚
                    placeholders = ",".join("?" for _ in seen_tx_ids)
                    tx_id_tuple = tuple(seen_tx_ids)
                    dup_tx = conn.execute(
                        f"SELECT tx_id FROM transactions WHERE tx_id IN ({placeholders}) LIMIT 1",
                        tx_id_tuple,
                    ).fetchone()
                    if dup_tx is not None:
                        raise ValueError(f"Duplicate transaction ID already exists: {dup_tx['tx_id']}")

                    dec_id_tuple = tuple(f"dec_{tid}" for tid in seen_tx_ids)
                    dup_dec = conn.execute(
                        f"SELECT decision_id FROM risk_decisions WHERE decision_id IN ({placeholders}) LIMIT 1",
                        dec_id_tuple,
                    ).fetchone()
                    if dup_dec is not None:
                        raise ValueError(f"Duplicate decision ID already exists: {dup_dec['decision_id']}")

                    q_row = conn.execute(
                        "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                        (tenant_id, ALERT_QUOTA_BUCKET),
                    ).fetchone()
                    alert_rem = int(q_row["remaining_quota"]) if q_row else 0
                    alert_consumed = 0
                    last_alert_ts = 0

                    tx_insert_rows: list[tuple[Any, ...]] = []
                    dec_insert_rows: list[tuple[Any, ...]] = []
                    results: list[dict[str, Any]] = []
                    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

                    for tx_obj, meta_json in normalized_txs:
                        tx_id = tx_obj["tx_id"]
                        acct_id = tx_obj["account_id"]
                        cp_id = tx_obj["counterparty_id"]
                        amt = tx_obj["amount_cents"]
                        ts = tx_obj["ts"]

                        g_pos, sanction_hop = state.graph.insert_and_query(
                            ts,
                            acct_id,
                            cp_id,
                            sanctioned,
                            SLIDING_WINDOW_SECONDS,
                        )
                        graph_undo_log.append(g_pos)

                        tracker = state.accounts.get(acct_id)
                        if tracker is None:
                            tracker = AccountWindowTracker()
                            state.accounts[acct_id] = tracker
                            created_accounts.append(acct_id)

                        w_pos, win_cnt, win_sum, win_uniq_cps, win_med = tracker.insert_and_measure(
                            ts,
                            amt,
                            cp_id,
                            SLIDING_WINDOW_SECONDS,
                        )
                        window_undo_log.append((tracker, w_pos))

                        if win_sum > INT64_MAX:
                            raise ValueError("Sliding window amount sum exceeds 64-bit integer limit")

                        risk_score, decision, reasons = compute_single_tx_decision(
                            tx_obj,
                            policy,
                            win_tx_count=win_cnt,
                            win_amount_cents=win_sum,
                            win_unique_cps=win_uniq_cps,
                            win_median_cents=win_med,
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

                        dec_id = f"dec_{tx_id}"
                        tx_insert_rows.append(
                            (
                                tx_id,
                                tenant_id,
                                clean_batch_id,
                                acct_id,
                                cp_id,
                                amt,
                                tx_obj["currency"],
                                tx_obj["channel"],
                                tx_obj["contact_email"],
                                ts,
                                meta_json,
                            )
                        )
                        dec_insert_rows.append(
                            (
                                dec_id,
                                tx_id,
                                tenant_id,
                                acct_id,
                                risk_score,
                                decision,
                                win_cnt,
                                win_sum,
                                win_uniq_cps,
                                win_med,
                                sanction_hop,
                                json.dumps(reasons),
                                ts,
                            )
                        )

                        counts[decision] += 1
                        results.append(
                            {
                                "decision_id": dec_id,
                                "tx_id": tx_id,
                                "account_id": acct_id,
                                "risk_score": risk_score,
                                "decision": decision,
                                "sanction_hop": sanction_hop,
                                "alert_dispatched": alert_dispatched,
                                "window": {
                                    "tx_count": win_cnt,
                                    "amount_cents": win_sum,
                                    "unique_counterparties": win_uniq_cps,
                                    "median_cents": win_med,
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
                        conn.execute(
                            "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                            "WHERE tenant_id = ? AND quota_type = ?",
                            (alert_rem, last_alert_ts, tenant_id, ALERT_QUOTA_BUCKET),
                        )
            except BaseException as exc:
                # 严格按逆序回滚内存滑窗与三跳传染图（SQLite 事务与告警配额已由 write_transaction 原子 ROLLBACK）
                for tracker, w_pos in reversed(window_undo_log):
                    tracker.undo_insert(w_pos)
                for acct_id in created_accounts:
                    trk = state.accounts.get(acct_id)
                    if trk is not None and not trk.ts_list:
                        del state.accounts[acct_id]
                for g_pos in reversed(graph_undo_log):
                    state.graph.undo_insert(g_pos)

                if isinstance(exc, sqlite3.IntegrityError):
                    raise ValueError("Transaction primary key conflict") from exc
                raise

    return {
        "tenant_id": tenant_id,
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

    with borrow_connection(db_path) as conn:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
            (clean_id, caller.tenant_id),
        ).fetchone()
    if not row:
        raise LookupError(f"Decision record not found: {clean_id}")

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
