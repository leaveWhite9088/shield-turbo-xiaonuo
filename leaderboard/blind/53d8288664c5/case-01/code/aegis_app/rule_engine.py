# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections import deque
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    CHANNEL_RISK_WEIGHTS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import _load_sanctioned_set
from .db import open_connection
from .epoch_cache import CACHE_MISS, EpochScopedCache, bump_epoch, epoch_token
from .ledger_ops import try_consume_realtime_alert_quota
from .legacy_compat import apply_sovereign_settlement_adjustment
from .window_stats import compute_exact_median_cents

# 注：本地部分已线性化去嵌套量词 —— `(A S*)+`（A=字母数字串，S=单分隔符+字母数字串）
# 的语言与 `A(S)*` 严格等价（多次外层迭代拼接处无分隔符，恒可归一为单次迭代），
# 匹配结果与原版完全一致，但对 "aaaa...!" 型恶意回溯输入为线性时间。
PARTNER_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@"
    r"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"
)
_EMAIL_MAX_LEN = 254


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email:
        return False
    if len(email) > _EMAIL_MAX_LEN:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


_policy_cache = EpochScopedCache("tenant_policy", 256)


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    """按 policy 纪元缓存租户风控策略（update_tenant_policy 提交后立即 bump 失效）。"""
    db_key = str(db_path)
    token = epoch_token(db_path, "policy")
    hit = _policy_cache.get(db_key, token, tenant_id)
    if hit is not CACHE_MISS:
        return hit
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
    _policy_cache.put(db_key, token, tenant_id, policy)
    return policy


def _strict_policy_int(raw: Any, label: str) -> int:
    """策略阈值严格整数守卫：拒绝 bool / 非整数 / 超 64 位数值。"""
    if isinstance(raw, bool):
        raise ValueError(f"Invalid policy threshold value for {label}")
    if isinstance(raw, int):
        num = raw
    elif isinstance(raw, str) and len(raw) <= 32:
        try:
            num = int(raw)
        except ValueError:
            raise ValueError(f"Invalid policy threshold value for {label}") from None
    else:
        raise ValueError(f"Invalid policy threshold value for {label}")
    if num < _INT64_MIN or num > _INT64_MAX:
        raise ValueError(f"Policy threshold out of 64-bit range for {label}")
    return num


def _validate_rule_tree_structure(
    node: Any,
    depth: int = 0,
    budget: list[int] | None = None,
) -> None:
    """策略热更新前的规则树结构预检：深度/节点预算、算子、正则编译与数值操作数守卫。"""
    if budget is None:
        budget = [_RULE_TREE_MAX_NODES]
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if depth > _RULE_TREE_MAX_DEPTH:
        raise ValueError("Rule tree nesting exceeds maximum allowed depth")
    if budget[0] <= 0:
        raise ValueError("Rule tree node budget exhausted")
    budget[0] -= 1

    op = str(node.get("op") or "").upper()
    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")
        for ch in children:
            _validate_rule_tree_structure(ch, depth + 1, budget)
        return

    if not str(node.get("field") or ""):
        raise ValueError("Leaf rule node missing 'field'")
    if op in ("GT", "GTE", "LT", "LTE"):
        _coerce_rule_number(node.get("value"), str(node.get("field")))
    elif op == "REGEX":
        target = node.get("value")
        if isinstance(target, str):
            _compile_guarded_rule_regex(target)
    elif op not in ("EQ", "NEQ", "IN", "CONTAINS"):
        raise ValueError(f"Unsupported rule operator: {op}")


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = _strict_policy_int(updates.get("high_amount_cents", current["high_amount_cents"]), "high_amount_cents")
    vel_tx = _strict_policy_int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]), "velocity_tx_limit")
    vel_amt = _strict_policy_int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]), "velocity_amount_cents")
    fanout = _strict_policy_int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]), "counterparty_fanout_limit")
    rev_th = _strict_policy_int(updates.get("review_threshold", current["review_threshold"]), "review_threshold")
    rej_th = _strict_policy_int(updates.get("reject_threshold", current["reject_threshold"]), "reject_threshold")
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    # 热更新前预检自定义规则树：非法算子 / 炸弹正则 / 超深超宽一律 400 拒绝。
    _validate_rule_tree_structure(custom_rules)

    new_ver = int(current["policy_version"]) + 1
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
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
    # 策略热更新提交后立即提升 policy 纪元，风控评估路径零脏读即时生效。
    bump_epoch(db_path, "policy")
    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


# ---------------------------------------------------------------------------
# 规则树求值安全预算与抗复杂度炸弹熔断常量
# ---------------------------------------------------------------------------
_RULE_TREE_MAX_DEPTH = 32
_RULE_TREE_MAX_NODES = 2000
_REGEX_PATTERN_MAX_LEN = 256
_REGEX_REPETITION_MAX = 64
_REGEX_SUBJECT_MAX_LEN = 10_000
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1

_REGEX_BACKREF_RE = re.compile(r"\\[0-9]|\\g")
_REGEX_BRACE_RE = re.compile(r"\{(\d+)(,(\d*))?\}")
_REGEX_INNER_QUANT_RE = re.compile(r"[*+?]|\{\d")
_regex_compile_lock = threading.Lock()
_regex_compile_cache: dict[str, Any] = {}
_REGEX_CACHE_MAX = 512


def _coerce_rule_number(value: Any, field_label: str) -> float:
    """严格数值操作数守卫：拒绝 bool 混淆、NaN/Inf、超 64 位整数与非数值字符串。"""
    if isinstance(value, bool):
        raise ValueError(f"Boolean operand is not allowed in numeric rule comparison: {field_label}")
    if isinstance(value, int):
        if value < _INT64_MIN or value > _INT64_MAX:
            raise ValueError(f"Integer operand out of 64-bit range in rule comparison: {field_label}")
        return float(value)
    if isinstance(value, float):
        num = value
    elif isinstance(value, str) and len(value) <= 64:
        try:
            num = float(value)
        except ValueError:
            raise ValueError(f"Non-numeric operand in rule comparison: {field_label}") from None
    else:
        raise ValueError(f"Unsupported numeric operand type in rule comparison: {field_label}")
    if num != num or num in (float("inf"), float("-inf")):
        raise ValueError(f"Non-finite number in rule comparison: {field_label}")
    return num


def _split_top_level_alternation(content: str) -> list[str] | None:
    """按深度 0 的 '|' 切分交替分支；无交替时返回 None。"""
    branches: list[str] = []
    depth = 0
    in_class = False
    seg_start = 0
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            i += 1
            continue
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            i += 1
            continue
        if ch == "|" and depth == 0:
            branches.append(content[seg_start:i])
            seg_start = i + 1
        i += 1
    branches.append(content[seg_start:])
    return branches if len(branches) > 1 else None


def _collect_group_contents(content: str) -> list[str]:
    """收集 content 自身及其中全部括号子表达式的内容文本（跳过字符类与转义）。"""
    results = [content]
    starts: list[int] = []
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            j = i + 1
            if j < n and content[j] == "^":
                j += 1
            if j < n and content[j] == "]":
                j += 1
            while j < n and content[j] != "]":
                if content[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            continue
        if ch == "(":
            starts.append(i)
            i += 1
            if i < n and content[i] == "?":
                i += 1
            continue
        if ch == ")" and starts:
            s = starts.pop()
            results.append(content[s + 1 : i])
            i += 1
            continue
        i += 1
    return results


def _reject_ambiguous_quantified_group(content: str) -> None:
    """量词修饰分组的安全熔断：内嵌量词、空交替分支与前缀歧义交替均拒绝。"""
    if _REGEX_INNER_QUANT_RE.search(content):
        raise ValueError("Rule REGEX pattern contains nested quantifiers")
    for group_text in _collect_group_contents(content):
        branches = _split_top_level_alternation(group_text)
        if branches is None:
            continue
        if len(branches) > 64:
            raise ValueError("Rule REGEX pattern contains too many alternation branches under quantifier")
        if any(b == "" for b in branches):
            raise ValueError("Rule REGEX pattern contains empty alternation branch under quantifier")
        for x in branches:
            for y in branches:
                if x != y and y.startswith(x):
                    raise ValueError("Rule REGEX pattern contains prefix-ambiguous alternation under quantifier")


def _reject_nested_quantifiers(pattern: str) -> None:
    """结构性防回溯熔断：拒绝嵌套量词、相邻叠量词及大上界有界重复。"""
    stack: list[list] = [[False, 0]]
    pending_group: str | None = None
    prev_was_quantifier = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            prev_was_quantifier = False
            pending_group = None
            continue
        if ch == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                if pattern[j] == "\\":
                    j += 1
                j += 1
            i = j + 1
            prev_was_quantifier = False
            pending_group = None
            continue
        if ch == "(":
            i += 1
            if i < n and pattern[i] == "?":
                i += 1
            stack.append([False, i])
            prev_was_quantifier = False
            pending_group = None
            continue
        if ch == ")":
            if len(stack) > 1:
                frame = stack.pop()
                if frame[0]:
                    stack[-1][0] = True
                pending_group = pattern[frame[1] : i]
            else:
                pending_group = None
            i += 1
            prev_was_quantifier = False
            continue
        if ch in "*+":
            if prev_was_quantifier:
                raise ValueError("Rule REGEX pattern contains stacked quantifiers")
            if pending_group is not None:
                _reject_ambiguous_quantified_group(pending_group)
            stack[-1][0] = True
            i += 1
            prev_was_quantifier = True
            pending_group = None
            continue
        if ch == "?":
            if not prev_was_quantifier:
                if pending_group is not None:
                    _reject_ambiguous_quantified_group(pending_group)
                stack[-1][0] = True
            i += 1
            prev_was_quantifier = True
            pending_group = None
            continue
        if ch == "{":
            m = _REGEX_BRACE_RE.match(pattern, i)
            if m is not None:
                if prev_was_quantifier:
                    raise ValueError("Rule REGEX pattern contains stacked quantifiers")
                if pending_group is not None:
                    _reject_ambiguous_quantified_group(pending_group)
                stack[-1][0] = True
                i = m.end()
                prev_was_quantifier = True
                pending_group = None
                continue
            i += 1
            prev_was_quantifier = False
            pending_group = None
            continue
        i += 1
        prev_was_quantifier = False
        pending_group = None
    return


def _validate_rule_regex_pattern(pattern: str) -> Any:
    """校验并编译用户可控正则：长度/反向引用/大上界/嵌套量词结构性熔断，非法模式一律 400。"""
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("Rule REGEX pattern must be a non-empty string")
    if len(pattern) > _REGEX_PATTERN_MAX_LEN:
        raise ValueError("Rule REGEX pattern exceeds maximum length")
    if _REGEX_BACKREF_RE.search(pattern):
        raise ValueError("Rule REGEX backreferences are not allowed")
    for m in _REGEX_BRACE_RE.finditer(pattern):
        lo = int(m.group(1))
        if lo > _REGEX_REPETITION_MAX:
            raise ValueError("Rule REGEX bounded repetition lower bound exceeds limit")
        hi_s = m.group(3)
        if hi_s and int(hi_s) > _REGEX_REPETITION_MAX:
            raise ValueError("Rule REGEX bounded repetition upper bound exceeds limit")
    _reject_nested_quantifiers(pattern)
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid rule REGEX pattern: {exc}") from exc


def _compile_guarded_rule_regex(pattern: str) -> Any:
    """带熔断校验与线程安全缓存的规则正则编译。"""
    with _regex_compile_lock:
        compiled = _regex_compile_cache.get(pattern)
    if compiled is not None:
        return compiled
    compiled = _validate_rule_regex_pattern(pattern)
    if len(_regex_compile_cache) < _REGEX_CACHE_MAX:
        with _regex_compile_lock:
            _regex_compile_cache[pattern] = compiled
    return compiled


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    """求值自定义布尔规则树（带深度 / 节点预算与抗回溯正则熔断，语义与原版一致）。"""
    return _eval_rule_node_bounded(node, tx, 0, [_RULE_TREE_MAX_NODES])


def _eval_rule_node_bounded(
    node: dict[str, Any],
    tx: dict[str, Any],
    depth: int,
    budget: list[int],
) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if depth > _RULE_TREE_MAX_DEPTH:
        raise ValueError("Rule tree nesting exceeds maximum allowed depth")
    if budget[0] <= 0:
        raise ValueError("Rule tree evaluation node budget exhausted")
    budget[0] -= 1

    op = str(node.get("op") or "").upper()
    bonus = int(node.get("bonus_score") or 0)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")

        child_results = [_eval_rule_node_bounded(ch, tx, depth + 1, budget) for ch in children]
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
        if actual is None:
            matched = False
        else:
            actual_num = _coerce_rule_number(actual, field_name)
            target_num = _coerce_rule_number(target, field_name)
            if op == "GT":
                matched = actual_num > target_num
            elif op == "GTE":
                matched = actual_num >= target_num
            elif op == "LT":
                matched = actual_num < target_num
            else:
                matched = actual_num <= target_num
    elif op == "IN":
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            if len(actual) > _REGEX_SUBJECT_MAX_LEN:
                matched = False
            else:
                matched = _compile_guarded_rule_regex(target).search(actual) is not None
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


_MAX_BATCH_TX_COUNT = 5000


def _contagion_hop_on_conn(
    conn: Any,
    db_path: str,
    tenant_id: str,
    account_id: str,
    counterparty_id: str,
    ts: int,
) -> int:
    """与 contagion_graph.compute_sanction_contagion_hop 语义严格一致的三跳传染计算，

    但在调用方已持有的 BEGIN IMMEDIATE 事务连接上执行区间扫边，使同批先序
    交易的未提交关联边即时纳入本批后续传染图（多源 BFS 深度 2 截断）。"""
    sanctioned = _load_sanctioned_set(db_path, tenant_id)
    if not sanctioned:
        return 0
    if account_id in sanctioned or counterparty_id in sanctioned:
        return 1

    win_start = ts - SLIDING_WINDOW_SECONDS
    rows = conn.execute(
        "SELECT account_id, counterparty_id FROM transactions "
        "WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
        (tenant_id, win_start, ts),
    ).fetchall()

    adj: dict[str, list[str]] = {}
    for r in rows:
        u = str(r["account_id"])
        v = str(r["counterparty_id"])
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    adj.setdefault(account_id, []).append(counterparty_id)
    adj.setdefault(counterparty_id, []).append(account_id)

    dist: dict[str, int] = {}
    queue: deque[str] = deque()
    for src in sanctioned:
        if src in adj and src not in dist:
            dist[src] = 0
            queue.append(src)
    while queue:
        curr = queue.popleft()
        d = dist[curr]
        if d >= 2:
            continue
        for nxt in adj.get(curr, ()):
            if nxt not in dist:
                dist[nxt] = d + 1
                queue.append(nxt)

    best_hop = 0
    for endpoint in (account_id, counterparty_id):
        if endpoint in dist:
            hop = dist[endpoint] + 1
            if 1 <= hop <= 3 and (best_hop == 0 or hop < best_hop):
                best_hop = hop
    return best_hop


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次并持久化交易及风控决策记录。

    四位一体强原子提交：单条 BEGIN IMMEDIATE 事务包裹全批「交易落库 + 风控决策 +
    滑动窗口读取 + 三跳传染图读取 + REALTIME_ALERT_POOL 告警扣减」，任一笔非法或
    主键冲突则整批回滚（零半截落盘、零配额泄漏、零内存污染）；同批先序交易经同
    事务连接即时纳入后续窗口与传染图；统一锁偏序首语句取写锁，与配额调拨/扣减
    路径零死锁。
    """
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > _MAX_BATCH_TX_COUNT:
        raise ValueError(f"Transaction batch exceeds maximum allowed size ({_MAX_BATCH_TX_COUNT})")

    tenant_id = caller.tenant_id
    policy = load_tenant_policy(db_path, tenant_id)

    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
    parsed: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()

    # 第一遍全量预校验：任一笔非法即整批拒绝，零数据库写入、零配额扣减。
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction in batch must be a JSON object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        amount_raw = item.get("amount_cents")
        ts_raw = item.get("ts")
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if isinstance(amount_raw, bool) or not isinstance(amount_raw, int):
            raise ValueError(f"Invalid amount_cents for tx_id={tx_id!r}")
        if isinstance(ts_raw, bool) or not isinstance(ts_raw, int):
            raise ValueError(f"Invalid ts for tx_id={tx_id!r}")
        if not tx_id or not account_id or not counterparty_id:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if not (0 < amount_raw <= _INT64_MAX) or not (0 < ts_raw <= _INT64_MAX):
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if tx_id in seen_tx_ids:
            raise ValueError(f"Duplicate tx_id within batch: {tx_id}")
        seen_tx_ids.add(tx_id)
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        parsed.append(
            {
                "tx_id": tx_id,
                "account_id": account_id,
                "counterparty_id": counterparty_id,
                "amount_cents": amount_raw,
                "currency": currency,
                "channel": channel,
                "contact_email": contact_email,
                "ts": ts_raw,
                "metadata": metadata,
            }
        )

    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for tx in parsed:
                tx_id = tx["tx_id"]
                account_id = tx["account_id"]
                counterparty_id = tx["counterparty_id"]
                amount_cents = tx["amount_cents"]
                currency = tx["currency"]
                channel = tx["channel"]
                contact_email = tx["contact_email"]
                ts = tx["ts"]
                metadata = tx["metadata"]

                # idx_tx_tenant_acct_ts 索引区间扫描：同连接可见同批先序未提交交易。
                win_start = ts - SLIDING_WINDOW_SECONDS
                hist_rows = conn.execute(
                    "SELECT counterparty_id, amount_cents, ts FROM transactions "
                    "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ?",
                    (tenant_id, account_id, win_start, ts),
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
                    cp_set.add(hr["counterparty_id"])

                win_unique_cps = len(cp_set)
                win_median_cents = compute_exact_median_cents(win_amounts_list)

                sanction_hop = _contagion_hop_on_conn(
                    conn, db_path, tenant_id, account_id, counterparty_id, ts
                )

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
                    if try_consume_realtime_alert_quota(db_path, tenant_id, ts, conn=conn):
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
                        tenant_id,
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
                        tenant_id,
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
        except sqlite3.IntegrityError as exc:
            # 主键冲突：整批四位一体强原子回滚（零半截落盘、零配额泄漏）。
            conn.rollback()
            raise ValueError(f"Duplicate primary key in transaction batch: {exc}") from exc
        except Exception:
            conn.rollback()
            raise
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
