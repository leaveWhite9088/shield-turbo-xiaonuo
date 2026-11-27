# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数、统一偏序四重原子事务与安全规则树引擎。"""
from __future__ import annotations

from functools import lru_cache
import json
import math
import re
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    SANCTION_HOP_SCORES,
)
from .contagion_graph import TenantContagionGraph, get_sanctioned_entities
from .legacy_compat import apply_sovereign_settlement_adjustment
from .middleware import parse_strict_finite_number, parse_strict_int
from .runtime import GatewayRuntime, get_runtime
from .window_stats import AccountSlidingWindow

# 线性无回溯邮箱校验正则（与原合法格式 100% 等价，彻底消除嵌套量词 ReDoS）
_EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$")
_EMAIL_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")
MAX_EMAIL_LEN = 254

MAX_RULE_DEPTH = 16
MAX_RULE_NODES = 128
MAX_RULE_IN_LEN = 100
MAX_REGEX_LEN = 128
MAX_REGEX_TARGET_LEN = 1024
MAX_REGEX_BRACE_BOUND = 20
MAX_BATCH_SIZE = 2000


def validate_contact_email(email: str) -> bool:
    """O(|s|) 线性无回溯邮箱格式校验。"""
    if not isinstance(email, str) or not email or len(email) > MAX_EMAIL_LEN:
        return False
    at_pos = email.find("@")
    if at_pos <= 0 or at_pos != email.rfind("@"):
        return False
    local = email[:at_pos]
    domain = email[at_pos + 1:]
    if not (1 <= len(local) <= 64) or not (1 <= len(domain) <= 253):
        return False
    return _EMAIL_LOCAL_RE.match(local) is not None and _EMAIL_DOMAIN_RE.match(domain) is not None


def _parse_brace_quantifier(pattern: str, start: int) -> tuple[int, int, int | None] | None:
    """若 pattern[start:] 为合法花括号量词 {m} / {m,} / {m,n}，返回 (end_pos, min_rep, max_rep_or_None)。"""
    n = len(pattern)
    if start >= n or pattern[start] != "{":
        return None
    j = start + 1
    while j < n and pattern[j].isdigit():
        j += 1
    if j == start + 1:
        return None
    m_str = pattern[start + 1: j]
    if j < n and pattern[j] == "}":
        m_val = int(m_str)
        return j + 1, m_val, m_val
    if j < n and pattern[j] == ",":
        k = j + 1
        while k < n and pattern[k].isdigit():
            k += 1
        if k < n and pattern[k] == "}":
            m_val = int(m_str)
            n_val = int(pattern[j + 1: k]) if k > j + 1 else None
            return k + 1, m_val, n_val
    return None


@lru_cache(maxsize=256)
def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    """静态审查并编译安全正则：毫秒级拦截嵌套量词、反向引用、大上界花括号、重叠交替与相邻通配链。"""
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("Regex pattern must be a non-empty string")
    if len(pattern) > MAX_REGEX_LEN:
        raise ValueError(f"Regex pattern exceeds maximum length ({MAX_REGEX_LEN})")

    n = len(pattern)
    i = 0
    in_char_class = False
    # 分组栈：每层记录 [has_quantifier, has_alternation]
    group_stack: list[list[bool]] = [[False, False]]
    last_atom_was_group: list[bool] | None = None
    last_atom_was_dot = False
    last_atom_was_quant = False
    # 相邻可变重复检测：记录上一已完成单元是否带可变重复量词，以及之后未经量词修饰的原子数
    prev_unit_var_repeat = False
    atoms_since_var_repeat = 0
    wildcard_repeat_count = 0

    while i < n:
        ch = pattern[i]
        if in_char_class:
            if ch == "\\":
                i += 2
                continue
            if ch == "]":
                in_char_class = False
                last_atom_was_group = None
                last_atom_was_dot = False
                last_atom_was_quant = False
                atoms_since_var_repeat += 1
            i += 1
            continue

        if ch == "\\":
            if i + 1 >= n:
                raise ValueError("Invalid trailing escape in regex")
            nxt = pattern[i + 1]
            # 拒绝反向引用 \1..\9 与八进制回溯混淆
            if nxt.isdigit() and nxt != "0":
                raise ValueError("Backreferences are not allowed in regex")
            last_atom_was_group = None
            last_atom_was_dot = False
            last_atom_was_quant = False
            atoms_since_var_repeat += 1
            i += 2
            continue

        if ch == "[":
            in_char_class = True
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue

        if ch == "(":
            if i + 1 < n and pattern[i + 1] == "?":
                # 仅允许非捕获分组 (?:...)，禁止环视、命名反向引用 (?P=...)、条件与内联修饰炸弹
                if pattern[i + 1: i + 3] == "?:":
                    i += 3
                else:
                    raise ValueError("Advanced regex group constructs (lookaround/backref/flags) are disallowed")
            else:
                i += 1
            group_stack.append([False, False])
            last_atom_was_group = None
            last_atom_was_dot = False
            last_atom_was_quant = False
            prev_unit_var_repeat = False
            atoms_since_var_repeat = 0
            continue

        if ch == ")":
            if len(group_stack) <= 1:
                raise ValueError("Unbalanced closing parenthesis in regex")
            closed = group_stack.pop()
            parent = group_stack[-1]
            if closed[0]:
                parent[0] = True
            if closed[1]:
                parent[1] = True
            last_atom_was_group = closed
            last_atom_was_dot = False
            last_atom_was_quant = False
            atoms_since_var_repeat += 1
            i += 1
            continue

        if ch == "|":
            group_stack[-1][1] = True
            last_atom_was_group = None
            last_atom_was_dot = False
            last_atom_was_quant = False
            prev_unit_var_repeat = False
            atoms_since_var_repeat = 0
            i += 1
            continue

        # 检测量词：* + ? {m,n}
        is_quant = False
        is_repeating = False
        is_variable = False
        next_i = i + 1

        if ch in ("*", "+"):
            is_quant = True
            is_repeating = True
            is_variable = True
        elif ch == "?":
            is_quant = True
            is_repeating = False
            is_variable = True
        elif ch == "{":
            parsed = _parse_brace_quantifier(pattern, i)
            if parsed is not None:
                next_i, m_val, max_val = parsed
                if m_val > MAX_REGEX_BRACE_BOUND or (max_val is not None and max_val > MAX_REGEX_BRACE_BOUND):
                    raise ValueError(f"Regex repetition bound exceeds limit ({MAX_REGEX_BRACE_BOUND})")
                if max_val is not None and max_val < m_val:
                    raise ValueError("Invalid regex repetition range")
                if max_val is None and last_atom_was_group is not None:
                    raise ValueError("Unbounded brace repetition on group is disallowed")
                is_quant = True
                is_repeating = max_val is None or max_val > 1
                is_variable = max_val is None or max_val != m_val

        if is_quant:
            # 跳过惰性修饰符 ?
            if next_i < n and pattern[next_i] == "?":
                next_i += 1
            if last_atom_was_quant:
                raise ValueError("Stacked quantifiers in regex are disallowed")
            if is_repeating:
                if last_atom_was_group is not None:
                    if last_atom_was_group[0]:
                        raise ValueError("Nested quantifiers in regex are disallowed (ReDoS protection)")
                    if last_atom_was_group[1]:
                        raise ValueError("Repeated alternation group in regex is disallowed (ReDoS protection)")
                if last_atom_was_dot:
                    wildcard_repeat_count += 1
                    if wildcard_repeat_count > 2:
                        raise ValueError("Excessive wildcard repetitions in regex are disallowed (ReDoS protection)")
                group_stack[-1][0] = True
            if is_variable and is_repeating:
                if prev_unit_var_repeat and atoms_since_var_repeat <= 1:
                    raise ValueError("Adjacent variable quantifiers in regex are disallowed (ReDoS protection)")
                prev_unit_var_repeat = True
                atoms_since_var_repeat = 0
            last_atom_was_group = None
            last_atom_was_dot = False
            last_atom_was_quant = True
            i = next_i
            continue

        # 普通字符字面量、通配点或锚点
        if ch not in ("^", "$"):
            atoms_since_var_repeat += 1
        last_atom_was_group = None
        last_atom_was_dot = ch == "."
        last_atom_was_quant = False
        i += 1

    if in_char_class or len(group_stack) != 1:
        raise ValueError("Unbalanced brackets or parentheses in regex")

    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex syntax: {exc}") from exc


def validate_rule_tree(node: dict[str, Any]) -> None:
    """迭代式静态校验自定义规则树（深度上限、节点总数上限、合法算子、安全正则与严格数值边界）。"""
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    stack: list[tuple[Any, int]] = [(node, 1)]
    node_count = 0
    while stack:
        curr, depth = stack.pop()
        if not isinstance(curr, dict):
            raise ValueError("Rule node must be an object")
        node_count += 1
        if node_count > MAX_RULE_NODES:
            raise ValueError(f"Rule tree exceeds maximum node limit ({MAX_RULE_NODES})")
        if depth > MAX_RULE_DEPTH:
            raise ValueError(f"Rule tree exceeds maximum nesting depth ({MAX_RULE_DEPTH})")

        op = str(curr.get("op") or "").upper()
        if "bonus_score" in curr and curr["bonus_score"] is not None:
            parse_strict_int(curr["bonus_score"], "bonus_score", min_val=-1000, max_val=1000)

        if op in ("AND", "OR", "NOT"):
            children = curr.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            if len(children) > 64:
                raise ValueError("Logical node has too many children")
            for ch in children:
                stack.append((ch, depth + 1))
            continue

        field_name = str(curr.get("field") or "")
        if not field_name or len(field_name) > 128:
            raise ValueError("Leaf rule node missing valid 'field'")

        target = curr.get("value")
        if op in ("EQ", "NEQ"):
            if isinstance(target, float) and not math.isfinite(target):
                raise ValueError("Rule comparison value must be finite")
        elif op in ("GT", "GTE", "LT", "LTE"):
            parse_strict_finite_number(target, "rule value")
        elif op == "IN":
            if not isinstance(target, list) or len(target) > MAX_RULE_IN_LEN:
                raise ValueError(f"IN operator requires a list with <= {MAX_RULE_IN_LEN} items")
        elif op == "CONTAINS":
            if target is not None and not isinstance(target, str):
                raise ValueError("CONTAINS target must be a string")
        elif op == "REGEX":
            if not isinstance(target, str):
                raise ValueError("REGEX target must be a string")
            _compile_safe_regex(target)
        else:
            raise ValueError(f"Unsupported rule operator: {op}")


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    rt = get_runtime(db_path)
    with rt.policy_lock(tenant_id):
        cached = rt.policy_cache.get(tenant_id)
        if cached is not None:
            return dict(cached)
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
        rt.policy_cache[tenant_id] = policy
        return dict(policy)


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy updates must be an object")

    rt = get_runtime(db_path)
    with rt.policy_lock(caller.tenant_id):
        current = load_tenant_policy(db_path, caller.tenant_id)
        high_amt = parse_strict_int(
            updates.get("high_amount_cents", current["high_amount_cents"]),
            "high_amount_cents",
            min_val=1,
        )
        vel_tx = parse_strict_int(
            updates.get("velocity_tx_limit", current["velocity_tx_limit"]),
            "velocity_tx_limit",
            min_val=1,
        )
        vel_amt = parse_strict_int(
            updates.get("velocity_amount_cents", current["velocity_amount_cents"]),
            "velocity_amount_cents",
            min_val=1,
        )
        fanout = parse_strict_int(
            updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]),
            "counterparty_fanout_limit",
            min_val=1,
        )
        rev_th = parse_strict_int(
            updates.get("review_threshold", current["review_threshold"]),
            "review_threshold",
            min_val=1,
            max_val=100,
        )
        rej_th = parse_strict_int(
            updates.get("reject_threshold", current["reject_threshold"]),
            "reject_threshold",
            min_val=rev_th,
            max_val=100,
        )
        custom_rules = updates.get("custom_rules", current["custom_rules"])
        if not isinstance(custom_rules, dict):
            raise ValueError("custom_rules must be a JSON object")
        if custom_rules:
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
        rt.policy_cache[caller.tenant_id] = updated_policy
        rt.epochs(caller.tenant_id).policy_epoch += 1
        return dict(updated_policy)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata")
        if not isinstance(meta, dict):
            return None
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
    if depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree exceeds maximum nesting depth ({MAX_RULE_DEPTH})")
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError(f"Rule tree exceeds maximum node limit ({MAX_RULE_NODES})")

    op = str(node.get("op") or "").upper()
    raw_bonus = node.get("bonus_score")
    bonus = parse_strict_int(raw_bonus, "bonus_score", default=0, min_val=-1000, max_val=1000)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")

        child_results = [
            _eval_rule_node_bounded(ch, tx, depth=depth + 1, budget=budget)
            for ch in children
        ]
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

    field_name = str(node.get("field") or "")
    if not field_name:
        raise ValueError("Leaf rule node missing 'field'")
    actual = _extract_field(tx, field_name)
    target = node.get("value")

    matched = False
    if op == "EQ":
        matched = (type(actual) is type(target) or (not isinstance(actual, bool) and not isinstance(target, bool))) and actual == target
    elif op == "NEQ":
        matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        target_num = parse_strict_finite_number(target, "rule value")
        if actual is not None and not isinstance(actual, bool) and isinstance(actual, (int, float)):
            actual_num = float(actual)
            if math.isfinite(actual_num):
                if op == "GT":
                    matched = actual_num > target_num
                elif op == "GTE":
                    matched = actual_num >= target_num
                elif op == "LT":
                    matched = actual_num < target_num
                else:
                    matched = actual_num <= target_num
    elif op == "IN":
        matched = isinstance(target, list) and len(target) <= MAX_RULE_IN_LEN and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if not isinstance(target, str):
            raise ValueError("REGEX target must be a string")
        compiled = _compile_safe_regex(target)
        if isinstance(actual, str):
            if len(actual) > MAX_REGEX_TARGET_LEN:
                raise ValueError(f"REGEX target field exceeds length limit ({MAX_REGEX_TARGET_LEN})")
            matched = compiled.search(actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    return _eval_rule_node_bounded(node, tx, depth=1, budget=[MAX_RULE_NODES])


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    if "amount_cents" in sample_tx and sample_tx["amount_cents"] is not None:
        parse_strict_int(sample_tx["amount_cents"], "amount_cents", min_val=0)
    if "ts" in sample_tx and sample_tx["ts"] is not None:
        parse_strict_int(sample_tx["ts"], "ts", min_val=0)
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


class _TenantRiskState:
    """租户级内存风控状态：聚合各账户 24h 动态滑窗与 3 跳资金传染图。"""

    __slots__ = ("accounts", "graph")

    def __init__(self) -> None:
        self.accounts: dict[str, AccountSlidingWindow] = {}
        self.graph = TenantContagionGraph()

    @classmethod
    def load_from_conn(cls, conn: sqlite3.Connection, tenant_id: str) -> "_TenantRiskState":
        state = cls()
        per_acct: dict[str, list[tuple[int, int, str]]] = {}
        all_edges: list[tuple[int, str, str]] = []
        cur = conn.execute(
            "SELECT account_id, counterparty_id, amount_cents, ts "
            "FROM transactions WHERE tenant_id = ? ORDER BY ts ASC, rowid ASC",
            (tenant_id,),
        )
        while True:
            rows = cur.fetchmany(512)
            if not rows:
                break
            for r in rows:
                acct = str(r["account_id"])
                cp = str(r["counterparty_id"])
                amt = int(r["amount_cents"])
                ts = int(r["ts"])
                per_acct.setdefault(acct, []).append((ts, amt, cp))
                all_edges.append((ts, acct, cp))

        for acct, entries in per_acct.items():
            win = AccountSlidingWindow()
            win.load_sorted_entries(entries)
            state.accounts[acct] = win
        state.graph.load_sorted_edges(all_edges)
        return state

    def get_account_window(self, account_id: str) -> AccountSlidingWindow:
        win = self.accounts.get(account_id)
        if win is None:
            win = AccountSlidingWindow()
            self.accounts[account_id] = win
        return win


def _ensure_risk_state(rt: GatewayRuntime, conn: sqlite3.Connection, tenant_id: str) -> _TenantRiskState:
    state: _TenantRiskState | None = rt.risk_states.get(tenant_id)
    if state is None:
        state = _TenantRiskState.load_from_conn(conn, tenant_id)
        rt.risk_states[tenant_id] = state
    return state


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次，以统一偏序锁实现数据库+滑窗+传染图+告警配额池四位一体强原子提交/回滚。"""
    norm_batch_id = str(batch_id or "").strip()
    if not norm_batch_id or len(norm_batch_id) > 128 or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > MAX_BATCH_SIZE:
        raise ValueError(f"Batch size exceeds maximum limit ({MAX_BATCH_SIZE})")

    # 阶段 0：无副作用全量输入预校验（任一笔不合法立即 400 拒绝，不获取任何写锁、零状态变更）
    prepared_txs: list[dict[str, Any]] = []
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

        amount_cents = parse_strict_int(item.get("amount_cents"), "amount_cents", min_val=1)
        ts = parse_strict_int(item.get("ts"), "ts", min_val=1)
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")

        raw_meta = item.get("metadata")
        if raw_meta is None:
            metadata: dict[str, Any] = {}
        elif isinstance(raw_meta, dict):
            metadata = raw_meta
        else:
            raise ValueError(f"Invalid metadata in transaction {tx_id}")

        prepared_txs.append(
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

    tenant_id = caller.tenant_id
    rt = get_runtime(db_path)

    # 读取最新租户策略与受制裁实体快照
    policy = load_tenant_policy(db_path, tenant_id)
    sanctioned = get_sanctioned_entities(db_path, tenant_id)

    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

    # 阶段 1 & 2：严格全局锁偏序 Level 1 (risk_lock) -> Level 2 (quota_lock) -> Level 3 (BEGIN IMMEDIATE)
    with rt.risk_lock(tenant_id):
        with rt.acquire_quota_locks(tenant_id, (ALERT_QUOTA_BUCKET,)):
            # 再次刷新策略与黑名单，防止等锁期间变更
            policy = load_tenant_policy(db_path, tenant_id)
            sanctioned = get_sanctioned_entities(db_path, tenant_id)

            added_by_acct: dict[str, list[tuple[int, int, str]]] = {}
            added_edges: list[tuple[int, str, str]] = []
            risk_state: _TenantRiskState | None = None

            try:
                with rt.write_tx() as conn:
                    risk_state = _ensure_risk_state(rt, conn, tenant_id)

                    q_row = conn.execute(
                        "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                        (tenant_id, ALERT_QUOTA_BUCKET),
                    ).fetchone()
                    alert_rem = int(q_row["remaining_quota"]) if q_row else 0
                    alert_consumed_total = 0
                    last_alert_ts = 0

                    for tx_obj in prepared_txs:
                        tx_id = tx_obj["tx_id"]
                        account_id = tx_obj["account_id"]
                        counterparty_id = tx_obj["counterparty_id"]
                        amount_cents = tx_obj["amount_cents"]
                        ts = tx_obj["ts"]

                        # 1) 动态三跳制裁传染图计算并增量入图
                        sanction_hop = risk_state.graph.query_and_push(
                            account_id,
                            counterparty_id,
                            ts,
                            sanctioned,
                        )
                        added_edges.append((ts, account_id, counterparty_id))

                        # 2) 动态滑动窗口精确四维指标（含双堆中位数 + 乱序回退）并增量入窗
                        acct_win = risk_state.get_account_window(account_id)
                        win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                            acct_win.query_and_push(ts, amount_cents, counterparty_id)
                        )
                        added_by_acct.setdefault(account_id, []).append(
                            (ts, amount_cents, counterparty_id)
                        )

                        # 3) 计算风控评分与决策（完整保留主权豁免等全部业务规则）
                        risk_score, decision, reasons = compute_single_tx_decision(
                            tx_obj,
                            policy,
                            win_tx_count=win_tx_count,
                            win_amount_cents=win_amount_cents,
                            win_unique_cps=win_unique_cps,
                            win_median_cents=win_median_cents,
                            sanction_hop=sanction_hop,
                        )

                        # 4) REJECT 实时告警配额联动（同事务暂扣，异常自动随 DB 事务整体回滚）
                        alert_dispatched = False
                        if decision == "REJECT":
                            if alert_rem >= 1:
                                alert_rem -= 1
                                alert_consumed_total += 1
                                last_alert_ts = ts
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
                                norm_batch_id,
                                account_id,
                                counterparty_id,
                                amount_cents,
                                tx_obj["currency"],
                                tx_obj["channel"],
                                tx_obj["contact_email"],
                                ts,
                                json.dumps(tx_obj["metadata"], sort_keys=True, allow_nan=False),
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

                    # 批次结束统一落盘本批次消耗的 REALTIME_ALERT_POOL 配额
                    if alert_consumed_total > 0:
                        conn.execute(
                            "UPDATE tenant_quotas SET remaining_quota = ?, updated_at = ? "
                            "WHERE tenant_id = ? AND quota_type = ?",
                            (alert_rem, last_alert_ts, tenant_id, ALERT_QUOTA_BUCKET),
                        )
            except BaseException as exc:
                # 四位一体强原子回滚：write_tx 已回滚 SQLite（含 transactions/risk_decisions/REALTIME_ALERT_POOL），
                # 此处精确回滚内存滑动窗口与三跳传染图，确保零内存污染！
                if risk_state is not None:
                    if added_edges:
                        risk_state.graph.rollback_edges(added_edges)
                    for acct_id, added_entries in added_by_acct.items():
                        acct_win = risk_state.accounts.get(acct_id)
                        if acct_win is not None:
                            acct_win.rollback_entries(added_entries)
                if isinstance(exc, sqlite3.IntegrityError):
                    raise ValueError("Batch rejected due to duplicate transaction ID or constraint violation") from exc
                raise

    return {
        "tenant_id": tenant_id,
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
    """查询本租户下的单笔风控决策完整详情（强制 tenant_id 隔离，杜绝跨租户 IDOR）。"""
    dec_id = str(decision_id or "").strip()
    if not dec_id or len(dec_id) > 128:
        raise ValueError("Valid decision_id is required")

    rt = get_runtime(db_path)
    with rt.read_conn() as conn:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
            (dec_id, caller.tenant_id),
        ).fetchone()
    if not row:
        raise LookupError(f"Decision record not found: {dec_id}")

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
