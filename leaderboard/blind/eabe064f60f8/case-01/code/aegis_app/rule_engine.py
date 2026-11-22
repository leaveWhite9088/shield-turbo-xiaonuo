# -*- coding: utf-8 -*-
"""实时交易风控评分、滑动时间窗特征计算与自定义布尔规则树引擎。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, deque
import json
import re
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import CHANNEL_RISK_WEIGHTS, SLIDING_WINDOW_SECONDS
from .db import ConflictError, get_thread_connection
from .runtime import get_db_runtime

# 线性时间、无回溯邮箱校验（彻底消除原嵌套量词 ReDoS 漏洞，语义与原正则 100% 等价）
_EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$")
_EMAIL_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")
MAX_EMAIL_LENGTH = 254

# 规则树与正则抗 DoS 硬限制
MAX_RULE_DEPTH = 16
MAX_RULE_NODES = 128
MAX_RULE_CHILDREN = 32
MAX_IN_LIST_SIZE = 64
MAX_REGEX_LENGTH = 128
MAX_REGEX_INPUT_LENGTH = 1024
MAX_BATCH_SIZE = 2000

_QUANTIFIER_CHARS = frozenset("+*{")
_BACKREF_OR_LOOKAROUND_RE = re.compile(r"\\[1-9]|\(\?(?:P=|<=|<!|=|!)")
_LARGE_REPEAT_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")
_MULTI_WILDCARD_RE = re.compile(r"\.[*+].*\.[*+]")
_COMPILED_SAFE_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    at_pos = email.find("@")
    if at_pos <= 0 or at_pos != email.rfind("@"):
        return False
    local = email[:at_pos]
    domain = email[at_pos + 1 :]
    if not local or not domain:
        return False
    return _EMAIL_LOCAL_RE.match(local) is not None and _EMAIL_DOMAIN_RE.match(domain) is not None


def _has_nested_quantifier(pattern: str) -> bool:
    """静态检测正则表达式中是否存在嵌套量词（如 (a+)+、(a|aa)+、(a*)* 等灾难性回溯结构）。"""
    # 栈中每个元素记录当前括号层级内是否出现过量词或分支
    group_has_quant_or_alt: list[bool] = []
    i = 0
    n = len(pattern)
    in_char_class = False

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_char_class:
            if ch == "]":
                in_char_class = False
            i += 1
            continue
        if ch == "[":
            in_char_class = True
            i += 1
            continue
        if ch == "(":
            group_has_quant_or_alt.append(False)
            i += 1
            continue
        if ch == ")":
            inner_risky = group_has_quant_or_alt.pop() if group_has_quant_or_alt else False
            nxt = pattern[i + 1] if i + 1 < n else ""
            if nxt in _QUANTIFIER_CHARS:
                if inner_risky:
                    return True
                # 该分组自身带量词，向上传播给外层分组
                if group_has_quant_or_alt:
                    group_has_quant_or_alt[-1] = True
            elif inner_risky and group_has_quant_or_alt:
                group_has_quant_or_alt[-1] = True
            i += 1
            continue
        if ch in ("+", "*", "{", "|"):
            if group_has_quant_or_alt:
                group_has_quant_or_alt[-1] = True
        i += 1

    return False


def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("REGEX pattern must be a non-empty string")
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"REGEX pattern exceeds maximum length of {MAX_REGEX_LENGTH}")

    cached = _COMPILED_SAFE_REGEX_CACHE.get(pattern)
    if cached is not None:
        return cached

    if _BACKREF_OR_LOOKAROUND_RE.search(pattern):
        raise ValueError("Unsafe REGEX construct (backreference or lookaround) is forbidden")
    if _has_nested_quantifier(pattern):
        raise ValueError("Unsafe REGEX pattern with nested quantifier (ReDoS risk) rejected")
    if _MULTI_WILDCARD_RE.search(pattern):
        raise ValueError("Unsafe REGEX pattern with multiple unbounded wildcards rejected")

    for m in _LARGE_REPEAT_RE.finditer(pattern):
        low = int(m.group(1))
        high = int(m.group(2)) if (m.group(2) is not None and m.group(2) != "") else low
        if low > 50 or high > 50:
            raise ValueError("REGEX repetition bound exceeds safe limit (50)")

    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid REGEX pattern: {exc}") from exc

    if len(_COMPILED_SAFE_REGEX_CACHE) >= 512:
        _COMPILED_SAFE_REGEX_CACHE.clear()
    _COMPILED_SAFE_REGEX_CACHE[pattern] = compiled
    return compiled


def validate_rule_tree(node: dict[str, Any]) -> None:
    """静态校验规则树的深度、总节点数、扇出宽度与正则安全性，毫秒级拦截 DoS 畸形载荷。"""
    if not isinstance(node, dict) or not node:
        raise ValueError("Rule tree must be a non-empty JSON object")

    node_count = 0

    def _walk(cur: Any, depth: int) -> None:
        nonlocal node_count
        if depth > MAX_RULE_DEPTH:
            raise ValueError(f"Rule tree exceeds maximum nesting depth of {MAX_RULE_DEPTH}")
        if not isinstance(cur, dict):
            raise ValueError("Rule node must be an object")
        node_count += 1
        if node_count > MAX_RULE_NODES:
            raise ValueError(f"Rule tree exceeds maximum node count of {MAX_RULE_NODES}")

        op = str(cur.get("op") or "").upper()
        if op in ("AND", "OR", "NOT"):
            children = cur.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            if len(children) > MAX_RULE_CHILDREN:
                raise ValueError(f"Logical operator {op} exceeds max children ({MAX_RULE_CHILDREN})")
            for ch in children:
                _walk(ch, depth + 1)
            return

        field_name = str(cur.get("field") or "")
        if not field_name:
            raise ValueError("Leaf rule node missing 'field'")
        if op not in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"):
            raise ValueError(f"Unsupported rule operator: {op}")

        target = cur.get("value")
        if op == "IN":
            if not isinstance(target, list) or len(target) > MAX_IN_LIST_SIZE:
                raise ValueError(f"IN operator value must be a list of at most {MAX_IN_LIST_SIZE} items")
        elif op == "REGEX":
            if not isinstance(target, str):
                raise ValueError("REGEX operator requires a string pattern")
            _compile_safe_regex(target)

    _walk(node, 1)


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    """从分租户缓存或数据库读取指定租户的当前风控策略配置。"""
    tr = get_db_runtime(db_path).tenant(tenant_id)
    cached = tr.get_cached_policy()
    if cached is not None:
        return cached

    with tr.lock:
        expected_epoch = tr.policy_epoch

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
    tr.put_cached_policy(expected_epoch, policy)
    return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    """更新租户风控阈值与自定义规则树并递增策略版本号，提交后立即失效策略缓存。"""
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
    if custom_rules:
        validate_rule_tree(custom_rules)

    now_ts = int(time.time())
    conn = get_thread_connection(db_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT policy_version FROM tenant_policies WHERE tenant_id = ?",
            (caller.tenant_id,),
        ).fetchone()
        if not row:
            conn.execute("ROLLBACK")
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
                json.dumps(custom_rules),
                now_ts,
                caller.tenant_id,
            ),
        )
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    get_db_runtime(db_path).tenant(caller.tenant_id).bump_policy_epoch()
    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key) if isinstance(meta, dict) else None
    return tx.get(field_path)


def eval_rule_node(
    node: dict[str, Any],
    tx: dict[str, Any],
    *,
    _depth: int = 1,
    _budget: list[int] | None = None,
) -> tuple[bool, int, list[str]]:
    """递归计算风控规则节点（带深度与节点数硬保护），返回 (是否命中, 附加风险分, 命中原因列表)。"""
    if _depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree exceeds maximum nesting depth of {MAX_RULE_DEPTH}")
    if _budget is None:
        _budget = [0]
    _budget[0] += 1
    if _budget[0] > MAX_RULE_NODES:
        raise ValueError(f"Rule tree exceeds maximum node count of {MAX_RULE_NODES}")

    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    bonus = int(node.get("bonus_score") or 0)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if len(children) > MAX_RULE_CHILDREN:
            raise ValueError(f"Logical operator {op} exceeds max children ({MAX_RULE_CHILDREN})")

        child_results = [eval_rule_node(ch, tx, _depth=_depth + 1, _budget=_budget) for ch in children]
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
    elif op == "GT":
        matched = actual is not None and float(actual) > float(target)
    elif op == "GTE":
        matched = actual is not None and float(actual) >= float(target)
    elif op == "LT":
        matched = actual is not None and float(actual) < float(target)
    elif op == "LTE":
        matched = actual is not None and float(actual) <= float(target)
    elif op == "IN":
        if not isinstance(target, list) or len(target) > MAX_IN_LIST_SIZE:
            raise ValueError(f"IN operator value must be a list of at most {MAX_IN_LIST_SIZE} items")
        matched = actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(target, str):
            compiled = _compile_safe_regex(target)
            if isinstance(actual, str):
                if len(actual) > MAX_REGEX_INPUT_LENGTH:
                    raise ValueError(f"REGEX input exceeds maximum length of {MAX_REGEX_INPUT_LENGTH}")
                matched = compiled.search(actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    """在沙盒中试算自定义风控规则树对单笔交易样本的命中结果。"""
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


def _compute_single_tx_decision(
    tx: dict[str, Any],
    policy: dict[str, Any],
    *,
    win_tx_count: int,
    win_amount_cents: int,
    win_unique_cps: int,
) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []

    amount_cents = int(tx["amount_cents"])
    channel = str(tx.get("channel") or "POS_CHIP")

    ch_weight = CHANNEL_RISK_WEIGHTS.get(channel, 8)
    score += ch_weight

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

    if win_unique_cps > int(policy["counterparty_fanout_limit"]):
        score += 14
        reasons.append("COUNTERPARTY_FANOUT")

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


class _MonotonicAccountWindow:
    """均摊 O(1) 单调时间戳滑动窗口（仅用于本次请求的局部栈帧，回滚零残留）。"""

    __slots__ = ("_hist", "_hist_idx", "_hist_len", "_dq", "_sum_amt", "_cp_counts")

    def __init__(self, sorted_hist: list[tuple[int, int, str]]) -> None:
        self._hist = sorted_hist
        self._hist_idx = 0
        self._hist_len = len(sorted_hist)
        self._dq: deque[tuple[int, int, str]] = deque()
        self._sum_amt = 0
        self._cp_counts: Counter[str] = Counter()

    def advance_and_add(self, ts: int, amount_cents: int, cp_id: str) -> tuple[int, int, int]:
        win_start = ts - SLIDING_WINDOW_SECONDS
        hist = self._hist
        h_idx = self._hist_idx
        h_len = self._hist_len
        dq = self._dq
        cp_counts = self._cp_counts
        sum_amt = self._sum_amt

        while h_idx < h_len and hist[h_idx][0] <= ts:
            h_ts, h_amt, h_cp = hist[h_idx]
            h_idx += 1
            if h_ts >= win_start:
                dq.append((h_ts, h_amt, h_cp))
                sum_amt += h_amt
                cp_counts[h_cp] += 1
        self._hist_idx = h_idx

        dq.append((ts, amount_cents, cp_id))
        sum_amt += amount_cents
        cp_counts[cp_id] += 1

        while dq and dq[0][0] < win_start:
            _, old_amt, old_cp = dq.popleft()
            sum_amt -= old_amt
            rem = cp_counts[old_cp] - 1
            if rem <= 0:
                del cp_counts[old_cp]
            else:
                cp_counts[old_cp] = rem

        self._sum_amt = sum_amt
        return len(dq), sum_amt, len(cp_counts)


class _GeneralAccountWindow:
    """支持乱序时间戳的精确二分查找滑动窗口（仅用于本次请求的局部栈帧，回滚零残留）。"""

    __slots__ = ("_ts_keys", "_records")

    def __init__(self, sorted_hist: list[tuple[int, int, str]]) -> None:
        self._ts_keys = [r[0] for r in sorted_hist]
        self._records = list(sorted_hist)

    def advance_and_add(self, ts: int, amount_cents: int, cp_id: str) -> tuple[int, int, int]:
        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect_left(self._ts_keys, win_start)
        hi = bisect_right(self._ts_keys, ts)

        win_cnt = 1
        win_amt = amount_cents
        cps: set[str] = {cp_id}
        for i in range(lo, hi):
            _, h_amt, h_cp = self._records[i]
            win_cnt += 1
            win_amt += h_amt
            cps.add(h_cp)

        ins_pos = bisect_right(self._ts_keys, ts)
        self._ts_keys.insert(ins_pos, ts)
        self._records.insert(ins_pos, (ts, amount_cents, cp_id))
        return win_cnt, win_amt, len(cps)


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次并原子持久化交易及风控决策记录。

    同一批次是数据库与内存双原子整体：
    1. 先在内存中完成全批字段校验、批内主键查重与邮箱线性校验；
    2. 在单个 BEGIN IMMEDIATE 事务内按涉及账户索引范围加载历史窗口，用局部栈帧维护滑动窗；
    3. executemany 批量写入并一次性提交；若遇主键冲突或异常，完整回滚，零半截落盘、零内存残留。
    """
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > MAX_BATCH_SIZE:
        raise ValueError(f"Batch size exceeds maximum limit of {MAX_BATCH_SIZE}")

    # 阶段 1：全批预校验（零 DB 写入）
    parsed_txs: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()
    acct_bounds: dict[str, list[int]] = {}  # acct_id -> [min_ts, max_ts, last_ts, is_monotonic(1/0)]

    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be a JSON object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()

        raw_amt = item.get("amount_cents")
        raw_ts = item.get("ts")
        if isinstance(raw_amt, bool) or isinstance(raw_ts, bool):
            raise ValueError(f"Invalid numeric field type for tx_id={tx_id!r}")
        amount_cents = int(raw_amt or 0)
        ts = int(raw_ts or 0)

        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if amount_cents > 10**15:
            raise ValueError(f"amount_cents overflow for tx_id={tx_id!r}")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")
        if tx_id in seen_tx_ids:
            raise ConflictError(f"Duplicate tx_id within batch: {tx_id}", 409)
        seen_tx_ids.add(tx_id)

        b = acct_bounds.get(account_id)
        if b is None:
            acct_bounds[account_id] = [ts, ts, ts, 1]
        else:
            if ts < b[0]:
                b[0] = ts
            if ts > b[1]:
                b[1] = ts
            if ts < b[2]:
                b[3] = 0
            b[2] = ts

        parsed_txs.append(
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

    # 阶段 2 & 3：单事务索引窗口预拉取 + 局部栈内存按序推演 + 批量原子提交
    conn = get_thread_connection(db_path)
    conn.execute("BEGIN IMMEDIATE")
    try:
        acct_windows: dict[str, _MonotonicAccountWindow | _GeneralAccountWindow] = {}
        for acct_id, bounds in acct_bounds.items():
            min_ts, max_ts, _, is_mono = bounds
            rows = conn.execute(
                "SELECT ts, amount_cents, counterparty_id "
                "FROM transactions "
                "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ? "
                "ORDER BY ts ASC",
                (caller.tenant_id, acct_id, min_ts - SLIDING_WINDOW_SECONDS, max_ts),
            ).fetchall()
            hist_list = [(int(r["ts"]), int(r["amount_cents"]), str(r["counterparty_id"])) for r in rows]
            if is_mono:
                acct_windows[acct_id] = _MonotonicAccountWindow(hist_list)
            else:
                acct_windows[acct_id] = _GeneralAccountWindow(hist_list)

        tx_rows_to_insert: list[tuple[Any, ...]] = []
        dec_rows_to_insert: list[tuple[Any, ...]] = []
        results: list[dict[str, Any]] = []
        counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

        for tx_obj in parsed_txs:
            acct_id = tx_obj["account_id"]
            win_tx_count, win_amount_cents, win_unique_cps = acct_windows[acct_id].advance_and_add(
                tx_obj["ts"],
                tx_obj["amount_cents"],
                tx_obj["counterparty_id"],
            )
            risk_score, decision, reasons = _compute_single_tx_decision(
                tx_obj,
                policy,
                win_tx_count=win_tx_count,
                win_amount_cents=win_amount_cents,
                win_unique_cps=win_unique_cps,
            )
            decision_id = f"dec_{tx_obj['tx_id']}"
            tx_rows_to_insert.append(
                (
                    tx_obj["tx_id"],
                    caller.tenant_id,
                    batch_id,
                    acct_id,
                    tx_obj["counterparty_id"],
                    tx_obj["amount_cents"],
                    tx_obj["currency"],
                    tx_obj["channel"],
                    tx_obj["contact_email"],
                    tx_obj["ts"],
                    json.dumps(tx_obj["metadata"], sort_keys=True),
                )
            )
            dec_rows_to_insert.append(
                (
                    decision_id,
                    tx_obj["tx_id"],
                    caller.tenant_id,
                    acct_id,
                    risk_score,
                    decision,
                    win_tx_count,
                    win_amount_cents,
                    win_unique_cps,
                    json.dumps(reasons),
                    tx_obj["ts"],
                )
            )
            counts[decision] += 1
            results.append(
                {
                    "decision_id": decision_id,
                    "tx_id": tx_obj["tx_id"],
                    "account_id": acct_id,
                    "risk_score": risk_score,
                    "decision": decision,
                    "window": {
                        "tx_count": win_tx_count,
                        "amount_cents": win_amount_cents,
                        "unique_counterparties": win_unique_cps,
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
            "win_tx_count, win_amount_cents, win_unique_counterparties, reasons_json, evaluated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            dec_rows_to_insert,
        )
        conn.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise ConflictError("Transaction batch conflict: duplicate tx_id or decision_id", 409) from exc
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
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
    """根据决策单号查询当前租户下的单笔实时风控评估详情（强制租户边界隔离）。"""
    if not decision_id:
        raise ValueError("decision_id is required")
    conn = get_thread_connection(db_path)
    row = conn.execute(
        "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
        "win_tx_count, win_amount_cents, win_unique_counterparties, reasons_json, evaluated_at "
        "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
        (decision_id, caller.tenant_id),
    ).fetchone()
    if not row:
        raise LookupError(f"Decision record not found: {decision_id}")
    return {
        "decision_id": row["decision_id"],
        "tx_id": row["tx_id"],
        "tenant_id": row["tenant_id"],
        "account_id": row["account_id"],
        "risk_score": int(row["risk_score"]),
        "decision": row["decision"],
        "window": {
            "tx_count": int(row["win_tx_count"]),
            "amount_cents": int(row["win_amount_cents"]),
            "unique_counterparties": int(row["win_unique_counterparties"]),
        },
        "reasons": json.loads(row["reasons_json"]),
        "evaluated_at": int(row["evaluated_at"]),
    }
