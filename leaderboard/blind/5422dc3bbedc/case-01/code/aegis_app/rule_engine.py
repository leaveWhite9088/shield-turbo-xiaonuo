# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。

性能与正确性契约：
- 批次评估一次预载全租户交易流（按账户分组 + 按 ts 排序），滑动窗口与三跳传染
  图均为纯内存增量结构（乱序时间戳精确回退），彻底消除原版逐笔全表扫描与逐笔
  json.loads；
- 滑窗精确中位数以"有序金额表 + 虚拟插入" O(log W) 求值、增量进出窗 O(W) 维护，
  输出与原版（含当前笔在内）逐位一致；
- 整批"数据库 + 滑窗 + 传染图 + REALTIME_ALERT_POOL 告警配额"四位一体强原子：
  所有落库与配额扣减统一收口到单一 BEGIN IMMEDIATE 事务，任一笔非法或主键冲突
  整批 ROLLBACK，零半截落盘、零配额泄漏、零内存污染；
- 规则树深度/节点数/正则模式均设硬熔断，严格 64 位整数与类型守卫。
"""
from __future__ import annotations

import json
import re
import time
from bisect import bisect_left, bisect_right, insort
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    CHANNEL_RISK_WEIGHTS,
    MAX_BATCH_TRANSACTIONS,
    MAX_RULE_REGEX_BOUND,
    MAX_RULE_REGEX_LEN,
    MAX_RULE_TREE_DEPTH,
    MAX_RULE_TREE_NODES,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import ContagionEdgeTracker
from .db import coerce_strict_int, immediate_transaction, open_connection
from .index_cache import get_state
from .ledger_ops import try_consume_realtime_alert_quota
from .legacy_compat import apply_sovereign_settlement_adjustment
from .window_stats import compute_exact_median_cents

# 等价简化（与原版语言完全一致），消除嵌套量词灾难性回溯（ReDoS）
PARTNER_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)"
)
_EMAIL_FULL_PATTERN = re.compile(r"^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$")


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > 254:
        return False
    return _EMAIL_FULL_PATTERN.match(email) is not None


def _safe_regex_search(pattern: str, text: str) -> bool:
    """抗 ReDoS 硬熔断：长度/分组/重复上界约束 + 量词化分组歧义拦截 + 预编译。

    拦截两类灾难性回溯构造：
    a) 量化分组体内含量词（(...+)+ / (...*)* / (...{2})+ 等嵌套量词）；
    b) 量化分组体内含前缀歧义交替（(a|aa)+ 型：一个分支是另一分支的前缀）。
    """
    if not isinstance(pattern, str) or len(pattern) > MAX_RULE_REGEX_LEN:
        raise ValueError("Rule regex pattern exceeds safe length limit")
    if pattern.count("(") > 24:
        raise ValueError("Rule regex group count exceeds safe limit")
    # 有限重复 {n,m} 上界约束
    for m in re.finditer(r"\{(\d+)(,(\d*)?)?\}", pattern):
        lo = int(m.group(1))
        hi = int(m.group(3)) if m.group(3) else lo
        if lo > MAX_RULE_REGEX_BOUND or hi > MAX_RULE_REGEX_BOUND:
            raise ValueError("Rule regex bounded repetition exceeds safe limit")
    # 嵌套量词与歧义量化分组启发式拦截（逐层扫描分组，忽略字符类与转义）
    idx = 0
    n = len(pattern)
    while idx < n:
        ch = pattern[idx]
        if ch == "\\":
            idx += 2
            continue
        if ch == "[":
            cls_end = idx + 1
            while cls_end < n and (cls_end == idx + 1 or pattern[cls_end] != "]"):
                if pattern[cls_end] == "\\":
                    cls_end += 1
                cls_end += 1
            idx = cls_end + 1
            continue
        if ch == "(":
            # 找配对右括号（忽略字符类内部）
            depth = 1
            j = idx + 1
            while j < n and depth:
                cj = pattern[j]
                if cj == "\\":
                    j += 2
                    continue
                if cj == "[":
                    k = j + 1
                    while k < n and (k == j + 1 or pattern[k] != "]"):
                        if pattern[k] == "\\":
                            k += 1
                        k += 1
                    j = k
                    continue
                if cj == "(":
                    depth += 1
                elif cj == ")":
                    depth -= 1
                j += 1
            body = pattern[idx + 1 : j - 1]
            # 分组后的量词
            after = pattern[j:] if j <= n else ""
            quantified = bool(after) and after[0] in "+*"
            if not quantified and after.startswith("{"):
                bound_m = re.match(r"\{(\d+)(,(\d*)?)?\}", after)
                if bound_m:
                    lo_b = int(bound_m.group(1))
                    hi_b = int(bound_m.group(3)) if bound_m.group(3) else lo_b
                    quantified = lo_b >= 2 or hi_b >= 2 or hi_b == 0
            if quantified:
                # (a) 体内含量词 → 嵌套量词炸弹
                if re.search(r"[+*]|\{\d", _strip_classes(body)):
                    raise ValueError("Rule regex contains nested quantifier (catastrophic backtracking guard)")
                # (b) 体内含前缀歧义交替（(a|aa)+ 型）
                alts = _split_top_alternation(body)
                if len(alts) > 1:
                    stripped_alts = [a.strip() for a in alts]
                    for x in range(len(stripped_alts)):
                        for y in range(len(stripped_alts)):
                            if x != y and stripped_alts[x] and stripped_alts[y].startswith(stripped_alts[x]):
                                raise ValueError("Rule regex contains ambiguous prefix alternation under quantifier")
            idx = j
            continue
        idx += 1
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid rule regex pattern: {exc}") from exc
    return compiled.search(text) is not None


def _strip_classes(body: str) -> str:
    """移除字符类内容，避免类内 + 号干扰嵌套量词判定。"""
    return re.sub(r"\[[^\]]*\]", "", body)


def _split_top_alternation(body: str) -> list[str]:
    """按顶层 | 切分（忽略字符类、转义与嵌套分组）。"""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            cur.append(ch)
            if i + 1 < len(body):
                cur.append(body[i + 1])
            i += 2
            continue
        if ch == "[":
            j = i + 1
            while j < len(body) and (j == i + 1 or body[j] != "]"):
                if body[j] == "\\":
                    j += 1
                j += 1
            cur.append(body[i : min(j + 1, len(body))])
            i = j + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    """读取租户风控策略（进程内 policy 纪元缓存热路径，零数据库往返）。"""
    state = get_state(db_path)
    policy = state.tenant(tenant_id).policy(db_path)
    if policy is None:
        raise LookupError(f"Policy configuration missing for {tenant_id}")
    return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    current = load_tenant_policy(db_path, caller.tenant_id)
    high_amt = coerce_strict_int(updates.get("high_amount_cents"), current["high_amount_cents"], field="high_amount_cents")
    vel_tx = coerce_strict_int(updates.get("velocity_tx_limit"), current["velocity_tx_limit"], field="velocity_tx_limit")
    vel_amt = coerce_strict_int(updates.get("velocity_amount_cents"), current["velocity_amount_cents"], field="velocity_amount_cents")
    fanout = coerce_strict_int(updates.get("counterparty_fanout_limit"), current["counterparty_fanout_limit"], field="counterparty_fanout_limit")
    rev_th = coerce_strict_int(updates.get("review_threshold"), current["review_threshold"], field="review_threshold")
    rej_th = coerce_strict_int(updates.get("reject_threshold"), current["reject_threshold"], field="reject_threshold")
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    # 规则树结构预算前置校验（防膨胀规则树落库）
    _count_rule_budget(custom_rules)

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
    get_state(db_path).tenant(caller.tenant_id).bump_policy()
    return load_tenant_policy(db_path, caller.tenant_id)


def _count_rule_budget(node: Any, counter: list[int] | None = None, depth: int = 0) -> list[int]:
    """统计规则树节点数并校验深度预算（防千层 JSON / 膨胀规则树）。"""
    if counter is None:
        counter = [0]
    if depth > MAX_RULE_TREE_DEPTH:
        raise ValueError("Rule tree nesting depth exceeds safe limit")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    counter[0] += 1
    if counter[0] > MAX_RULE_TREE_NODES:
        raise ValueError("Rule tree node count exceeds safe limit")
    children = node.get("children")
    if isinstance(children, list):
        for child in children:
            _count_rule_budget(child, counter, depth + 1)
    return counter


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any], *, depth: int = 0, budget: list[int] | None = None) -> tuple[bool, int, list[str]]:
    if depth > MAX_RULE_TREE_DEPTH:
        raise ValueError("Rule tree nesting depth exceeds safe limit")
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_RULE_TREE_NODES:
        raise ValueError("Rule tree node count exceeds safe limit")

    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    bonus = coerce_strict_int(node.get("bonus_score"), 0, field="bonus_score")
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")

        child_results = [eval_rule_node(ch, tx, depth=depth + 1, budget=budget) for ch in children]
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
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            matched = _safe_regex_search(target, actual)
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
    _count_rule_budget(rule_tree)
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


class _AccountWindowTracker:
    """单账户 24h 滑动窗口增量统计器：O(log W) 精确中位数 + 乱序时间戳精确回退。

    底层保留该账户全量 (ts, amount, cp) 按 ts 升序数组；每次观察用二分定位窗口
    [lo, hi)，当时间前推时增量进出窗维护有序金额表 / 对手方计数 / 累计金额，
    时间回退或插入点落在当前窗口内时整窗精确重建，保证任意乱序下的零失真。
    """

    __slots__ = ("ts_l", "am_l", "cp_l", "win_sorted", "win_cps", "win_sum",
                 "cur_lo", "cur_hi", "prev_ts")

    def __init__(self, rows: list[tuple[int, int, str]]) -> None:
        rows_sorted = sorted(rows, key=lambda r: r[0])
        self.ts_l = [r[0] for r in rows_sorted]
        self.am_l = [r[1] for r in rows_sorted]
        self.cp_l = [r[2] for r in rows_sorted]
        self.win_sorted: list[int] = []
        self.win_cps: dict[str, int] = {}
        self.win_sum = 0
        self.cur_lo = 0
        self.cur_hi = 0
        self.prev_ts: int | None = None

    def observe(self, ts: int, amount: int, cp: str) -> tuple[int, int, int, int]:
        """纳入当前交易观察窗口，返回 (win_tx_count, win_amount, win_unique_cps, win_median)。"""
        win_start = ts - SLIDING_WINDOW_SECONDS
        lo = bisect_left(self.ts_l, win_start)
        hi = bisect_right(self.ts_l, ts)
        if (
            self.prev_ts is None
            or ts < self.prev_ts
            or lo < self.cur_lo
            or hi < self.cur_hi
        ):
            window_amts = self.am_l[lo:hi]
            self.win_sorted = sorted(window_amts)
            self.win_sum = sum(window_amts)
            cps: dict[str, int] = {}
            for c in self.cp_l[lo:hi]:
                cps[c] = cps.get(c, 0) + 1
            self.win_cps = cps
        else:
            # 增量进出窗：仅处理与旧窗口 [cur_lo, cur_hi) 相交的部分；
            # 当 lo > cur_hi（窗口出现空档）时，[cur_hi, lo) 不属于新窗口，绝不加入
            evict_end = min(lo, self.cur_hi)
            for i in range(self.cur_lo, evict_end):
                evicted = self.am_l[i]
                k = bisect_left(self.win_sorted, evicted)
                if k < len(self.win_sorted) and self.win_sorted[k] == evicted:
                    self.win_sorted.pop(k)
                self.win_sum -= evicted
                c_ev = self.cp_l[i]
                rem = self.win_cps.get(c_ev, 0) - 1
                if rem <= 0:
                    self.win_cps.pop(c_ev, None)
                else:
                    self.win_cps[c_ev] = rem
            add_start = max(self.cur_hi, lo)
            for j in range(add_start, hi):
                insort(self.win_sorted, self.am_l[j])
                self.win_sum += self.am_l[j]
                self.win_cps[self.cp_l[j]] = self.win_cps.get(self.cp_l[j], 0) + 1
        self.cur_lo = lo
        self.cur_hi = hi
        self.prev_ts = ts

        # 虚拟插入当前交易金额后求精确中位数（与原版 [当前笔]+窗口历史 语义一致）
        hist_cnt = hi - lo
        win_tx_count = hist_cnt + 1
        win_amount = self.win_sum + amount
        win_unique_cps = len(self.win_cps) + (0 if cp in self.win_cps else 1)
        win_median = self._median_with(amount)
        return win_tx_count, win_amount, win_unique_cps, win_median

    def _median_with(self, extra: int) -> int:
        """有序窗口金额表 + 虚拟插入 extra 的精确中位数（O(log W) 定位，零拷贝）。"""
        base = self.win_sorted
        n = len(base) + 1
        idx = bisect_left(base, extra)

        def elem(k: int) -> int:
            if k < idx:
                return base[k]
            if k == idx:
                return extra
            return base[k - 1]

        mid = n // 2
        if n % 2 == 1:
            return int(elem(mid))
        return int((elem(mid - 1) + elem(mid)) // 2)

    def append(self, ts: int, amount: int, cp: str) -> None:
        """批次先序交易入账（与原版"先落库后评估"的窗口可见性语义一致）。"""
        pos = bisect_left(self.ts_l, ts)
        # 使用 insert 保持 ts 升序（同 ts 时插入在左侧不影响 bisect_right 上界）
        self.ts_l.insert(pos, ts)
        self.am_l.insert(pos, amount)
        self.cp_l.insert(pos, cp)
        if pos < self.cur_hi:
            self.prev_ts = None  # 插入点在当前窗口内：指针失效，下次精确重建


def _validate_batch_transactions(transactions: list[Any]) -> list[dict[str, Any]]:
    """逐笔严格校验与规整（任一笔非法 → 整批 ValueError，零落盘）。"""
    if not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > MAX_BATCH_TRANSACTIONS:
        raise ValueError(f"Batch size exceeds limit of {MAX_BATCH_TRANSACTIONS} transactions")

    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction must be an object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        try:
            amount_cents = coerce_strict_int(item.get("amount_cents"), 0, field="amount_cents")
            ts = coerce_strict_int(item.get("ts"), 0, field="ts")
        except ValueError as exc:
            raise ValueError(f"Invalid numeric field for tx_id={tx_id!r}: {exc}") from exc
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if len(tx_id) > 64 or len(account_id) > 128 or len(counterparty_id) > 128:
            raise ValueError(f"Identifier length limit exceeded for tx_id={tx_id!r}")
        if len(currency) > 8 or len(channel) > 32:
            raise ValueError(f"Field length limit exceeded for tx_id={tx_id!r}")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")
        if tx_id in seen_ids:
            raise ValueError(f"Duplicate tx_id within batch: {tx_id}")
        seen_ids.add(tx_id)

        normalized.append(
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
    return normalized


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次（四位一体强原子提交/回滚）。"""
    if not batch_id or not isinstance(batch_id, str) or len(batch_id) > 128:
        raise ValueError("batch_id and non-empty transactions list are required")
    if not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")

    # —— 阶段 1：全批输入严格校验（任一笔非法 → 整批拒绝，零副作用） ——
    normalized = _validate_batch_transactions(transactions)

    tenant_id = caller.tenant_id
    policy = load_tenant_policy(db_path, tenant_id)
    state = get_state(db_path)
    tstate = state.tenant(tenant_id)
    sanctions = tstate.sanctions(db_path)
    sanctioned = {ent for ent, flag in sanctions.items() if flag == 1}

    # —— 阶段 2：一次预载全租户交易流，构建账户滑窗与传染图增量结构 ——
    conn = open_connection(db_path)
    try:
        hist_rows = conn.execute(
            "SELECT account_id, counterparty_id, amount_cents, ts "
            "FROM transactions WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    account_rows: dict[str, list[tuple[int, int, str]]] = {}
    edge_list: list[tuple[int, str, str]] = []
    for r in hist_rows:
        h_ts = int(r["ts"])
        h_acct = r["account_id"]
        edge_list.append((h_ts, h_acct, r["counterparty_id"]))
        account_rows.setdefault(h_acct, []).append((h_ts, int(r["amount_cents"]), r["counterparty_id"]))
    account_trackers = {acct: _AccountWindowTracker(rows) for acct, rows in account_rows.items()}
    contagion = ContagionEdgeTracker(edge_list)

    # —— 阶段 3：纯内存逐笔评估（同批先序交易纳入后续窗口与关联图；任何异常零污染） ——
    evaluations: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
    for item in normalized:
        tx_id = item["tx_id"]
        account_id = item["account_id"]
        counterparty_id = item["counterparty_id"]
        amount_cents = item["amount_cents"]
        ts = item["ts"]

        tracker = account_trackers.get(account_id)
        if tracker is None:
            tracker = _AccountWindowTracker([])
            account_trackers[account_id] = tracker
        win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = tracker.observe(
            ts, amount_cents, counterparty_id
        )

        contagion.update(ts)
        if sanctioned:
            sanction_hop = contagion.hop_for(sanctioned, account_id, counterparty_id)
        else:
            sanction_hop = 0

        risk_score, decision, reasons = compute_single_tx_decision(
            item,
            policy,
            win_tx_count=win_tx_count,
            win_amount_cents=win_amount_cents,
            win_unique_cps=win_unique_cps,
            win_median_cents=win_median_cents,
            sanction_hop=sanction_hop,
        )

        evaluations.append(
            {
                "item": item,
                "risk_score": risk_score,
                "decision": decision,
                "sanction_hop": sanction_hop,
                "window": {
                    "tx_count": win_tx_count,
                    "amount_cents": win_amount_cents,
                    "unique_counterparties": win_unique_cps,
                    "median_cents": win_median_cents,
                },
                "reasons": reasons,
                "needs_alert": decision == "REJECT",
            }
        )
        counts[decision] += 1
        # 同批先序交易纳入后续账户窗口与传染图
        tracker.append(ts, amount_cents, counterparty_id)
        contagion.append_edge(ts, account_id, counterparty_id)

    # —— 阶段 4：单一 BEGIN IMMEDIATE 事务内完成主键冲突预检、落库与告警配额联动 ——
    decision_rows: list[tuple[Any, ...]] = []
    results: list[dict[str, Any]] = []
    conn = open_connection(db_path)
    try:
        with immediate_transaction(conn):
            tx_ids = [ev["item"]["tx_id"] for ev in evaluations]
            for start in range(0, len(tx_ids), 500):
                chunk = tx_ids[start:start + 500]
                placeholders = ",".join("?" for _ in chunk)
                dup_rows = conn.execute(
                    f"SELECT tx_id FROM transactions WHERE tx_id IN ({placeholders})",
                    tuple(chunk),
                ).fetchall()
                if dup_rows:
                    raise ValueError(
                        f"Duplicate tx_id conflicts with existing records: {dup_rows[0]['tx_id']}"
                    )

            alert_flags: list[bool] = []
            for ev in evaluations:
                dispatched = False
                if ev["needs_alert"]:
                    cur = conn.execute(
                        "UPDATE tenant_quotas SET remaining_quota = remaining_quota - 1, updated_at = ? "
                        "WHERE tenant_id = ? AND quota_type = 'REALTIME_ALERT_POOL' AND remaining_quota >= 1",
                        (int(ev["item"]["ts"]), tenant_id),
                    )
                    if cur.rowcount == 1:
                        dispatched = True
                        ev["reasons"].append("ALERT_QUOTA_CONSUMED")
                    else:
                        ev["reasons"].append("ALERT_POOL_DEPLETED")
                alert_flags.append(dispatched)

            for ev, dispatched in zip(evaluations, alert_flags):
                item = ev["item"]
                decision_id = f"dec_{item['tx_id']}"
                conn.execute(
                    "INSERT INTO transactions("
                    "tx_id, tenant_id, batch_id, account_id, counterparty_id, amount_cents, "
                    "currency, channel, contact_email, ts, metadata_json"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item["tx_id"],
                        tenant_id,
                        batch_id,
                        item["account_id"],
                        item["counterparty_id"],
                        item["amount_cents"],
                        item["currency"],
                        item["channel"],
                        item["contact_email"],
                        item["ts"],
                        json.dumps(item["metadata"], sort_keys=True),
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
                        item["tx_id"],
                        tenant_id,
                        item["account_id"],
                        ev["risk_score"],
                        ev["decision"],
                        ev["window"]["tx_count"],
                        ev["window"]["amount_cents"],
                        ev["window"]["unique_counterparties"],
                        ev["window"]["median_cents"],
                        ev["sanction_hop"],
                        json.dumps(ev["reasons"]),
                        item["ts"],
                    ),
                )
    except ValueError:
        raise  # 主键冲突：事务已 ROLLBACK，零半截落盘、零配额泄漏
    finally:
        conn.close()

    for ev, dispatched in zip(evaluations, alert_flags):
        results.append(
            {
                "decision_id": f"dec_{ev['item']['tx_id']}",
                "tx_id": ev["item"]["tx_id"],
                "account_id": ev["item"]["account_id"],
                "risk_score": ev["risk_score"],
                "decision": ev["decision"],
                "sanction_hop": ev["sanction_hop"],
                "alert_dispatched": dispatched,
                "window": ev["window"],
                "reasons": ev["reasons"],
            }
        )

    return {
        "tenant_id": tenant_id,
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
