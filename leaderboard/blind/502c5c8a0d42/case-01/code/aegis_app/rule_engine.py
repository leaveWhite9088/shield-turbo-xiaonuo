# -*- coding: utf-8 -*-
"""实时交易风控评分、滑动时间窗特征计算与自定义布尔规则树引擎。"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
import json
import re
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import CHANNEL_RISK_WEIGHTS, SLIDING_WINDOW_SECONDS
from .runtime import ConflictError, get_runtime

# 无嵌套量词的线性确定性邮箱校验（彻底消除 ReDoS 回溯）
_EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$")
_EMAIL_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")

MAX_EMAIL_LEN = 254
MAX_RULE_DEPTH = 16
MAX_RULE_NODES = 256
MAX_REGEX_LEN = 256
MAX_REGEX_TARGET_LEN = 4096
MAX_BATCH_SIZE = 2000


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > MAX_EMAIL_LEN:
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain:
        return False
    return (_EMAIL_LOCAL_RE.match(local) is not None) and (_EMAIL_DOMAIN_RE.match(domain) is not None)


def _is_safe_regex(pattern: str) -> bool:
    """静态检测正则表达式是否存在嵌套量词、前瞻回溯等 ReDoS 风险。"""
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_REGEX_LEN:
        return False
    # 拒绝前瞻/后顾与反向引用
    if re.search(r"\(\?[=!<]|\\[1-9]", pattern):
        return False

    # 扫描括号分组，禁止“内部含重复量词/交替的分组”再被外部量词重复
    stack: list[bool] = []  # 当前分组内是否出现过量词或交替
    i = 0
    n = len(pattern)
    prev_was_group_end = False
    last_group_had_quant = False

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            prev_was_group_end = False
            continue
        if ch == "[":
            # 跳过字符类 [...]
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            while i < n and pattern[i] != "]":
                if pattern[i] == "\\":
                    i += 2
                else:
                    i += 1
            i += 1
            prev_was_group_end = False
            continue
        if ch == "(":
            stack.append(False)
            prev_was_group_end = False
            i += 1
            continue
        if ch == ")":
            had_inner = stack.pop() if stack else False
            if stack and had_inner:
                stack[-1] = True
            prev_was_group_end = True
            last_group_had_quant = had_inner
            i += 1
            continue
        if ch in ("*", "+", "?"):
            if prev_was_group_end and last_group_had_quant:
                return False
            # 检查连续非惰性量词如 ++, **
            if i + 1 < n and pattern[i + 1] in ("*", "+"):
                return False
            if stack:
                stack[-1] = True
            prev_was_group_end = False
            i += 1
            continue
        if ch == "{":
            end_brace = pattern.find("}", i + 1)
            if end_brace != -1 and re.fullmatch(r"\d+(?:,\d*)?", pattern[i + 1 : end_brace]):
                if prev_was_group_end and last_group_had_quant:
                    return False
                if stack:
                    stack[-1] = True
                prev_was_group_end = False
                i = end_brace + 1
                continue
        if ch == "|" and stack:
            stack[-1] = True
        prev_was_group_end = False
        i += 1

    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def _validate_rule_tree(node: Any, depth: int = 1, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [0]
    if depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree exceeds maximum depth ({MAX_RULE_DEPTH})")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    budget[0] += 1
    if budget[0] > MAX_RULE_NODES:
        raise ValueError(f"Rule tree exceeds maximum node count ({MAX_RULE_NODES})")

    op = str(node.get("op") or "").upper()
    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")
        for ch in children:
            _validate_rule_tree(ch, depth + 1, budget)
        return

    field_name = str(node.get("field") or "")
    if not field_name:
        raise ValueError("Leaf rule node missing 'field'")
    if op not in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"):
        raise ValueError(f"Unsupported rule operator: {op}")
    if op == "REGEX":
        target = node.get("value")
        if not isinstance(target, str) or not _is_safe_regex(target):
            raise ValueError("Unsafe or invalid REGEX pattern in rule node")


def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
    """从缓存或数据库读取并反序列化指定租户的当前风控策略配置。"""
    rt = get_runtime(db_path)
    ep_before, cached = rt.get_policy_cached(tenant_id)
    if cached is not None:
        return dict(cached)

    conn = rt.get_connection()
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
    rt.put_policy_cached(tenant_id, ep_before, policy)
    return dict(policy)


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    """更新租户风控阈值与自定义规则树，递增策略版本号并立即失效策略缓存。"""
    require_admin(caller)
    rt = get_runtime(db_path)
    with rt.get_tenant_lock(caller.tenant_id):
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
            _validate_rule_tree(custom_rules)

        new_ver = int(current["policy_version"]) + 1
        now_ts = int(time.time())
        conn = rt.get_connection()
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
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        rt.bump_epoch("policy", caller.tenant_id)
    return load_tenant_policy(db_path, caller.tenant_id)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def eval_rule_node(
    node: dict[str, Any],
    tx: dict[str, Any],
    *,
    _depth: int = 1,
    _budget: list[int] | None = None,
) -> tuple[bool, int, list[str]]:
    """递归计算风控规则节点，返回 (是否命中, 附加风险分, 命中原因列表)。"""
    if _budget is None:
        _budget = [0]
    if _depth > MAX_RULE_DEPTH:
        raise ValueError(f"Rule tree exceeds maximum depth ({MAX_RULE_DEPTH})")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    _budget[0] += 1
    if _budget[0] > MAX_RULE_NODES:
        raise ValueError(f"Rule tree exceeds maximum node count ({MAX_RULE_NODES})")

    op = str(node.get("op") or "").upper()
    bonus = int(node.get("bonus_score") or 0)
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")

        child_results = [
            eval_rule_node(ch, tx, _depth=_depth + 1, _budget=_budget) for ch in children
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
        if not isinstance(target, str) or not _is_safe_regex(target):
            raise ValueError("Unsafe or invalid REGEX pattern in rule node")
        if isinstance(actual, str):
            if len(actual) > MAX_REGEX_TARGET_LEN:
                raise ValueError("Target string exceeds maximum REGEX evaluation length")
            matched = re.search(target, actual) is not None
    else:
        raise ValueError(f"Unsupported rule operator: {op}")

    if matched:
        return True, bonus, ([reason] if reason else [])
    return False, 0, []


def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
    """在沙盒中试算自定义风控规则树对单笔交易样本的命中结果（含复杂度与 ReDoS 熔断）。"""
    if not isinstance(sample_tx, dict):
        raise ValueError("sample_tx must be an object")
    _validate_rule_tree(rule_tree)
    email = sample_tx.get("contact_email")
    if email is not None and not validate_contact_email(str(email)):
        raise ValueError("Invalid contact_email format in sample_tx")
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


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次并原子持久化交易及风控决策记录。

    同一批次在单一数据库事务内原子提交或全量回滚，严禁半截落盘。
    """
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > MAX_BATCH_SIZE:
        raise ValueError(f"Batch size exceeds maximum limit ({MAX_BATCH_SIZE})")

    # 第一阶段：全量输入合法性与批内 tx_id 唯一性预校验（Fail-Fast）
    normalized_txs: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()
    account_ids_set: set[str] = set()
    min_ts = 1 << 62
    max_ts = 0

    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction item must be an object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        amount_cents = int(item.get("amount_cents") or 0)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = str(item.get("contact_email") or "").strip()
        ts = int(item.get("ts") or 0)
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

        if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")
        if tx_id in seen_tx_ids:
            raise ConflictError(f"Duplicate tx_id in batch: {tx_id}")

        seen_tx_ids.add(tx_id)
        account_ids_set.add(account_id)
        if ts < min_ts:
            min_ts = ts
        if ts > max_ts:
            max_ts = ts

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

    policy = load_tenant_policy(db_path, caller.tenant_id)
    rt = get_runtime(db_path)

    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
    tx_insert_rows: list[tuple[Any, ...]] = []
    dec_insert_rows: list[tuple[Any, ...]] = []

    with rt.get_tenant_lock(caller.tenant_id):
        conn = rt.get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")

            # 一次性按 (tenant_id, account_id, ts) 索引加载相关账户在窗口范围内的历史交易
            acct_ts_list: dict[str, list[int]] = defaultdict(list)
            acct_records: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
            window_lower = min_ts - SLIDING_WINDOW_SECONDS

            acct_list = list(account_ids_set)
            for chunk_start in range(0, len(acct_list), 400):
                chunk = acct_list[chunk_start : chunk_start + 400]
                placeholders = ",".join("?" for _ in chunk)
                hist_rows = conn.execute(
                    f"SELECT account_id, counterparty_id, amount_cents, ts "
                    f"FROM transactions "
                    f"WHERE tenant_id = ? AND account_id IN ({placeholders}) "
                    f"AND ts >= ? AND ts <= ? "
                    f"ORDER BY ts ASC",
                    (caller.tenant_id, *chunk, window_lower, max_ts),
                ).fetchall()
                for hr in hist_rows:
                    aid = hr["account_id"]
                    h_ts = int(hr["ts"])
                    acct_ts_list[aid].append(h_ts)
                    acct_records[aid].append((h_ts, int(hr["amount_cents"]), hr["counterparty_id"]))

            # 对每个账户确保按 ts 升序（多块时仍各自有序，直接 sort 以防万一）
            for aid, recs in acct_records.items():
                if len(recs) > 1:
                    recs.sort(key=lambda x: x[0])
                    acct_ts_list[aid] = [r[0] for r in recs]

            # 在局部内存状态中按批次顺序推演每笔交易的滑动时间窗，不污染共享状态
            for tx_eval_obj in normalized_txs:
                tx_id = tx_eval_obj["tx_id"]
                account_id = tx_eval_obj["account_id"]
                counterparty_id = tx_eval_obj["counterparty_id"]
                amount_cents = tx_eval_obj["amount_cents"]
                ts = tx_eval_obj["ts"]

                win_start = ts - SLIDING_WINDOW_SECONDS
                ts_arr = acct_ts_list[account_id]
                rec_arr = acct_records[account_id]

                lo = bisect_left(ts_arr, win_start)
                hi = bisect_right(ts_arr, ts)

                win_tx_count = 1 + (hi - lo)
                win_amount_cents = amount_cents
                cp_set: set[str] = {counterparty_id}
                for idx in range(lo, hi):
                    _, h_amt, h_cp = rec_arr[idx]
                    win_amount_cents += h_amt
                    cp_set.add(h_cp)
                win_unique_cps = len(cp_set)

                risk_score, decision, reasons = _compute_single_tx_decision(
                    tx_eval_obj,
                    policy,
                    win_tx_count=win_tx_count,
                    win_amount_cents=win_amount_cents,
                    win_unique_cps=win_unique_cps,
                )

                # 将本笔先序交易纳入同账户后续交易的局部可见窗口
                ins_pos = hi
                ts_arr.insert(ins_pos, ts)
                rec_arr.insert(ins_pos, (ts, amount_cents, counterparty_id))

                decision_id = f"dec_{tx_id}"
                tx_insert_rows.append(
                    (
                        tx_id,
                        caller.tenant_id,
                        batch_id,
                        account_id,
                        counterparty_id,
                        amount_cents,
                        tx_eval_obj["currency"],
                        tx_eval_obj["channel"],
                        tx_eval_obj["contact_email"],
                        ts,
                        json.dumps(tx_eval_obj["metadata"], sort_keys=True),
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
                tx_insert_rows,
            )
            conn.executemany(
                "INSERT INTO risk_decisions("
                "decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                "win_tx_count, win_amount_cents, win_unique_counterparties, reasons_json, evaluated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                dec_insert_rows,
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            if conn.in_transaction:
                conn.rollback()
            raise ConflictError("Transaction ID conflict in batch") from exc
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
    """根据决策单号查询当前租户下的单笔实时风控评估详情（防止跨租户 IDOR）。"""
    rt = get_runtime(db_path)
    conn = rt.get_connection()
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
