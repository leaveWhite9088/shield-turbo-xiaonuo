# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。

批次评估的强原子性（四位一体）：
    在**同一个** ``BEGIN IMMEDIATE`` 事务内完成
    ``transactions`` 落库 → ``risk_decisions`` 落库 → ``REALTIME_ALERT_POOL`` 条件扣减 → 提交；
    任意一笔校验/落库失败（含并发写冲突）→ 整批回滚，数据库、滑窗统计、传染图与告警池状态
    完全一致（滑窗与传染图的增量在提交成功后才生效，失败即丢弃）。

加锁偏序（全局统一，永不交叉等待）：
    SQL 写事务（BEGIN IMMEDIATE）→ 内存滑窗/传染图结构锁 → Python 共享锁，任何路径都只按此顺序持有。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    CHANNEL_RISK_WEIGHTS,
    MAX_BATCH_ACCOUNTS,
    MAX_BATCH_TXS,
    MAX_ID_CHARS,
    MAX_IN_VALUE,
    MAX_RULE_DEPTH,
    MAX_RULE_NODES,
    MAX_RULE_PATTERN_CHARS,
    MAX_TS_ABS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import compute_sanction_contagion_hop
from .db import GatewayDB
from .guards import GuardError, guard_json_obj, guard_regex, strict_int
from .ledger_ops import refund_realtime_alert_quota, try_consume_realtime_alert_quota
from .legacy_compat import apply_sovereign_settlement_adjustment
from .window_stats import AccountWindow, compute_exact_median_cents

PARTNER_EMAIL_PATTERN = re.compile(
    r"^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)$"
)
_EMAIL_MAX_CHARS = 254


def validate_contact_email(email: str) -> bool:
    if not isinstance(email, str) or not email or len(email) > _EMAIL_MAX_CHARS:
        return False
    return PARTNER_EMAIL_PATTERN.match(email) is not None


def load_tenant_policy(db_path: str, tenant_id: str, *, db: GatewayDB | None = None) -> dict[str, Any]:
    work = db if db is not None else GatewayDB(db_path)
    own = db is None
    try:
        row = work.one(
            "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, "
            "velocity_amount_cents, counterparty_fanout_limit, review_threshold, "
            "reject_threshold, custom_rules_json, updated_at "
            "FROM tenant_policies WHERE tenant_id = ?",
            (tenant_id,),
        )
    finally:
        if own:
            work.close_thread()
    if not row:
        raise LookupError(f"Policy configuration missing for {tenant_id}")
    policy = dict(row)
    policy["custom_rules"] = json.loads(policy["custom_rules_json"])
    return policy


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy updates must be an object")
    current = load_tenant_policy(db_path, caller.tenant_id, db=caller.db)
    high_amt = strict_int(updates.get("high_amount_cents", current["high_amount_cents"]), name="high_amount_cents")
    vel_tx = strict_int(updates.get("velocity_tx_limit", current["velocity_tx_limit"]), name="velocity_tx_limit")
    vel_amt = strict_int(updates.get("velocity_amount_cents", current["velocity_amount_cents"]),
                         name="velocity_amount_cents")
    fanout = strict_int(updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]),
                        name="counterparty_fanout_limit")
    rev_th = strict_int(updates.get("review_threshold", current["review_threshold"]), name="review_threshold")
    rej_th = strict_int(updates.get("reject_threshold", current["reject_threshold"]), name="reject_threshold")
    custom_rules = updates.get("custom_rules", current["custom_rules"])

    if high_amt <= 0 or vel_tx <= 0 or rev_th <= 0 or rej_th < rev_th:
        raise ValueError("Invalid policy threshold values")
    if not isinstance(custom_rules, dict):
        raise ValueError("custom_rules must be a JSON object")
    _validate_rule_tree(custom_rules)

    new_ver = int(current["policy_version"]) + 1
    now_ts = int(caller.request_ts or int(time.time()))
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        db.write(
            lambda conn: conn.execute(
                "UPDATE tenant_policies SET policy_version = ?, high_amount_cents = ?, "
                "velocity_tx_limit = ?, velocity_amount_cents = ?, counterparty_fanout_limit = ?, "
                "review_threshold = ?, reject_threshold = ?, custom_rules_json = ?, updated_at = ? "
                "WHERE tenant_id = ?",
                (
                    new_ver, high_amt, vel_tx, vel_amt, fanout, rev_th, rej_th,
                    json.dumps(custom_rules), now_ts, caller.tenant_id,
                ),
            )
        )
        if caller.shared is not None:
            caller.shared.epoch.bump("policy")
            caller.shared.policy_cache.pop(caller.tenant_id, None)
    finally:
        if own:
            db.close_thread()
    return load_tenant_policy(db_path, caller.tenant_id, db=db if not own else None)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        return meta.get(sub_key)
    return tx.get(field_path)


def _validate_rule_tree(tree: dict[str, Any]) -> None:
    """落库前静态校验规则树：节点数/深度上限 + 正则模式白名单（拒绝回溯炸弹）。"""
    stack: list[tuple[Any, int]] = [(tree, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_RULE_NODES:
            raise ValueError("Rule tree exceeds node limit")
        if depth > MAX_RULE_DEPTH:
            raise ValueError("Rule tree exceeds depth limit")
        if not isinstance(node, dict):
            raise ValueError("Rule node must be an object")
        op = str(node.get("op") or "").upper()
        if op in ("AND", "OR", "NOT"):
            children = node.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            for ch in children:
                stack.append((ch, depth + 1))
        elif op == "REGEX":
            pattern = node.get("value")
            if not isinstance(pattern, str):
                raise ValueError("REGEX rule requires string pattern")
            guard_regex(pattern)
        elif op not in ("EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS"):
            raise ValueError(f"Unsupported rule operator: {op}")


def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    bonus = strict_int(node.get("bonus_score") or 0, name="bonus_score")
    reason = str(node.get("reason") or "").strip()

    if op in ("AND", "OR", "NOT"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")

        child_results = [eval_rule_node(ch, tx) for ch in children]
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
        if actual is not None:
            try:
                a_num = float(actual)
                t_num = float(target)
            except (TypeError, ValueError) as exc:
                raise ValueError("Numeric comparison requires numeric operands") from exc
            if op == "GT":
                matched = a_num > t_num
            elif op == "GTE":
                matched = a_num >= t_num
            elif op == "LT":
                matched = a_num < t_num
            else:
                matched = a_num <= t_num
    elif op == "IN":
        matched = isinstance(target, list) and len(target) <= MAX_IN_VALUE and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if isinstance(actual, str) and isinstance(target, str):
            matched = guard_regex(target).search(actual) is not None
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
    if not isinstance(rule_tree, dict):
        raise ValueError("rule_tree must be an object")
    _validate_rule_tree(rule_tree)
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
        tx, policy, raw_ch_weight,
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


def _parse_tx(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("Each transaction must be an object")
    tx_id = str(item.get("tx_id") or "").strip()
    account_id = str(item.get("account_id") or "").strip()
    counterparty_id = str(item.get("counterparty_id") or "").strip()
    amount_cents = strict_int(item.get("amount_cents") or 0, name="amount_cents")
    currency = str(item.get("currency") or "USD").strip()
    channel = str(item.get("channel") or "POS_CHIP").strip()
    contact_email = str(item.get("contact_email") or "").strip()
    ts = strict_int(item.get("ts") or 0, name="ts")
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}

    if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
        raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
    if not validate_contact_email(contact_email):
        raise ValueError(f"Invalid contact_email in transaction {tx_id}")
    if len(tx_id) > MAX_ID_CHARS or len(account_id) > MAX_ID_CHARS or len(counterparty_id) > MAX_ID_CHARS:
        raise ValueError("Transaction identifier exceeds length limit")
    if len(currency) > 16 or len(channel) > 64:
        raise ValueError("Transaction field exceeds length limit")
    if amount_cents > MAX_IN_VALUE or ts > MAX_TS_ABS:
        raise ValueError("Transaction amount or timestamp out of supported range")
    return {
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

def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次并持久化交易及风控决策记录（批次级强原子）。"""
    if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if not isinstance(batch_id, str) or len(batch_id) > MAX_ID_CHARS:
        raise ValueError("Invalid batch_id")
    if len(transactions) > MAX_BATCH_TXS:
        raise ValueError(f"Batch exceeds transaction limit of {MAX_BATCH_TXS}")

    parsed = [_parse_tx(item) for item in transactions]
    if len({t["account_id"] for t in parsed}) > MAX_BATCH_ACCOUNTS:
        raise ValueError(f"Batch exceeds account limit of {MAX_BATCH_ACCOUNTS}")

    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    shared = caller.shared if not own else None
    windows = getattr(shared, "windows", None)
    store = getattr(shared, "contagion", None)
    try:
        policy = load_tenant_policy(db_path, caller.tenant_id, db=db)
        if windows is not None:
            windows.ensure(db, caller.tenant_id)

        results: list[dict[str, Any]] = []
        counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
        tx_rows: list[tuple] = []
        decision_rows: list[tuple] = []
        alert_flags: list[bool | None] = []
        batch_rows: dict[str, list[tuple]] = {}

        for tx in parsed:
            account_id = tx["account_id"]
            ts = tx["ts"]
            amount_cents = tx["amount_cents"]
            counterparty_id = tx["counterparty_id"]
            win_start = ts - SLIDING_WINDOW_SECONDS

            hop = compute_sanction_contagion_hop(
                db_path, caller.tenant_id, account_id, counterparty_id, ts, db=db, store=store,
            )

            # 批次内滚动状态：同一批次里先前已评估但尚未提交的同账户交易，按真实提交语义计入窗口
            prev = batch_rows.get(account_id, ())
            if windows is not None:
                win_tx_count, win_amount_cents, win_median_cents, win_unique_cps = windows.stats(
                    caller.tenant_id, account_id, win_start, ts, amount_cents, counterparty_id, prev,
                )
            else:
                hist = _db_window(db, caller.tenant_id, account_id, win_start, ts)
                amounts = [h[2] for h in hist] + [r[1] for r in prev] + [amount_cents]
                win_tx_count = len(amounts)
                win_amount_cents = sum(amounts)
                win_median_cents = compute_exact_median_cents(amounts)
                win_unique_cps = len({h[1] for h in hist} | {r[3] for r in prev} | {counterparty_id})
            batch_rows.setdefault(account_id, []).append((tx["tx_id"], amount_cents, ts, counterparty_id))

            tx_eval_obj = {
                "tx_id": tx["tx_id"],
                "account_id": account_id,
                "counterparty_id": counterparty_id,
                "amount_cents": amount_cents,
                "currency": tx["currency"],
                "channel": tx["channel"],
                "contact_email": tx["contact_email"],
                "ts": ts,
                "metadata": tx["metadata"],
            }
            risk_score, decision, reasons = compute_single_tx_decision(
                tx_eval_obj,
                policy,
                win_tx_count=win_tx_count,
                win_amount_cents=win_amount_cents,
                win_unique_cps=win_unique_cps,
                win_median_cents=win_median_cents,
                sanction_hop=hop,
            )
            reasons = list(reasons)
            decision_id = f"dec_{tx['tx_id']}"
            tx_rows.append((
                tx["tx_id"], caller.tenant_id, batch_id, account_id, counterparty_id, amount_cents,
                tx["currency"], tx["channel"], tx["contact_email"], ts,
                json.dumps(tx["metadata"], sort_keys=True),
            ))
            decision_rows.append((
                decision_id, tx["tx_id"], caller.tenant_id, account_id, risk_score, decision,
                win_tx_count, win_amount_cents, win_unique_cps, win_median_cents, hop,
                json.dumps(reasons), ts,
            ))
            alert_flags.append(False if decision == "REJECT" else None)
            results.append({
                "decision_id": decision_id,
                "tx_id": tx["tx_id"],
                "account_id": account_id,
                "risk_score": risk_score,
                "decision": decision,
                "sanction_hop": hop,
                "alert_dispatched": False,
                "window": {
                    "tx_count": win_tx_count,
                    "amount_cents": win_amount_cents,
                    "unique_counterparties": win_unique_cps,
                    "median_cents": win_median_cents,
                },
                "reasons": reasons,
            })
            counts[decision] += 1

        def _tx(conn):
            conn.executemany(
                "INSERT INTO transactions("
                "tx_id, tenant_id, batch_id, account_id, counterparty_id, amount_cents, "
                "currency, channel, contact_email, ts, metadata_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tx_rows,
            )
            conn.executemany(
                "INSERT INTO risk_decisions("
                "decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
                "sanction_hop, reasons_json, evaluated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                decision_rows,
            )
            # 告警池扣减落在同一批次事务内：后续任何异常整批回滚，配额不泄漏
            for idx, flag in enumerate(alert_flags):
                if flag is None:
                    continue
                r = results[idx]
                if try_consume_realtime_alert_quota(db_path, caller.tenant_id, tx_rows[idx][9], conn=conn):
                    alert_flags[idx] = True
                    r["alert_dispatched"] = True
                    r["reasons"].append("ALERT_QUOTA_CONSUMED")
                else:
                    alert_flags[idx] = False
                    r["reasons"].append("ALERT_POOL_DEPLETED")

        db.write(_tx)

        # 提交成功后才演进内存结构（提交失败已整批回滚，内存与数据库保持严格一致）
        if windows is not None:
            for tx in parsed:
                windows.record(
                    caller.tenant_id, tx["account_id"], tx["tx_id"], tx["amount_cents"], tx["ts"],
                    tx["counterparty_id"], tx["ts"] - SLIDING_WINDOW_SECONDS,
                )
        if store is not None:
            for tx in parsed:
                store.record_edge(caller.tenant_id, tx["account_id"], tx["counterparty_id"], tx["ts"])
    finally:
        if own:
            db.close_thread()

    return {
        "tenant_id": caller.tenant_id,
        "batch_id": batch_id,
        "evaluated_count": len(results),
        "decision_counts": counts,
        "results": results,
    }


def _db_window(db: GatewayDB, tenant_id: str, account_id: str, win_start: int, ts: int) -> list[tuple]:
    rows = db.rows(
        "SELECT tx_id, counterparty_id, amount_cents, ts FROM transactions "
        "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ?",
        (tenant_id, account_id, win_start, ts),
    )
    return [(r[0], r[1], int(r[2]), int(r[3])) for r in rows]


def get_risk_decision_detail(
    db_path: str,
    caller: CallerContext,
    decision_id: str,
) -> dict[str, Any]:
    """按决策 ID 读取单笔风控决策明细（含窗口四维、三跳传染等级与命中原因）。"""
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        row = db.one(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE tenant_id = ? AND decision_id = ?",
            (caller.tenant_id, str(decision_id)),
        )
    finally:
        if own:
            db.close_thread()
    if not row:
        raise LookupError(f"Risk decision not found: {decision_id}")
    return {
        "decision_id": row["decision_id"],
        "tx_id": row["tx_id"],
        "tenant_id": row["tenant_id"],
        "account_id": row["account_id"],
        "risk_score": int(row["risk_score"]),
        "decision": row["decision"],
        "sanction_hop": int(row["sanction_hop"]),
        "evaluated_at": int(row["evaluated_at"]),
        "window": {
            "tx_count": int(row["win_tx_count"]),
            "amount_cents": int(row["win_amount_cents"]),
            "unique_counterparties": int(row["win_unique_counterparties"]),
            "median_cents": int(row["win_median_cents"]),
        },
        "reasons": json.loads(row["reasons_json"]),
    }
