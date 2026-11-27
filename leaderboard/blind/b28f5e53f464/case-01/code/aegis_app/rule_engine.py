# -*- coding: utf-8 -*-
"""实时交易风控评分、三跳制裁传染耦合、O(log W) 滑动窗口中位数与四重强原子批次引擎。"""
from __future__ import annotations

from bisect import insort
from collections import defaultdict
import json
import sqlite3
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    ALERT_QUOTA_BUCKET,
    CHANNEL_RISK_WEIGHTS,
    SANCTION_HOP_SCORES,
    SLIDING_WINDOW_SECONDS,
)
from .contagion_graph import compute_sanction_contagion_hop_fast
from .legacy_compat import apply_sovereign_settlement_adjustment
from .runtime import GatewayRuntime, get_runtime
from .validation import (
    MAX_REGEX_INPUT_LEN,
    MAX_RULE_DEPTH,
    MAX_RULE_NODES,
    safe_json_loads,
    strict_finite_float,
    strict_int,
    validate_contact_email,
    validate_safe_regex,
)
from .window_stats import AccountWindowState, compute_exact_median_cents

_LOGICAL_OPS = frozenset({"AND", "OR", "NOT"})
_LEAF_OPS = frozenset({"EQ", "NEQ", "GT", "GTE", "LT", "LTE", "IN", "CONTAINS", "REGEX"})


def validate_rule_tree(node: Any) -> None:
    """预检布尔规则树深度、总节点数、数值边界与安全正则，拦截复杂度与 ReDoS 炸弹。"""
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")
    if not node:
        return

    node_count = 0

    def _walk(cur: Any, depth: int) -> None:
        nonlocal node_count
        if depth > MAX_RULE_DEPTH:
            raise ValueError("Rule tree depth exceeds maximum allowed limit")
        if not isinstance(cur, dict):
            raise ValueError("Rule node must be an object")
        node_count += 1
        if node_count > MAX_RULE_NODES:
            raise ValueError("Rule tree node count exceeds maximum allowed limit")

        if "bonus_score" in cur and cur["bonus_score"] is not None:
            strict_int(cur["bonus_score"], "bonus_score", min_val=-1000, max_val=1000)

        op = str(cur.get("op") or "").upper()
        if op in _LOGICAL_OPS:
            children = cur.get("children")
            if not isinstance(children, list) or not children:
                raise ValueError(f"Logical operator {op} requires non-empty children list")
            if op == "NOT" and len(children) != 1:
                raise ValueError("NOT operator requires exactly 1 child")
            for ch in children:
                _walk(ch, depth + 1)
            return

        if op not in _LEAF_OPS:
            raise ValueError(f"Unsupported rule operator: {op}")
        field_name = str(cur.get("field") or "").strip()
        if not field_name or len(field_name) > 128:
            raise ValueError("Leaf rule node missing valid 'field'")
        target = cur.get("value")
        if op in ("GT", "GTE", "LT", "LTE"):
            strict_finite_float(target, "rule target value")
        elif op == "REGEX":
            if not isinstance(target, str):
                raise ValueError("REGEX target value must be a string")
            validate_safe_regex(target)
        elif op == "IN":
            if not isinstance(target, list) or len(target) > 256:
                raise ValueError("IN target must be a list of at most 256 items")

    _walk(node, 1)


def load_tenant_policy(
    db_path: str,
    tenant_id: str,
    *,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    rt = runtime or get_runtime(db_path)
    risk_state = rt.get_risk_state(tenant_id)
    if risk_state.policy_loaded:
        return dict(risk_state.policy)
    with rt.risk_lock(tenant_id):
        if not risk_state.policy_loaded:
            with rt.connection() as conn:
                return risk_state.load_policy(conn, tenant_id)
        return dict(risk_state.policy)


def update_tenant_policy(
    db_path: str,
    caller: CallerContext,
    updates: dict[str, Any],
    *,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    require_admin(caller)
    if not isinstance(updates, dict):
        raise ValueError("Policy update payload must be an object")

    rt = runtime or get_runtime(db_path)
    with rt.risk_lock(caller.tenant_id):
        risk_state = rt.get_risk_state(caller.tenant_id)
        if not risk_state.policy_loaded:
            with rt.connection() as conn:
                risk_state.load_policy(conn, caller.tenant_id)
        current = risk_state.policy

        high_amt = strict_int(
            updates.get("high_amount_cents", current["high_amount_cents"]),
            "high_amount_cents",
            min_val=1,
        )
        vel_tx = strict_int(
            updates.get("velocity_tx_limit", current["velocity_tx_limit"]),
            "velocity_tx_limit",
            min_val=1,
        )
        vel_amt = strict_int(
            updates.get("velocity_amount_cents", current["velocity_amount_cents"]),
            "velocity_amount_cents",
            min_val=0,
        )
        fanout = strict_int(
            updates.get("counterparty_fanout_limit", current["counterparty_fanout_limit"]),
            "counterparty_fanout_limit",
            min_val=0,
        )
        rev_th = strict_int(
            updates.get("review_threshold", current["review_threshold"]),
            "review_threshold",
            min_val=1,
        )
        rej_th = strict_int(
            updates.get("reject_threshold", current["reject_threshold"]),
            "reject_threshold",
            min_val=rev_th,
        )
        custom_rules = updates.get("custom_rules", current["custom_rules"])
        if not isinstance(custom_rules, dict):
            raise ValueError("custom_rules must be a JSON object")
        validate_rule_tree(custom_rules)

        new_ver = int(current["policy_version"]) + 1
        now_ts = int(caller.request_ts or int(time.time()))
        rules_json = json.dumps(custom_rules)

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

        risk_state.policy = {
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
        risk_state.policy_epoch += 1
        return dict(risk_state.policy)


def _extract_field(tx: dict[str, Any], field_path: str) -> Any:
    if field_path.startswith("metadata."):
        sub_key = field_path.split(".", 1)[1]
        meta = tx.get("metadata") or {}
        if not isinstance(meta, dict):
            return None
        return meta.get(sub_key)
    return tx.get(field_path)


def eval_rule_node(
    node: dict[str, Any],
    tx: dict[str, Any],
    *,
    _depth: int = 1,
) -> tuple[bool, int, list[str]]:
    if _depth > MAX_RULE_DEPTH:
        raise ValueError("Rule tree depth exceeds maximum allowed limit")
    if not isinstance(node, dict):
        raise ValueError("Rule node must be an object")

    op = str(node.get("op") or "").upper()
    raw_bonus = node.get("bonus_score")
    bonus = 0 if raw_bonus is None else strict_int(raw_bonus, "bonus_score", min_val=-1000, max_val=1000)
    reason = str(node.get("reason") or "").strip()

    if op in _LOGICAL_OPS:
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError(f"Logical operator {op} requires non-empty children list")
        if op == "NOT" and len(children) != 1:
            raise ValueError("NOT operator requires exactly 1 child")

        child_results = [eval_rule_node(ch, tx, _depth=_depth + 1) for ch in children]
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
        if isinstance(actual, bool) or isinstance(target, bool):
            matched = isinstance(actual, bool) and isinstance(target, bool) and actual == target
        else:
            matched = actual == target
    elif op == "NEQ":
        if isinstance(actual, bool) or isinstance(target, bool):
            matched = not (isinstance(actual, bool) and isinstance(target, bool) and actual == target)
        else:
            matched = actual != target
    elif op in ("GT", "GTE", "LT", "LTE"):
        t_num = strict_finite_float(target, "rule target value")
        if actual is not None:
            a_num = strict_finite_float(actual, f"tx.{field_name}")
            if op == "GT":
                matched = a_num > t_num
            elif op == "GTE":
                matched = a_num >= t_num
            elif op == "LT":
                matched = a_num < t_num
            else:
                matched = a_num <= t_num
    elif op == "IN":
        matched = isinstance(target, list) and actual in target
    elif op == "CONTAINS":
        matched = isinstance(actual, str) and isinstance(target, str) and (target in actual)
    elif op == "REGEX":
        if not isinstance(target, str):
            raise ValueError("REGEX target must be a string")
        compiled = validate_safe_regex(target)
        if isinstance(actual, str):
            if len(actual) > MAX_REGEX_INPUT_LEN:
                raise ValueError("Input string for REGEX exceeds maximum allowed length")
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
    if email is not None and not validate_contact_email(email):
        raise ValueError("Invalid contact_email format in sample_tx")
    if "amount_cents" in sample_tx and sample_tx["amount_cents"] is not None:
        strict_int(sample_tx["amount_cents"], "amount_cents", min_val=0)
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


def _add_staged_edge(
    staged_edges: dict[str, dict[str, list[int]]],
    u: str,
    v: str,
    ts: int,
) -> None:
    u_map = staged_edges.setdefault(u, {})
    lst = u_map.get(v)
    if lst is None:
        u_map[v] = [ts]
    else:
        insort(lst, ts)
    if u != v:
        v_map = staged_edges.setdefault(v, {})
        lst2 = v_map.get(u)
        if lst2 is None:
            v_map[u] = [ts]
        else:
            insort(lst2, ts)


def evaluate_transaction_batch(
    db_path: str,
    caller: CallerContext,
    *,
    batch_id: str,
    transactions: list[dict[str, Any]],
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """按输入顺序逐笔评估实时交易批次并执行数据库/滑窗/传染图/告警配额四位一体强原子提交。"""
    clean_batch_id = str(batch_id or "").strip()
    if not clean_batch_id or len(clean_batch_id) > 128:
        raise ValueError("Valid batch_id is required")
    if not isinstance(transactions, list) or len(transactions) == 0:
        raise ValueError("batch_id and non-empty transactions list are required")
    if len(transactions) > 2000:
        raise ValueError("Transaction batch size exceeds maximum allowed limit")

    # 1. 在获取任何业务锁前先做全批严格参数校验
    parsed_items: list[dict[str, Any]] = []
    seen_tx_ids: set[str] = set()
    for item in transactions:
        if not isinstance(item, dict):
            raise ValueError("Each transaction must be an object")
        tx_id = str(item.get("tx_id") or "").strip()
        account_id = str(item.get("account_id") or "").strip()
        counterparty_id = str(item.get("counterparty_id") or "").strip()
        if not tx_id or len(tx_id) > 128 or not account_id or not counterparty_id:
            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
        if tx_id in seen_tx_ids:
            raise ValueError(f"Duplicate tx_id within batch: {tx_id}")
        seen_tx_ids.add(tx_id)

        amount_cents = strict_int(item.get("amount_cents"), "amount_cents", min_val=1)
        ts = strict_int(item.get("ts"), "ts", min_val=1)
        currency = str(item.get("currency") or "USD").strip()
        channel = str(item.get("channel") or "POS_CHIP").strip()
        contact_email = item.get("contact_email")
        if not validate_contact_email(contact_email):
            raise ValueError(f"Invalid contact_email in transaction {tx_id}")
        raw_meta = item.get("metadata")
        if raw_meta is None:
            metadata: dict[str, Any] = {}
        elif isinstance(raw_meta, dict):
            metadata = raw_meta
        else:
            raise ValueError("Transaction metadata must be a JSON object")

        parsed_items.append(
            {
                "tx_id": tx_id,
                "account_id": account_id,
                "counterparty_id": counterparty_id,
                "amount_cents": amount_cents,
                "currency": currency,
                "channel": channel,
                "contact_email": str(contact_email).strip(),
                "ts": ts,
                "metadata": metadata,
            }
        )

    rt = runtime or get_runtime(db_path)
    results: list[dict[str, Any]] = []
    counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}

    # 2. 严格全局锁偏序：tenant_risk_lock -> quota_lock(REALTIME_ALERT_POOL) -> db write_tx
    with rt.risk_lock(caller.tenant_id):
        with rt.quota_lock(caller.tenant_id, ALERT_QUOTA_BUCKET):
            risk_state = rt.get_risk_state(caller.tenant_id)
            with rt.connection() as conn:
                if not risk_state.policy_loaded:
                    risk_state.load_policy(conn, caller.tenant_id)
                if not risk_state.sanctions_loaded:
                    risk_state.load_sanctions(conn, caller.tenant_id)
                if not risk_state.graph_loaded:
                    risk_state.load_graph(conn, caller.tenant_id)

                q_row = conn.execute(
                    "SELECT remaining_quota FROM tenant_quotas WHERE tenant_id = ? AND quota_type = ?",
                    (caller.tenant_id, ALERT_QUOTA_BUCKET),
                ).fetchone()
                alert_quota_rem = int(q_row["remaining_quota"]) if q_row else 0

            policy = risk_state.policy
            window_undos: dict[str, dict[str, Any]] = {}
            staged_by_account: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
            staged_edges: dict[str, dict[str, list[int]]] = {}
            tx_rows: list[tuple[Any, ...]] = []
            dec_rows: list[tuple[Any, ...]] = []
            alert_consumed = 0
            last_alert_ts = 0

            try:
                for tx_eval_obj in parsed_items:
                    tx_id = tx_eval_obj["tx_id"]
                    account_id = tx_eval_obj["account_id"]
                    counterparty_id = tx_eval_obj["counterparty_id"]
                    amount_cents = tx_eval_obj["amount_cents"]
                    ts = tx_eval_obj["ts"]

                    sanction_hop = compute_sanction_contagion_hop_fast(
                        risk_state,
                        account_id,
                        counterparty_id,
                        ts,
                        staged_edges=staged_edges,
                    )

                    win_state = risk_state.window_accounts.get(account_id)
                    if win_state is None or not win_state.initialized:
                        win_state = AccountWindowState()
                        with rt.connection() as conn:
                            acct_rows = conn.execute(
                                "SELECT ts, amount_cents, counterparty_id FROM transactions "
                                "WHERE tenant_id = ? AND account_id = ? ORDER BY ts ASC",
                                (caller.tenant_id, account_id),
                            ).fetchall()
                        win_state.load_rows(
                            [(int(r["ts"]), int(r["amount_cents"]), str(r["counterparty_id"])) for r in acct_rows]
                        )
                        risk_state.window_accounts[account_id] = win_state

                    undo_log = window_undos.get(account_id)
                    if undo_log is None:
                        undo_log = {}
                        window_undos[account_id] = undo_log

                    if ts >= win_state.max_ts:
                        win_tx_count, win_amount_cents, win_unique_cps, win_median_cents = (
                            win_state.push_monotonic(ts, amount_cents, counterparty_id, undo_log)
                        )
                    else:
                        # 乱序时间戳精确回退路径：利用复合索引区间扫描 + 当批暂存列表
                        win_start = ts - SLIDING_WINDOW_SECONDS
                        with rt.connection() as conn:
                            hist_rows = conn.execute(
                                "SELECT amount_cents, counterparty_id FROM transactions "
                                "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ?",
                                (caller.tenant_id, account_id, win_start, ts),
                            ).fetchall()
                        win_amts: list[int] = [amount_cents]
                        win_cps: set[str] = {counterparty_id}
                        win_amount_cents = amount_cents
                        for hr in hist_rows:
                            h_amt = int(hr["amount_cents"])
                            win_amts.append(h_amt)
                            win_amount_cents += h_amt
                            win_cps.add(str(hr["counterparty_id"]))
                        for s_ts, s_amt, s_cp in staged_by_account.get(account_id, ()):
                            if win_start <= s_ts <= ts:
                                win_amts.append(s_amt)
                                win_amount_cents += s_amt
                                win_cps.add(s_cp)
                        win_tx_count = len(win_amts)
                        win_unique_cps = len(win_cps)
                        win_median_cents = compute_exact_median_cents(win_amts)
                        win_state.insert_out_of_order(ts, amount_cents, counterparty_id, undo_log)

                    staged_by_account[account_id].append((ts, amount_cents, counterparty_id))

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
                        if alert_quota_rem >= 1:
                            alert_quota_rem -= 1
                            alert_consumed += 1
                            last_alert_ts = ts
                            alert_dispatched = True
                            reasons.append("ALERT_QUOTA_CONSUMED")
                        else:
                            reasons.append("ALERT_POOL_DEPLETED")

                    _add_staged_edge(staged_edges, account_id, counterparty_id, ts)

                    decision_id = f"dec_{tx_id}"
                    tx_rows.append(
                        (
                            tx_id,
                            caller.tenant_id,
                            clean_batch_id,
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
                    dec_rows.append(
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

                # 单一原子 BEGIN IMMEDIATE 事务落盘全部交易、决策与告警配额扣减
                with rt.write_tx() as conn:
                    if alert_consumed > 0:
                        cur = conn.execute(
                            "UPDATE tenant_quotas SET remaining_quota = remaining_quota - ?, updated_at = ? "
                            "WHERE tenant_id = ? AND quota_type = ? AND remaining_quota >= ?",
                            (
                                alert_consumed,
                                last_alert_ts,
                                caller.tenant_id,
                                ALERT_QUOTA_BUCKET,
                                alert_consumed,
                            ),
                        )
                        if cur.rowcount != 1:
                            raise RuntimeError("Alert quota atomic deduction failed")

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
                        dec_rows,
                    )

                # 数据库 COMMIT 成功后才将暂存边合并进常驻传染图
                for u_node, nbr_map in staged_edges.items():
                    for v_node, ts_list in nbr_map.items():
                        if u_node <= v_node:
                            for e_ts in ts_list:
                                risk_state.add_edge(u_node, v_node, e_ts)

            except BaseException as exc:
                for acct_id, undo_log in window_undos.items():
                    win_st = risk_state.window_accounts.get(acct_id)
                    if win_st is not None:
                        win_st.rollback(undo_log)
                if isinstance(exc, sqlite3.IntegrityError):
                    raise ValueError("Duplicate or conflicting transaction in batch") from exc
                raise

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
    *,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    clean_id = str(decision_id or "").strip()
    if not clean_id:
        raise ValueError("decision_id is required")

    rt = runtime or get_runtime(db_path)
    with rt.connection() as conn:
        row = conn.execute(
            "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
            "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
            "sanction_hop, reasons_json, evaluated_at "
            "FROM risk_decisions WHERE tenant_id = ? AND decision_id = ?",
            (caller.tenant_id, clean_id),
        ).fetchone()
        if not row:
            raise LookupError(f"Decision record not found: {clean_id}")
        reasons_list = safe_json_loads(row["reasons_json"])
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
