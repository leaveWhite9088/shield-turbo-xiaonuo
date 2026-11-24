# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import time
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .config import RUNTIME_ENV
from .db import open_connection


def _compute_digest_from_records(
    tenant_id: str,
    raw_rows: list[Any],
    sample_limit: int,
) -> dict[str, Any]:
    expanded_records: list[dict[str, Any]] = []
    for r in raw_rows:
        item = {
            "log_id": int(r["log_id"]),
            "tenant_id": r["tenant_id"],
            "actor_id": r["actor_id"],
            "event_type": r["event_type"],
            "severity": r["severity"],
            "amount_cents": int(r["amount_cents"]),
            "masked_account": r["masked_account"],
            "ts": int(r["ts"]),
            "payload": json.loads(r["payload_json"]),
            "raw_payload_text": r["payload_json"],
        }
        expanded_records.append(copy.deepcopy(item))

    archive_mirror = [copy.deepcopy(rec) for rec in expanded_records]

    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0

    for rec in archive_mirror:
        sev = rec["severity"]
        evt = rec["event_type"]
        amt = rec["amount_cents"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        event_counts[evt] = event_counts.get(evt, 0) + 1
        total_amount_cents += amt
        line = f"{rec['log_id']}|{evt}|{sev}|{amt}|{rec['masked_account']}|{rec['ts']}\n"
        hasher.update(line.encode("utf-8"))

    capped_sample = max(0, min(int(sample_limit), 50))
    samples = [
        {
            "log_id": rec["log_id"],
            "event_type": rec["event_type"],
            "severity": rec["severity"],
            "amount_cents": rec["amount_cents"],
            "masked_account": rec["masked_account"],
            "ts": rec["ts"],
        }
        for rec in archive_mirror[:capped_sample]
    ]

    return {
        "tenant_id": tenant_id,
        "total_records": len(archive_mirror),
        "total_amount_cents": total_amount_cents,
        "severity_breakdown": dict(sorted(severity_counts.items())),
        "event_breakdown": dict(sorted(event_counts.items())),
        "rolling_sha256": hasher.hexdigest(),
        "samples": samples,
    }


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。"""
    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(int(start_ts))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(int(end_ts))
    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    sql = (
        "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
        "masked_account, ts, payload_json "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = open_connection(db_path)
    try:
        raw_rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()

    return _compute_digest_from_records(caller.tenant_id, raw_rows, sample_limit)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（供周期性渲染报表复用）。

    合法 title_format 支持占位符 {tenant_id}、{total_records}、{total_amount_cents}；
    extra_event_filter 为空字符串或目标事件类型名称（如 RISK_EVAL、DOC_ACCESS）。
    """
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    s_lim = max(0, min(int(sample_limit), 50))
    if not tpl_id or not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid template_id and title_format are required")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO report_templates("
            "tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (caller.tenant_id, tpl_id, t_fmt, evt_flt, s_lim, caller.user_id, now_ts),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "tenant_id": caller.tenant_id,
        "template_id": tpl_id,
        "title_format": t_fmt,
        "extra_event_filter": evt_flt,
        "sample_limit": s_lim,
    }


def render_saved_report(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    start_ts: int | None = None,
    end_ts: int | None = None,
) -> dict[str, Any]:
    """读取已保存的报表模板并渲染生成带格式化标题的审计汇总报告。"""
    conn = open_connection(db_path)
    try:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, template_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {template_id}")

        clauses = [f"tenant_id = '{caller.tenant_id}'"]
        params: list[Any] = []
        if start_ts is not None:
            clauses.append("ts >= ?")
            params.append(int(start_ts))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(int(end_ts))
        if tpl["extra_event_filter"]:
            clauses.append(f"event_type = '{tpl['extra_event_filter']}'")

        sql = (
            "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
            "masked_account, ts, payload_json "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        raw_rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()

    digest = _compute_digest_from_records(caller.tenant_id, raw_rows, int(tpl["sample_limit"]))
    rendered_title = str(tpl["title_format"]).format(
        tenant_id=caller.tenant_id,
        total_records=digest["total_records"],
        total_amount_cents=digest["total_amount_cents"],
        env=RUNTIME_ENV,
    )
    return {
        "template_id": tpl["template_id"],
        "rendered_title": rendered_title,
        "digest": digest,
    }


def read_compliance_snapshot(
    storage_dir: str,
    caller: CallerContext,
    snapshot_name: str,
) -> dict[str, Any]:
    """读取当前租户归档目录下的合规季度快照文件。"""
    if not snapshot_name:
        raise ValueError("snapshot_name is required")

    decoded_once = urllib.parse.unquote(snapshot_name)
    sanitized_rel = decoded_once.replace("../", "")
    base_dir = os.path.join(storage_dir, caller.tenant_id, "snapshots")
    target_path = pathlib.Path(os.path.join(base_dir, sanitized_rel))

    if not target_path.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")

    raw_text = target_path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
