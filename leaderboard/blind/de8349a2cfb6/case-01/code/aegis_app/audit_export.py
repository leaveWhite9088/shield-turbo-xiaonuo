# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .config import parse_strict_int
from .db import open_connection

_ALLOWED_LITERAL_PLACEHOLDERS = frozenset({
    "{tenant_id}",
    "{total_records}",
    "{total_amount_cents}",
})
_EVENT_FILTER_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_SNAPSHOT_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}\.json$")
_BRACE_TOKEN_RE = re.compile(r"\{[^{}]*\}|\{|\}")


def _validate_and_render_title_format(
    title_format: str,
    *,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """严格字面占位符白名单校验与零 str.format 替换（彻底阻断属性反射与格式化宽度放大攻击）。"""
    if not isinstance(title_format, str) or not title_format.strip() or len(title_format) > 200:
        raise ValueError("Valid title_format is required (max 200 chars)")

    for m in _BRACE_TOKEN_RE.finditer(title_format):
        token = m.group(0)
        if token not in _ALLOWED_LITERAL_PLACEHOLDERS:
            raise ValueError(f"Forbidden or malformed template placeholder: {token}")

    rendered = (
        title_format
        .replace("{tenant_id}", str(tenant_id))
        .replace("{total_records}", str(total_records))
        .replace("{total_amount_cents}", str(total_amount_cents))
    )
    return rendered


def _stream_digest_from_cursor(
    tenant_id: str,
    rows_iter: Iterable[Any],
    sample_limit: int,
) -> dict[str, Any]:
    """O(1) 内存流式滚动计算审计摘要哈希，仅保留前 capped_sample 条轻量样本且不加载 payload_json。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    for r in rows_iter:
        log_id = int(r["log_id"])
        evt = str(r["event_type"])
        sev = str(r["severity"])
        amt = int(r["amount_cents"])
        masked_acc = str(r["masked_account"])
        ts = int(r["ts"])

        total_records += 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        event_counts[evt] = event_counts.get(evt, 0) + 1
        total_amount_cents += amt

        line = f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts}\n"
        hasher.update(line.encode("utf-8"))

        if len(samples) < capped_sample:
            samples.append(
                {
                    "log_id": log_id,
                    "event_type": evt,
                    "severity": sev,
                    "amount_cents": amt,
                    "masked_account": masked_acc,
                    "ts": ts,
                }
            )

    return {
        "tenant_id": tenant_id,
        "total_records": total_records,
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
    """统计指定时间窗口内的审计事件分布并流式计算顺序滚动完整性校验哈希。"""
    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(parse_strict_int(start_ts, "start_ts"))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(parse_strict_int(end_ts, "end_ts"))
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity))

    s_lim = parse_strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000)

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = open_connection(db_path)
    try:
        cur = conn.execute(sql, tuple(params))
        return _stream_digest_from_cursor(caller.tenant_id, cur, s_lim)
    finally:
        conn.close()


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（严格校验占位符白名单与事件过滤名）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    raw_lim = parse_strict_int(sample_limit, "sample_limit")
    if raw_lim < 0:
        raise ValueError("sample_limit must be non-negative")
    s_lim = max(0, min(raw_lim, 50))
    if not tpl_id or len(tpl_id) > 128 or not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid template_id and title_format are required")

    # 保存前预检模板格式占位符白名单
    _validate_and_render_title_format(
        t_fmt,
        tenant_id=caller.tenant_id,
        total_records=0,
        total_amount_cents=0,
    )
    if evt_flt and not _EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("Invalid extra_event_filter format")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
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
    """读取已保存的报表模板并安全渲染生成带格式化标题的审计汇总报告（二阶 SQL 全参数化 + 字面替换）。"""
    if not template_id:
        raise ValueError("template_id is required")
    conn = open_connection(db_path)
    try:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, template_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {template_id}")

        t_fmt = str(tpl["title_format"])
        evt_flt = str(tpl["extra_event_filter"] or "").strip()
        if evt_flt and not _EVENT_FILTER_RE.match(evt_flt):
            raise ValueError("Stored extra_event_filter is invalid")

        clauses = ["tenant_id = ?"]
        params: list[Any] = [caller.tenant_id]
        if start_ts is not None:
            clauses.append("ts >= ?")
            params.append(parse_strict_int(start_ts, "start_ts"))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(parse_strict_int(end_ts, "end_ts"))
        if evt_flt:
            clauses.append("event_type = ?")
            params.append(evt_flt)

        sql = (
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        cur = conn.execute(sql, tuple(params))
        digest = _stream_digest_from_cursor(caller.tenant_id, cur, int(tpl["sample_limit"]))
    finally:
        conn.close()

    rendered_title = _validate_and_render_title_format(
        t_fmt,
        tenant_id=caller.tenant_id,
        total_records=digest["total_records"],
        total_amount_cents=digest["total_amount_cents"],
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
    """安全读取当前租户归档目录下的合规季度快照文件（双重解码拦截 + 文件名白名单 + relative_to 物理边界锚定）。"""
    if not snapshot_name or not isinstance(snapshot_name, str):
        raise ValueError("snapshot_name is required")

    raw_name = snapshot_name.strip()
    if "\x00" in raw_name or "%" in raw_name or "/" in raw_name or "\\" in raw_name or ".." in raw_name:
        raise PermissionError("Invalid snapshot path traversal attempt")

    unquoted_1 = urllib.parse.unquote(raw_name)
    unquoted_2 = urllib.parse.unquote(unquoted_1)
    if unquoted_1 != raw_name or unquoted_2 != raw_name:
        raise PermissionError("Encoded path characters are forbidden in snapshot_name")
    if not _SNAPSHOT_FILENAME_RE.match(raw_name):
        raise PermissionError("Invalid snapshot filename format")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    target_path = (base_dir / raw_name).resolve()

    try:
        target_path.relative_to(base_dir)
    except ValueError as exc:
        raise PermissionError("Snapshot path escapes tenant directory") from exc

    if target_path.parent != base_dir or target_path.is_symlink():
        raise PermissionError("Snapshot symlink or nested directory access forbidden")

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
