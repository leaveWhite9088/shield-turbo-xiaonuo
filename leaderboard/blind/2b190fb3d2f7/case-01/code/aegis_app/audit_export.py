# -*- coding: utf-8 -*-
"""合规审计流水流式汇总摘要导出、无反射安全报表模板渲染与路径锚定快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sqlite3
import time
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .db import borrow_connection, write_transaction
from .runtime_state import parse_strict_int

_ALLOWED_PLACEHOLDERS = frozenset({"{tenant_id}", "{total_records}", "{total_amount_cents}"})
_BRACE_TOKEN_RE = re.compile(r"\{[^{}]*\}")
_EVENT_FILTER_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_SAFE_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_STREAM_BATCH_SIZE = 512
_MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024


def _validate_title_format(title_format: str) -> str:
    """严格白名单校验报表标题模板：仅允许三个字面占位符，禁止任何格式说明符/属性反射/宽度放大。"""
    if not isinstance(title_format, str):
        raise ValueError("title_format must be a string")
    t_fmt = title_format.strip()
    if not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid template_id and title_format are required")

    for match in _BRACE_TOKEN_RE.finditer(t_fmt):
        if match.group(0) not in _ALLOWED_PLACEHOLDERS:
            raise ValueError(f"Disallowed placeholder in title_format: {match.group(0)}")

    stripped = _BRACE_TOKEN_RE.sub("", t_fmt)
    if "{" in stripped or "}" in stripped:
        raise ValueError("Unbalanced or nested braces in title_format")
    return t_fmt


def _render_title_safely(
    title_format: str,
    *,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """纯字面字符串替换渲染报表标题（严禁调用 str.format，彻底杜绝属性反射与宽度填充放大）。"""
    safe_fmt = _validate_title_format(title_format)
    return (
        safe_fmt.replace("{tenant_id}", str(tenant_id))
        .replace("{total_records}", str(total_records))
        .replace("{total_amount_cents}", str(total_amount_cents))
    )


def _compute_digest_streaming(
    cursor: sqlite3.Cursor,
    tenant_id: str,
    sample_limit: int,
) -> dict[str, Any]:
    """基于 fetchmany(512) 游标流式聚合审计流水并计算滚动 SHA-256，维持 O(1) 峰值内存。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_records = 0
    total_amount_cents = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    while True:
        chunk = cursor.fetchmany(_STREAM_BATCH_SIZE)
        if not chunk:
            break
        for r in chunk:
            log_id = int(r["log_id"])
            evt = str(r["event_type"])
            sev = str(r["severity"])
            amt = int(r["amount_cents"])
            masked_acc = str(r["masked_account"])
            ts = int(r["ts"])

            total_records += 1
            total_amount_cents += amt
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            event_counts[evt] = event_counts.get(evt, 0) + 1

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
    """流式统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。"""
    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(parse_strict_int(start_ts, field_name="start_ts", min_val=0))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(parse_strict_int(end_ts, field_name="end_ts", min_val=0))
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity))

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    with borrow_connection(db_path) as conn:
        cur = conn.execute(sql, tuple(params))
        return _compute_digest_streaming(cur, caller.tenant_id, sample_limit)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（入口严格校验占位符白名单与事件过滤标识符）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    if not tpl_id or len(tpl_id) > 128:
        raise ValueError("Valid template_id and title_format are required")

    t_fmt = _validate_title_format(title_format)
    evt_flt = str(extra_event_filter or "").strip()
    if evt_flt and not _EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("Invalid extra_event_filter identifier")

    raw_lim = parse_strict_int(sample_limit, field_name="sample_limit", min_val=0, max_val=1000)
    s_lim = max(0, min(raw_lim, 50))

    now_ts = int(caller.request_ts or int(time.time()))
    with write_transaction(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO report_templates("
            "tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (caller.tenant_id, tpl_id, t_fmt, evt_flt, s_lim, caller.user_id, now_ts),
        )

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
    """读取已保存报表模板并全参数化流式查询、安全字面渲染审计汇总报告（阻断二阶 SQLi 与格式化反射）。"""
    with borrow_connection(db_path) as conn:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, template_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {template_id}")

        clauses = ["tenant_id = ?"]
        params: list[Any] = [caller.tenant_id]
        if start_ts is not None:
            clauses.append("ts >= ?")
            params.append(parse_strict_int(start_ts, field_name="start_ts", min_val=0))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(parse_strict_int(end_ts, field_name="end_ts", min_val=0))

        evt_flt = str(tpl["extra_event_filter"] or "").strip()
        if evt_flt:
            if not _EVENT_FILTER_RE.match(evt_flt):
                raise ValueError("Invalid extra_event_filter stored in template")
            clauses.append("event_type = ?")
            params.append(evt_flt)

        sql = (
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        cur = conn.execute(sql, tuple(params))
        digest = _compute_digest_streaming(cur, caller.tenant_id, int(tpl["sample_limit"]))

    rendered_title = _render_title_safely(
        str(tpl["title_format"]),
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
    """严格路径锚定读取当前租户归档快照（阻断多变体目录穿越、双重编码、反斜杠、空字节与符号链接逃逸）。"""
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")

    # 拒绝任何编码残留、空字节、路径分隔符、相对跳转与非法文件名字符
    decoded = urllib.parse.unquote(urllib.parse.unquote(snapshot_name))
    for candidate in (snapshot_name, decoded):
        if (
            "\x00" in candidate
            or "/" in candidate
            or "\\" in candidate
            or ".." in candidate
            or ":" in candidate
            or "%" in candidate
        ):
            raise PermissionError("Invalid snapshot path")

    if not _SAFE_SNAPSHOT_NAME_RE.match(snapshot_name):
        raise PermissionError("Invalid snapshot filename")

    base_dir = (pathlib.Path(storage_dir) / caller.tenant_id / "snapshots").resolve(strict=False)
    raw_target = base_dir / snapshot_name
    if raw_target.is_symlink():
        raise PermissionError("Symbolic links are not allowed")

    target_path = raw_target.resolve(strict=False)
    if target_path.parent != base_dir or not target_path.is_relative_to(base_dir):
        raise PermissionError("Snapshot path escapes tenant boundary")

    if not target_path.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")

    if target_path.stat().st_size > _MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot file exceeds maximum size limit")

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
