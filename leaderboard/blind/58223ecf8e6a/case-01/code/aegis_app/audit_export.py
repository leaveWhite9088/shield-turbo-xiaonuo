# -*- coding: utf-8 -*-
"""游标流式审计摘要、字面占位符模板沙箱与锚定快照读取。"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import string
import time
import urllib.parse
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .db import open_connection
from .security import bounded_text, strict_int

_EVENT_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
_SNAPSHOT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.json\Z", re.ASCII)
_ALLOWED_FIELDS = frozenset({"tenant_id", "total_records", "total_amount_cents"})


def _compute_digest_from_records(
    tenant_id: str,
    raw_rows: Iterable[Any],
    sample_limit: int,
) -> dict[str, Any]:
    """单次游标扫描；不解析无用 payload、不 fetchall、不复制归档镜像。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount = 0
    total_records = 0
    capped = max(0, min(strict_int(sample_limit, "sample_limit"), 50))
    samples: list[dict[str, Any]] = []
    for row in raw_rows:
        severity = str(row["severity"])
        event = str(row["event_type"])
        amount = int(row["amount_cents"])
        log_id = int(row["log_id"])
        masked = str(row["masked_account"])
        timestamp = int(row["ts"])
        total_records += 1
        total_amount += amount
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        event_counts[event] = event_counts.get(event, 0) + 1
        line = f"{log_id}|{event}|{severity}|{amount}|{masked}|{timestamp}\n"
        hasher.update(line.encode("utf-8"))
        if len(samples) < capped:
            samples.append({
                "log_id": log_id, "event_type": event, "severity": severity,
                "amount_cents": amount, "masked_account": masked, "ts": timestamp,
            })
    return {
        "tenant_id": tenant_id,
        "total_records": total_records,
        "total_amount_cents": total_amount,
        "severity_breakdown": dict(sorted(severity_counts.items())),
        "event_breakdown": dict(sorted(event_counts.items())),
        "rolling_sha256": hasher.hexdigest(),
        "samples": samples,
    }


def _audit_query(
    conn: Any,
    tenant_id: str,
    *,
    start_ts: int | None,
    end_ts: int | None,
    severity: str = "",
    event_type: str = "",
) -> Any:
    clauses = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(strict_int(start_ts, "start_ts"))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(strict_int(end_ts, "end_ts"))
    if severity:
        clauses.append("severity = ?")
        params.append(bounded_text(severity, "severity", max_length=32))
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )
    cursor = conn.execute(sql, tuple(params))
    cursor.arraysize = 256
    return cursor


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    conn = open_connection(db_path)
    try:
        cursor = _audit_query(
            conn, caller.tenant_id, start_ts=start_ts, end_ts=end_ts, severity=severity,
        )
        return _compute_digest_from_records(caller.tenant_id, cursor, sample_limit)
    finally:
        conn.close()


def _render_literal_template(template: str, values: dict[str, Any]) -> str:
    """Formatter 仅用于解析；拒绝属性/索引/转换/格式规格，渲染不调用 str.format。"""
    output: list[str] = []
    try:
        parts = string.Formatter().parse(template)
        for literal, field, format_spec, conversion in parts:
            output.append(literal)
            if field is not None:
                if field not in _ALLOWED_FIELDS or format_spec or conversion:
                    raise ValueError("Only literal tenant/total placeholders are supported")
                output.append(str(values[field]))
    except (ValueError, KeyError) as exc:
        raise ValueError("Invalid report title template") from exc
    rendered = "".join(output)
    if len(rendered) > 4096:
        raise ValueError("Rendered report title exceeds budget")
    return rendered


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    template_id = bounded_text(template_id, "template_id", max_length=128)
    title_format = bounded_text(title_format, "title_format", max_length=200)
    event_filter = bounded_text(extra_event_filter or "", "extra_event_filter", max_length=64, allow_empty=True)
    sample_limit = strict_int(sample_limit, "sample_limit", minimum=0, maximum=50)
    if event_filter and not _EVENT_RE.fullmatch(event_filter):
        raise ValueError("Invalid audit event filter")
    _render_literal_template(title_format, {"tenant_id": "tenant", "total_records": 0, "total_amount_cents": 0})
    now_ts = caller.request_ts or int(time.time())
    conn = open_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT OR REPLACE INTO report_templates(tenant_id, template_id, title_format, extra_event_filter, "
            "sample_limit, created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (caller.tenant_id, template_id, title_format, event_filter, sample_limit, caller.user_id, now_ts),
        )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "tenant_id": caller.tenant_id, "template_id": template_id, "title_format": title_format,
        "extra_event_filter": event_filter, "sample_limit": sample_limit,
    }


def render_saved_report(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    start_ts: int | None = None,
    end_ts: int | None = None,
) -> dict[str, Any]:
    template_id = bounded_text(template_id, "template_id", max_length=128)
    conn = open_connection(db_path)
    try:
        template = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit FROM report_templates "
            "WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, template_id),
        ).fetchone()
        if not template:
            raise LookupError("Report template not found")
        event_filter = str(template["extra_event_filter"])
        if event_filter and not _EVENT_RE.fullmatch(event_filter):
            raise ValueError("Stored report event filter is invalid")
        cursor = _audit_query(
            conn, caller.tenant_id, start_ts=start_ts, end_ts=end_ts, event_type=event_filter,
        )
        digest = _compute_digest_from_records(caller.tenant_id, cursor, int(template["sample_limit"]))
        title = _render_literal_template(str(template["title_format"]), {
            "tenant_id": caller.tenant_id,
            "total_records": digest["total_records"],
            "total_amount_cents": digest["total_amount_cents"],
        })
        return {"template_id": template["template_id"], "rendered_title": title, "digest": digest}
    finally:
        conn.close()


def read_compliance_snapshot(storage_dir: str, caller: CallerContext, snapshot_name: str) -> dict[str, Any]:
    snapshot_name = bounded_text(snapshot_name, "snapshot_name", max_length=256)
    decoded = snapshot_name
    for _ in range(3):
        next_value = urllib.parse.unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if urllib.parse.unquote(decoded) != decoded or not _SNAPSHOT_RE.fullmatch(decoded):
        raise ValueError("Invalid snapshot file name")
    if decoded in (".", "..") or "/" in decoded or "\\" in decoded:
        raise ValueError("Snapshot path traversal is forbidden")
    base = pathlib.Path(storage_dir, caller.tenant_id, "snapshots").resolve()
    target = (base / decoded).resolve()
    try:
        if os.path.commonpath((str(base), str(target))) != str(base):
            raise ValueError("Snapshot path escapes tenant archive")
    except ValueError as exc:
        raise ValueError("Snapshot path escapes tenant archive") from exc
    if not target.is_file() or target.stat().st_size > 1_048_576:
        raise LookupError("Snapshot file not found")
    raw = target.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw_content": raw}
    return {"tenant_id": caller.tenant_id, "snapshot_name": snapshot_name, "data": parsed}
