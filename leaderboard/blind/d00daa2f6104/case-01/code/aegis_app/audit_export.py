# -*- coding: utf-8 -*-
"""流式审计摘要、字面模板沙箱与目录锚定快照读取。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import string
import time
import urllib.parse
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .db import open_connection
from .runtime import bounded_text, strict_int

_ALLOWED_FIELDS = frozenset({"tenant_id", "total_records", "total_amount_cents"})
_EVENT_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SNAPSHOT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _new_digest(tenant_id: str, sample_limit: int) -> dict[str, Any]:
    capped = max(0, min(strict_int(sample_limit, "sample_limit"), 50))
    return {
        "tenant_id": tenant_id, "total_records": 0, "total_amount_cents": 0,
        "severity_breakdown": {}, "event_breakdown": {},
        "_hasher": hashlib.sha256(), "_samples": [], "_sample_limit": capped,
    }


def _consume_rows(state: dict[str, Any], rows: Iterable[Any]) -> None:
    for row in rows:
        log_id = int(row["log_id"])
        event = str(row["event_type"])
        severity = str(row["severity"])
        amount = int(row["amount_cents"])
        masked = str(row["masked_account"])
        ts = int(row["ts"])
        state["total_records"] += 1
        state["total_amount_cents"] += amount
        state["severity_breakdown"][severity] = state["severity_breakdown"].get(severity, 0) + 1
        state["event_breakdown"][event] = state["event_breakdown"].get(event, 0) + 1
        state["_hasher"].update(f"{log_id}|{event}|{severity}|{amount}|{masked}|{ts}\n".encode("utf-8"))
        if len(state["_samples"]) < state["_sample_limit"]:
            state["_samples"].append({
                "log_id": log_id, "event_type": event, "severity": severity,
                "amount_cents": amount, "masked_account": masked, "ts": ts,
            })


def _finish_digest(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "tenant_id": state["tenant_id"],
        "total_records": state["total_records"],
        "total_amount_cents": state["total_amount_cents"],
        "severity_breakdown": dict(sorted(state["severity_breakdown"].items())),
        "event_breakdown": dict(sorted(state["event_breakdown"].items())),
        "rolling_sha256": state["_hasher"].hexdigest(),
        "samples": state["_samples"],
    }


def _compute_digest_from_records(tenant_id: str, raw_rows: Iterable[Any], sample_limit: int) -> dict[str, Any]:
    state = _new_digest(tenant_id, sample_limit)
    _consume_rows(state, raw_rows)
    return _finish_digest(state)


def _audit_where(caller: CallerContext, start_ts: int | None, end_ts: int | None,
                 severity: str = "", event_filter: str = "") -> tuple[str, list[Any]]:
    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(strict_int(start_ts, "start_ts"))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(strict_int(end_ts, "end_ts"))
    if severity:
        clauses.append("severity = ?")
        params.append(bounded_text(severity, "severity", 32))
    if event_filter:
        clauses.append("event_type = ?")
        params.append(event_filter)
    return " AND ".join(clauses), params


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    where, params = _audit_where(caller, start_ts, end_ts, severity)
    state = _new_digest(caller.tenant_id, sample_limit)
    conn = open_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {where} ORDER BY log_id ASC",
            tuple(params),
        )
        _consume_rows(state, cursor)
    finally:
        conn.close()
    return _finish_digest(state)


def _parse_template(title_format: str) -> list[tuple[str, str | None]]:
    parsed: list[tuple[str, str | None]] = []
    try:
        for literal, field, format_spec, conversion in string.Formatter().parse(title_format):
            if field is None:
                parsed.append((literal, None))
                continue
            if field not in _ALLOWED_FIELDS or format_spec or conversion:
                raise ValueError("Only literal tenant/total placeholders are supported")
            parsed.append((literal, field))
    except (ValueError, IndexError) as exc:
        raise ValueError("Unsafe report title template") from exc
    return parsed


def _validate_event_filter(event_filter: str) -> str:
    if event_filter and _EVENT_RE.fullmatch(event_filter) is None:
        raise ValueError("extra_event_filter must be a valid event name")
    return event_filter


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
    template_id = bounded_text(template_id, "template_id", 128)
    title_format = bounded_text(title_format, "title_format", 200)
    extra_event_filter = bounded_text(extra_event_filter, "extra_event_filter", 64, allow_empty=True)
    _parse_template(title_format)
    _validate_event_filter(extra_event_filter)
    sample_limit = max(0, min(strict_int(sample_limit, "sample_limit"), 50))
    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO report_templates(tenant_id, template_id, title_format, extra_event_filter, "
            "sample_limit, created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (caller.tenant_id, template_id, title_format, extra_event_filter,
             sample_limit, caller.user_id, now_ts),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "tenant_id": caller.tenant_id, "template_id": template_id,
        "title_format": title_format, "extra_event_filter": extra_event_filter,
        "sample_limit": sample_limit,
    }


def render_saved_report(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    start_ts: int | None = None,
    end_ts: int | None = None,
) -> dict[str, Any]:
    template_id = bounded_text(template_id, "template_id", 128)
    conn = open_connection(db_path)
    try:
        template = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit FROM report_templates "
            "WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, template_id),
        ).fetchone()
        if not template:
            raise LookupError("Report template not found")
        # 对存量数据库中的模板再次校验，阻断落库后的二阶格式化攻击。
        parsed_title = _parse_template(str(template["title_format"]))
        event_filter = _validate_event_filter(str(template["extra_event_filter"] or ""))
        where, params = _audit_where(caller, start_ts, end_ts, event_filter=event_filter)
        state = _new_digest(caller.tenant_id, int(template["sample_limit"]))
        cursor = conn.execute(
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {where} ORDER BY log_id ASC",
            tuple(params),
        )
        _consume_rows(state, cursor)
    finally:
        conn.close()
    digest = _finish_digest(state)
    values = {
        "tenant_id": caller.tenant_id, "total_records": str(digest["total_records"]),
        "total_amount_cents": str(digest["total_amount_cents"]),
    }
    rendered = "".join(literal + (values[field] if field is not None else "") for literal, field in parsed_title)
    if len(rendered) > 4096:
        raise ValueError("Rendered report title exceeds output budget")
    return {"template_id": template_id, "rendered_title": rendered, "digest": digest}


def read_compliance_snapshot(storage_dir: str, caller: CallerContext, snapshot_name: str) -> dict[str, Any]:
    if not isinstance(snapshot_name, str) or not snapshot_name or len(snapshot_name) > 512:
        raise ValueError("snapshot_name is required and must be bounded")
    decoded = snapshot_name
    for _ in range(4):
        next_value = urllib.parse.unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if (
        _SNAPSHOT_RE.fullmatch(decoded) is None or not decoded.endswith(".json")
        or ".." in decoded or decoded.startswith(".")
    ):
        raise ValueError("Unsafe snapshot name")
    base = pathlib.Path(storage_dir, caller.tenant_id, "snapshots").resolve()
    target = (base / decoded).resolve()
    if target.parent != base or not target.is_file():
        raise LookupError("Snapshot file not found")
    with target.open("r", encoding="utf-8") as handle:
        raw_text = handle.read(1_048_577)
    if len(raw_text) > 1_048_576:
        raise ValueError("Snapshot exceeds size budget")
    try:
        parsed = json.loads(raw_text, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite number")))
    except json.JSONDecodeError:
        parsed = {"raw_content": raw_text}
    return {"tenant_id": caller.tenant_id, "snapshot_name": snapshot_name, "data": parsed}
