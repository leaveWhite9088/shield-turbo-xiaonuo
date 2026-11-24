# -*- coding: utf-8 -*-
"""高性能安全审计导出与报表渲染：游标分块流式扫描、二阶参数化防注入、安全字面量替换防反射与物理路径锚定。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .db import get_striped_lock, get_thread_connection, require_strict_int

SAFE_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.json$")
SAFE_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
SAFE_EVENT_TYPE_RE = re.compile(r"^[A-Z0-9_]{2,32}$")
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_TEMPLATE_VARS = {"tenant_id", "total_records", "total_amount_cents"}
_BRACE_TOKEN_RE = re.compile(r"\{([^{}]*)\}")


def _validate_and_render_title(title_format: str, values: dict[str, str] | None = None) -> str:
    """严格白名单占位符校验与单遍字面量替换，彻底阻断 Python .format() 属性/字典反射泄露。"""
    if not isinstance(title_format, str) or not title_format.strip() or len(title_format) > 200:
        raise ValueError("title_format must be a non-empty string up to 200 chars")

    # 检查是否存在未闭合或嵌套花括号
    stripped_tokens = _BRACE_TOKEN_RE.sub("", title_format)
    if "{" in stripped_tokens or "}" in stripped_tokens:
        raise ValueError("Malformed or nested braces in title_format")

    for match in _BRACE_TOKEN_RE.finditer(title_format):
        var_name = match.group(1)
        if var_name not in ALLOWED_TEMPLATE_VARS:
            raise ValueError(f"Disallowed template placeholder: {var_name!r}")

    if values is None:
        return title_format

    return _BRACE_TOKEN_RE.sub(lambda m: values[m.group(1)], title_format)


def _stream_audit_digest(
    db_path: str,
    tenant_id: str,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    event_type: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    clauses = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(require_strict_int(start_ts, "start_ts", min_val=0))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(require_strict_int(end_ts, "end_ts", min_val=0))
    if severity:
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid severity filter: {severity}")
        clauses.append("severity = ?")
        params.append(severity)
    if event_type:
        if not SAFE_EVENT_TYPE_RE.match(event_type):
            raise ValueError("Invalid event_type filter")
        clauses.append("event_type = ?")
        params.append(event_type)

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = get_thread_connection(db_path)
    cur = conn.execute(sql, tuple(params))

    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_records = 0
    total_amount_cents = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    try:
        while True:
            batch = cur.fetchmany(256)
            if not batch:
                break
            for r in batch:
                log_id = int(r[0])
                evt = r[1]
                sev = r[2]
                amt = int(r[3])
                masked_acc = r[4]
                ts = int(r[5])

                total_records += 1
                total_amount_cents += amt
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                event_counts[evt] = event_counts.get(evt, 0) + 1
                hasher.update(f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts}\n".encode("utf-8"))

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
    finally:
        cur.close()

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
    sample_limit: Any = 10,
) -> dict[str, Any]:
    checked_slim = require_strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000)
    return _stream_audit_digest(
        db_path,
        caller.tenant_id,
        start_ts=start_ts,
        end_ts=end_ts,
        severity=severity,
        sample_limit=min(checked_slim, 50),
    )


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: Any = 10,
) -> dict[str, Any]:
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)

    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    checked_slim = require_strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000)
    s_lim = min(checked_slim, 50)

    if not tpl_id or not SAFE_TEMPLATE_ID_RE.match(tpl_id):
        raise ValueError("Invalid template_id format")
    _validate_and_render_title(t_fmt, None)
    if evt_flt and not SAFE_EVENT_TYPE_RE.match(evt_flt):
        raise ValueError("Invalid extra_event_filter value")

    now_ts = int(caller.request_ts or int(time.time()))
    lock = get_striped_lock(db_path, caller.tenant_id, "report_tpl")
    with lock:
        conn = get_thread_connection(db_path)
        conn.execute(
            "INSERT OR REPLACE INTO report_templates("
            "tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (caller.tenant_id, tpl_id, t_fmt, evt_flt, s_lim, caller.user_id, now_ts),
        )
        conn.commit()

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
    tpl_id = str(template_id or "").strip()
    if not tpl_id or not SAFE_TEMPLATE_ID_RE.match(tpl_id):
        raise ValueError("Invalid template_id")

    conn = get_thread_connection(db_path)
    tpl = conn.execute(
        "SELECT template_id, title_format, extra_event_filter, sample_limit "
        "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
        (caller.tenant_id, tpl_id),
    ).fetchone()
    if not tpl:
        raise LookupError(f"Report template not found: {tpl_id}")

    stored_filter = str(tpl["extra_event_filter"] or "").strip()
    digest = _stream_audit_digest(
        db_path,
        caller.tenant_id,
        start_ts=start_ts,
        end_ts=end_ts,
        event_type=stored_filter,
        sample_limit=int(tpl["sample_limit"]),
    )

    rendered_title = _validate_and_render_title(
        str(tpl["title_format"]),
        {
            "tenant_id": caller.tenant_id,
            "total_records": str(digest["total_records"]),
            "total_amount_cents": str(digest["total_amount_cents"]),
        },
    )
    return {
        "template_id": str(tpl["template_id"]),
        "rendered_title": rendered_title,
        "digest": digest,
    }


def read_compliance_snapshot(
    storage_dir: str,
    caller: CallerContext,
    snapshot_name: str,
) -> dict[str, Any]:
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")

    unquoted_once = urllib.parse.unquote(snapshot_name)
    unquoted_twice = urllib.parse.unquote(unquoted_once)
    if (
        unquoted_once != snapshot_name
        or unquoted_twice != snapshot_name
        or "/" in snapshot_name
        or "\\" in snapshot_name
        or ".." in snapshot_name
        or "\x00" in snapshot_name
        or not SAFE_SNAPSHOT_NAME_RE.match(snapshot_name)
    ):
        raise ValueError("Illegal snapshot_name format")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    target_path = (base_dir / snapshot_name).resolve()

    if not target_path.is_relative_to(base_dir) or target_path.parent != base_dir:
        raise ValueError("Path traversal attempt blocked")

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
