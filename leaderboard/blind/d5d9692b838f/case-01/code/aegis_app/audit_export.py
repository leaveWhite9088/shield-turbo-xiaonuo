# -*- coding: utf-8 -*-
"""合规审计流水游标流式摘要导出、字面占位符报表沙箱渲染与锚定路径归档快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
from typing import Any

from .auth import CallerContext, require_admin
from .config import MAX_JSON_BODY_BYTES, MAX_SAFE_TS
from .db import borrow_connection, write_transaction
from .middleware import (
    _precheck_json_structure,
    _reject_json_constant,
    strict_int,
)

_ALLOWED_PLACEHOLDERS = frozenset({"tenant_id", "total_records", "total_amount_cents"})
_SAFE_EVENT_FILTER_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_SAFE_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _parse_safe_title_template(title_format: str) -> list[tuple[bool, str]]:
    """严格字面量占位符解析器（彻底废除 str.format，零属性反射、零宽度格式化内存放大）。"""
    if not isinstance(title_format, str):
        raise ValueError("title_format must be a string")
    t_fmt = title_format.strip()
    if not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid title_format within 200 characters is required")

    segments: list[tuple[bool, str]] = []
    literal_buf: list[str] = []
    n = len(t_fmt)
    i = 0

    while i < n:
        ch = t_fmt[i]
        if ch == "{":
            if i + 1 < n and t_fmt[i + 1] == "{":
                literal_buf.append("{")
                i += 2
                continue
            close_idx = t_fmt.find("}", i + 1)
            if close_idx == -1:
                raise ValueError("Unclosed placeholder brace in title_format")
            token = t_fmt[i + 1 : close_idx]
            if token not in _ALLOWED_PLACEHOLDERS:
                raise ValueError(f"Unsupported or unsafe placeholder in title_format: {token!r}")
            if literal_buf:
                segments.append((False, "".join(literal_buf)))
                literal_buf.clear()
            segments.append((True, token))
            i = close_idx + 1
        elif ch == "}":
            if i + 1 < n and t_fmt[i + 1] == "}":
                literal_buf.append("}")
                i += 2
                continue
            raise ValueError("Unmatched closing brace in title_format")
        else:
            literal_buf.append(ch)
            i += 1

    if literal_buf:
        segments.append((False, "".join(literal_buf)))
    return segments


def _render_safe_title(segments: list[tuple[bool, str]], values: dict[str, Any]) -> str:
    out_parts: list[str] = []
    for is_var, token in segments:
        if is_var:
            out_parts.append(str(values[token]))
        else:
            out_parts.append(token)
    return "".join(out_parts)


def _stream_audit_digest(
    conn: Any,
    tenant_id: str,
    sql: str,
    params: tuple[Any, ...],
    sample_limit: int,
) -> dict[str, Any]:
    """基于数据库游标 fetchmany 分块流式计算滚动 SHA-256 摘要（O(1) 常驻内存，跳过 payload_json 读取与深拷贝）。"""
    capped_sample = max(0, min(int(sample_limit), 50))
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_records = 0
    total_amount_cents = 0
    samples: list[dict[str, Any]] = []

    cur = conn.execute(sql, params)
    while True:
        chunk = cur.fetchmany(512)
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
    sample_limit: Any = 10,
) -> dict[str, Any]:
    """流式统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。"""
    s_lim = strict_int(sample_limit, "sample_limit")
    if not isinstance(severity, str) or len(severity) > 64:
        raise ValueError("Invalid severity filter")

    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(strict_int(start_ts, "start_ts", min_val=0, max_val=MAX_SAFE_TS))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(strict_int(end_ts, "end_ts", min_val=0, max_val=MAX_SAFE_TS))
    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    with borrow_connection(db_path) as conn:
        return _stream_audit_digest(conn, caller.tenant_id, sql, tuple(params), s_lim)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: Any = 10,
) -> dict[str, Any]:
    """校验并保存租户自定义审计汇总报表配置模板（入口硬拦截二阶注入载荷与非法占位符）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)

    tpl_id = str(template_id or "").strip()
    if not tpl_id or not _SAFE_TEMPLATE_ID_RE.match(tpl_id):
        raise ValueError("Invalid template_id")

    if not isinstance(title_format, str):
        raise ValueError("title_format must be a string")
    t_fmt = title_format.strip()
    _parse_safe_title_template(t_fmt)

    if not isinstance(extra_event_filter, str):
        raise ValueError("extra_event_filter must be a string")
    evt_flt = extra_event_filter.strip()
    if evt_flt and not _SAFE_EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("Invalid extra_event_filter: must be an uppercase event identifier")

    raw_slim = strict_int(sample_limit, "sample_limit")
    s_lim = max(0, min(raw_slim, 50))
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
    """读取已保存的报表模板，执行二阶参数化查询与纯字面量占位符渲染。"""
    clean_tpl_id = str(template_id or "").strip()
    if not clean_tpl_id or len(clean_tpl_id) > 128:
        raise ValueError("Valid template_id is required")

    s_val = (
        strict_int(start_ts, "start_ts", min_val=0, max_val=MAX_SAFE_TS)
        if start_ts is not None
        else None
    )
    e_val = (
        strict_int(end_ts, "end_ts", min_val=0, max_val=MAX_SAFE_TS)
        if end_ts is not None
        else None
    )

    with borrow_connection(db_path) as conn:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, clean_tpl_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {clean_tpl_id}")

        segments = _parse_safe_title_template(str(tpl["title_format"]))
        evt_flt = str(tpl["extra_event_filter"] or "").strip()
        if evt_flt and not _SAFE_EVENT_FILTER_RE.match(evt_flt):
            raise ValueError("Stored template contains invalid extra_event_filter")

        clauses = ["tenant_id = ?"]
        params: list[Any] = [caller.tenant_id]
        if s_val is not None:
            clauses.append("ts >= ?")
            params.append(s_val)
        if e_val is not None:
            clauses.append("ts <= ?")
            params.append(e_val)
        if evt_flt:
            clauses.append("event_type = ?")
            params.append(evt_flt)

        sql = (
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        digest = _stream_audit_digest(
            conn,
            caller.tenant_id,
            sql,
            tuple(params),
            int(tpl["sample_limit"]),
        )

    rendered_title = _render_safe_title(
        segments,
        {
            "tenant_id": caller.tenant_id,
            "total_records": digest["total_records"],
            "total_amount_cents": digest["total_amount_cents"],
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
    """多层路径规范化与根目录锚定校验，安全读取本租户 snapshots/ 归档文件。"""
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")

    # 阻断双重编码（%）、空字节、正反斜杠、盘符冒号、备选数据流与相对上级目录穿越
    if (
        "\x00" in snapshot_name
        or "%" in snapshot_name
        or "/" in snapshot_name
        or "\\" in snapshot_name
        or ":" in snapshot_name
        or ".." in snapshot_name
        or not _SAFE_SNAPSHOT_NAME_RE.match(snapshot_name)
    ):
        raise ValueError("Invalid snapshot filename")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    raw_candidate = base_dir / snapshot_name
    if raw_candidate.is_symlink():
        raise PermissionError("Symlink snapshot access is forbidden")

    target_path = raw_candidate.resolve()
    if target_path.parent != base_dir or not target_path.is_relative_to(base_dir):
        raise PermissionError("Snapshot path escapes tenant boundary")

    if not target_path.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")

    stat_info = target_path.stat()
    if stat_info.st_size > MAX_JSON_BODY_BYTES:
        raise ValueError("Snapshot file exceeds maximum allowed size")

    raw_text = target_path.read_text(encoding="utf-8")
    try:
        _precheck_json_structure(raw_text)
        parsed = json.loads(raw_text, parse_constant=_reject_json_constant)
    except (ValueError, json.JSONDecodeError):
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
