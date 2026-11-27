# -*- coding: utf-8 -*-
"""合规审计流水游标流式摘要导出、零反射字面报表模板渲染与沙盒快照安全读取服务。"""
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
from .db import get_db_runtime
from .middleware import strict_int

_ALLOWED_PLACEHOLDERS = frozenset({"tenant_id", "total_records", "total_amount_cents"})
_EVENT_FILTER_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_SAFE_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")


def _validate_and_render_title(
    title_format: str,
    context_values: dict[str, Any] | None = None,
) -> str:
    """单趟词法扫描校验并渲染标题模板（彻底弃用 str.format，100% 阻断属性反射与 :0>200000 宽度填充放大）。"""
    if not isinstance(title_format, str) or not title_format or len(title_format) > 200:
        raise ValueError("title_format must be a non-empty string within 200 characters")

    out_parts: list[str] = []
    n = len(title_format)
    i = 0

    while i < n:
        ch = title_format[i]
        if ch == "{":
            if i + 1 < n and title_format[i + 1] == "{":
                out_parts.append("{")
                i += 2
                continue
            close_idx = title_format.find("}", i + 1)
            if close_idx == -1:
                raise ValueError("Unclosed '{' in title_format")
            token = title_format[i + 1: close_idx]
            if token not in _ALLOWED_PLACEHOLDERS:
                raise ValueError(f"Unsupported or unsafe template placeholder: {{{token}}}")
            if context_values is not None:
                out_parts.append(str(context_values[token]))
            i = close_idx + 1
        elif ch == "}":
            if i + 1 < n and title_format[i + 1] == "}":
                out_parts.append("}")
                i += 2
                continue
            raise ValueError("Unmatched '}' in title_format")
        else:
            next_open = title_format.find("{", i)
            next_close = title_format.find("}", i)
            if next_open == -1 and next_close == -1:
                out_parts.append(title_format[i:])
                break
            stop = min(
                next_open if next_open != -1 else n,
                next_close if next_close != -1 else n,
            )
            out_parts.append(title_format[i:stop])
            i = stop

    return "".join(out_parts)


def _stream_digest_from_cursor(
    tenant_id: str,
    cursor: sqlite3.Cursor,
    sample_limit: int,
) -> dict[str, Any]:
    """基于 SQLite 游标 fetchmany 分块流式计算滚动 SHA-256 摘要（零 fetchall、O(1) 常驻内存）。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_records = 0
    total_amount_cents = 0

    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    while True:
        batch = cursor.fetchmany(512)
        if not batch:
            break
        lines_chunk: list[str] = []
        for r in batch:
            log_id = int(r[0])
            evt = str(r[1])
            sev = str(r[2])
            amt = int(r[3])
            masked_acc = str(r[4])
            ts = int(r[5])

            total_records += 1
            total_amount_cents += amt
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            event_counts[evt] = event_counts.get(evt, 0) + 1

            lines_chunk.append(f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts}\n")

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
        hasher.update("".join(lines_chunk).encode("utf-8"))

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
    if not isinstance(severity, str) or len(severity) > 32:
        raise ValueError("Invalid severity parameter")
    s_lim = strict_int(sample_limit, "sample_limit", min_val=-1000, max_val=100000)

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
        params.append(severity)

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    rt = get_db_runtime(db_path)
    with rt.read_conn() as conn:
        cur = conn.cursor()
        cur.row_factory = None  # type: ignore[assignment]
        cur.execute(sql, tuple(params))
        return _stream_digest_from_cursor(caller.tenant_id, cur, s_lim)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（静态校验字面占位符白名单与合法事件过滤词）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)

    if not isinstance(template_id, str) or not isinstance(title_format, str) or not isinstance(extra_event_filter, str):
        raise ValueError("template_id, title_format, and extra_event_filter must be strings")

    tpl_id = template_id.strip()
    t_fmt = title_format.strip()
    evt_flt = extra_event_filter.strip()
    raw_slim = strict_int(sample_limit, "sample_limit", min_val=-1000, max_val=100000)
    s_lim = max(0, min(raw_slim, 50))

    if not tpl_id or len(tpl_id) > 128 or not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid template_id and title_format are required")

    # 校验占位符严格属于 {tenant_id}, {total_records}, {total_amount_cents} 字面集合
    _validate_and_render_title(t_fmt, None)

    if evt_flt and not _EVENT_FILTER_RE.fullmatch(evt_flt):
        raise ValueError("Invalid extra_event_filter: only uppercase event identifiers are allowed")

    now_ts = int(caller.request_ts or int(time.time()))
    rt = get_db_runtime(db_path)
    with rt.write_tx() as conn:
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
    """读取已保存的报表模板并安全流式渲染汇总报告（100% 参数化二阶查询 + 字面状态机渲染）。"""
    if not isinstance(template_id, str) or not template_id.strip() or len(template_id.strip()) > 128:
        raise ValueError("Valid template_id is required")
    norm_tpl_id = template_id.strip()

    s_val = strict_int(start_ts, "start_ts") if start_ts is not None else None
    e_val = strict_int(end_ts, "end_ts") if end_ts is not None else None

    rt = get_db_runtime(db_path)
    with rt.read_conn() as conn:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, norm_tpl_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {norm_tpl_id}")

        evt_flt = str(tpl["extra_event_filter"] or "").strip()
        if evt_flt and not _EVENT_FILTER_RE.fullmatch(evt_flt):
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
        cur = conn.cursor()
        cur.row_factory = None  # type: ignore[assignment]
        cur.execute(sql, tuple(params))
        digest = _stream_digest_from_cursor(caller.tenant_id, cur, int(tpl["sample_limit"]))

    rendered_title = _validate_and_render_title(
        str(tpl["title_format"]),
        {
            "tenant_id": caller.tenant_id,
            "total_records": digest["total_records"],
            "total_amount_cents": digest["total_amount_cents"],
        },
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
    """安全读取本租户 snapshots/ 目录下的季度归档快照文件（阻断一切多变体路径穿越与符号链接逃逸）。"""
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")
    if len(snapshot_name) > 128 or "\x00" in snapshot_name:
        raise PermissionError("Invalid snapshot_name")

    # 递归解码检查多层 URL 编码穿越载荷
    curr = snapshot_name
    for _ in range(4):
        nxt = urllib.parse.unquote(curr)
        if nxt == curr:
            break
        curr = nxt

    if (
        "/" in snapshot_name
        or "\\" in snapshot_name
        or ":" in snapshot_name
        or ".." in snapshot_name
        or "/" in curr
        or "\\" in curr
        or ":" in curr
        or ".." in curr
        or not _SAFE_SNAPSHOT_NAME_RE.fullmatch(curr)
    ):
        raise PermissionError("Snapshot path traversal or invalid filename rejected")

    base_dir = (pathlib.Path(storage_dir) / caller.tenant_id / "snapshots").resolve()
    candidate = base_dir / curr

    if candidate.is_symlink():
        raise PermissionError("Symlink snapshot access denied")

    target_path = candidate.resolve()
    if target_path.parent != base_dir or not target_path.is_relative_to(base_dir):
        raise PermissionError("Snapshot target outside tenant sandbox")

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
