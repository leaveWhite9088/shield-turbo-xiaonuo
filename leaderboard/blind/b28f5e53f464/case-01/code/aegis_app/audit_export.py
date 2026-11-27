# -*- coding: utf-8 -*-
"""合规审计流水游标流式摘要导出、安全模板白名单沙箱渲染与防穿越快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import time
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .runtime import GatewayRuntime, get_runtime
from .validation import (
    render_safe_title,
    safe_json_loads,
    strict_int,
    validate_event_filter,
    validate_title_format,
)

_STREAM_CHUNK_SIZE = 2048
_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024


def _stream_digest_from_cursor(
    cursor: sqlite3.Cursor,
    tenant_id: str,
    sample_limit: int,
) -> dict[str, Any]:
    """基于 SQLite 游标分块流式计算审计摘要与滚动 SHA-256，常驻堆内存保持 O(1)。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    while True:
        chunk = cursor.fetchmany(_STREAM_CHUNK_SIZE)
        if not chunk:
            break
        for r in chunk:
            log_id = int(r["log_id"])
            evt = r["event_type"]
            sev = r["severity"]
            amt = int(r["amount_cents"])
            masked_acc = r["masked_account"]
            ts_val = int(r["ts"])

            total_records += 1
            total_amount_cents += amt
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            event_counts[evt] = event_counts.get(evt, 0) + 1
            line = f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts_val}\n"
            hasher.update(line.encode("utf-8"))

            if len(samples) < capped_sample:
                samples.append(
                    {
                        "log_id": log_id,
                        "event_type": evt,
                        "severity": sev,
                        "amount_cents": amt,
                        "masked_account": masked_acc,
                        "ts": ts_val,
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """统计指定时间窗口内的审计事件分布并流式计算顺序滚动完整性校验哈希。"""
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
        params.append(str(severity).strip())

    s_lim = strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000)
    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    rt = runtime or get_runtime(db_path)
    with rt.connection() as conn:
        cur = conn.execute(sql, tuple(params))
        return _stream_digest_from_cursor(cur, caller.tenant_id, s_lim)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（严格校验字面占位符白名单与合法事件名）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    if not tpl_id or len(tpl_id) > 128:
        raise ValueError("Valid template_id is required")

    t_fmt = validate_title_format(title_format)
    evt_flt = validate_event_filter(extra_event_filter)
    s_lim = max(0, min(strict_int(sample_limit, "sample_limit", min_val=0), 50))

    now_ts = int(caller.request_ts or int(time.time()))
    rt = runtime or get_runtime(db_path)
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
    runtime: GatewayRuntime | None = None,
) -> dict[str, Any]:
    """读取已保存的报表模板，通过全参数化查询与无反射字面渲染生成审计汇总报告。"""
    clean_tpl_id = str(template_id or "").strip()
    if not clean_tpl_id:
        raise ValueError("template_id is required")

    rt = runtime or get_runtime(db_path)
    with rt.connection() as conn:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, clean_tpl_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {clean_tpl_id}")

        # 对持久化模板进行二次校验（拦截历史遗留或外部直写污染的恶意模板/过滤条件）
        safe_fmt = validate_title_format(str(tpl["title_format"]))
        evt_filter = validate_event_filter(str(tpl["extra_event_filter"] or ""))

        clauses = ["tenant_id = ?"]
        params: list[Any] = [caller.tenant_id]
        if start_ts is not None:
            clauses.append("ts >= ?")
            params.append(strict_int(start_ts, "start_ts"))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(strict_int(end_ts, "end_ts"))
        if evt_filter:
            clauses.append("event_type = ?")
            params.append(evt_filter)

        sql = (
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        cur = conn.execute(sql, tuple(params))
        digest = _stream_digest_from_cursor(cur, caller.tenant_id, int(tpl["sample_limit"]))

    rendered_title = render_safe_title(
        safe_fmt,
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
    """安全读取当前租户 snapshots/ 目录下的合规季度快照文件（彻底阻断路径穿越与符号链接逃逸）。"""
    if not isinstance(snapshot_name, str) or not snapshot_name.strip():
        raise ValueError("snapshot_name is required")

    raw_name = snapshot_name.strip()
    decoded = urllib.parse.unquote(raw_name)
    if (
        "\x00" in raw_name
        or "\x00" in decoded
        or "\\" in raw_name
        or "\\" in decoded
        or "%" in decoded
        or ":" in raw_name
        or ":" in decoded
    ):
        raise PermissionError("Invalid snapshot path")

    pure = pathlib.PurePosixPath(decoded)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or "." in pure.parts:
        raise PermissionError("Path traversal outside tenant snapshots is forbidden")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    if not base_dir.is_dir():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")

    cur = base_dir
    for part in pure.parts:
        cur = cur / part
        if cur.is_symlink():
            raise PermissionError("Symbolic links are forbidden in snapshot path")

    resolved = cur.resolve()
    if not resolved.is_relative_to(base_dir) or resolved == base_dir:
        raise PermissionError("Path traversal outside tenant snapshots is forbidden")
    if not resolved.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")
    if resolved.stat().st_size > _MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot file exceeds maximum readable size")

    raw_text = resolved.read_text(encoding="utf-8")
    try:
        parsed = safe_json_loads(raw_text)
    except json.JSONDecodeError:
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
