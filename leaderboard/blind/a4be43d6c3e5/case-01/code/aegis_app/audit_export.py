# -*- coding: utf-8 -*-
"""合规审计流水流式游标摘要导出、字面沙箱报表模板渲染与锚定快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .state import get_gateway_state
from .validation import (
    EVENT_FILTER_RE,
    parse_strict_int,
    render_literal_template,
    validate_literal_template,
)

_STREAM_CHUNK_SIZE = 512


def _stream_digest_from_cursor(
    tenant_id: str,
    cur: Any,
    sample_limit: int,
) -> dict[str, Any]:
    """流式游标分批读取审计记录并计算滚动 SHA-256，保持 O(1) 常驻内存。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    while True:
        chunk = cur.fetchmany(_STREAM_CHUNK_SIZE)
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
            hasher.update(f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts_val}\n".encode("utf-8"))

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

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    gw_state = get_gateway_state(db_path)
    with gw_state.pool.borrow() as conn:
        cur = conn.execute(sql, tuple(params))
        return _stream_digest_from_cursor(caller.tenant_id, cur, sample_limit)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（严格校验字面占位符白名单与事件过滤名）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    s_lim = max(0, min(parse_strict_int(sample_limit, "sample_limit"), 50))
    if not tpl_id or not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid template_id and title_format are required")
    validate_literal_template(t_fmt)
    if evt_flt and not EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("extra_event_filter contains invalid characters")

    now_ts = int(caller.request_ts or int(time.time()))
    gw_state = get_gateway_state(db_path)
    with gw_state.pool.borrow() as conn:
        conn.execute("BEGIN IMMEDIATE")
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
    """读取已保存的报表模板并参数化查询、字面沙箱渲染审计汇总报告。"""
    gw_state = get_gateway_state(db_path)
    with gw_state.pool.borrow() as conn:
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
            params.append(parse_strict_int(start_ts, "start_ts"))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(parse_strict_int(end_ts, "end_ts"))
        evt_flt = str(tpl["extra_event_filter"] or "").strip()
        if evt_flt:
            if not EVENT_FILTER_RE.match(evt_flt):
                raise ValueError("Invalid extra_event_filter in template")
            clauses.append("event_type = ?")
            params.append(evt_flt)

        sql = (
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        cur = conn.execute(sql, tuple(params))
        digest = _stream_digest_from_cursor(caller.tenant_id, cur, int(tpl["sample_limit"]))

    rendered_title = render_literal_template(
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
    """严格锚定租户 snapshots/ 目录并阻止多层编码、反斜杠与符号链接穿越。"""
    if not snapshot_name or not isinstance(snapshot_name, str):
        raise ValueError("snapshot_name is required")

    decoded = snapshot_name
    for _ in range(3):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt

    if "\x00" in snapshot_name or "\x00" in decoded:
        raise ValueError("Invalid snapshot_name")
    if "/" in decoded or "\\" in decoded or ".." in decoded:
        raise PermissionError("Path traversal is not permitted")

    base_dir = (pathlib.Path(storage_dir) / caller.tenant_id / "snapshots").resolve()
    raw_target = base_dir / decoded
    if raw_target.is_symlink():
        raise PermissionError("Symlink snapshot access is not permitted")
    target_path = raw_target.resolve()
    if target_path == base_dir or not target_path.is_relative_to(base_dir):
        raise PermissionError("Snapshot path escapes tenant directory")
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
