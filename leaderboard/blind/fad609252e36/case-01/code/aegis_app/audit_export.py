# -*- coding: utf-8 -*-
"""合规审计流水 O(1) 内存流式摘要导出、零反射字面占位符报表渲染与防穿越快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .db import open_connection
from .middleware import strict_int

_VALID_PLACEHOLDER_RE = re.compile(r"\{(tenant_id|total_records|total_amount_cents)\}")
_VALID_EVENT_FILTER_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
_VALID_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.json$")
_STREAM_FETCH_BATCH = 512


def _validate_title_format(title_format: str) -> str:
    if not isinstance(title_format, str):
        raise ValueError("title_format must be a string")
    t_fmt = title_format.strip()
    if not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid title_format within 200 characters is required")
    residual = _VALID_PLACEHOLDER_RE.sub("", t_fmt)
    if "{" in residual or "}" in residual:
        raise ValueError("Unsupported placeholder, attribute access, or width specifier in title_format")
    return t_fmt


def _render_safe_title(
    title_format: str,
    *,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """使用严格字面正则替换渲染报表标题（绝不调用 str.format，彻底阻断属性反射与宽度放大炸弹）。"""
    clean_fmt = _validate_title_format(title_format)
    mapping = {
        "tenant_id": str(tenant_id),
        "total_records": str(total_records),
        "total_amount_cents": str(total_amount_cents),
    }
    return _VALID_PLACEHOLDER_RE.sub(lambda m: mapping[m.group(1)], clean_fmt)


def _compute_digest_from_records(
    tenant_id: str,
    raw_rows: Iterable[Any],
    sample_limit: int,
) -> dict[str, Any]:
    capped_sample = max(0, min(strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000), 50))
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    samples: list[dict[str, Any]] = []

    for r in raw_rows:
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


def _stream_audit_digest_query(
    db_path: str,
    tenant_id: str,
    sql: str,
    params: tuple[Any, ...],
    sample_limit: int,
) -> dict[str, Any]:
    """通过 SQLite 游标 fetchmany 分块流式扫描审计流水，以 O(1) 常数内存完成滚动 SHA-256 摘要。"""
    capped_sample = max(0, min(strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000), 50))
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    samples: list[dict[str, Any]] = []

    conn = open_connection(db_path)
    try:
        cur = conn.execute(sql, params)
        while True:
            rows = cur.fetchmany(_STREAM_FETCH_BATCH)
            if not rows:
                break
            for r in rows:
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
    finally:
        conn.close()

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
        params.append(strict_int(start_ts, "start_ts"))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(strict_int(end_ts, "end_ts"))
    sev = str(severity or "").strip()
    if sev:
        if len(sev) > 32:
            raise ValueError("Invalid severity filter")
        clauses.append("severity = ?")
        params.append(sev)

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )
    return _stream_audit_digest_query(db_path, caller.tenant_id, sql, tuple(params), sample_limit)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（校验三项字面占位符白名单与合法事件类型名）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    if not isinstance(template_id, str) or not isinstance(title_format, str) or not isinstance(extra_event_filter, str):
        raise ValueError("Template fields must be strings")

    tpl_id = template_id.strip()
    if not tpl_id or len(tpl_id) > 128:
        raise ValueError("Valid template_id is required")
    t_fmt = _validate_title_format(title_format)
    evt_flt = extra_event_filter.strip()
    if evt_flt and not _VALID_EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("Invalid extra_event_filter format")
    s_lim = max(0, min(strict_int(sample_limit, "sample_limit", min_val=0, max_val=1000), 50))

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
    """读取已保存的报表模板并安全渲染审计汇总报告（全参数化查询阻断二阶注入 + 字面占位符替换阻断格式化反射/放大）。"""
    tpl_id = str(template_id or "").strip()
    if not tpl_id or len(tpl_id) > 128:
        raise ValueError("Valid template_id is required")

    conn = open_connection(db_path)
    try:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, tpl_id),
        ).fetchone()
    finally:
        conn.close()

    if not tpl:
        raise LookupError(f"Report template not found: {tpl_id}")

    t_fmt = _validate_title_format(str(tpl["title_format"]))
    evt_flt = str(tpl["extra_event_filter"] or "").strip()
    if evt_flt and not _VALID_EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("Stored template contains invalid extra_event_filter")

    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(strict_int(start_ts, "start_ts"))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(strict_int(end_ts, "end_ts"))
    if evt_flt:
        clauses.append("event_type = ?")
        params.append(evt_flt)

    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )
    digest = _stream_audit_digest_query(
        db_path,
        caller.tenant_id,
        sql,
        tuple(params),
        int(tpl["sample_limit"]),
    )
    rendered_title = _render_safe_title(
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
    """读取当前租户归档目录下的合规季度快照文件（多层解码校验 + 文件名白名单 + resolve 目录锚定防穿越）。"""
    if not isinstance(snapshot_name, str) or not snapshot_name.strip():
        raise ValueError("snapshot_name is required")
    if len(snapshot_name) > 128 or "\x00" in snapshot_name:
        raise ValueError("Invalid snapshot_name")

    curr = snapshot_name
    for _ in range(3):
        nxt = urllib.parse.unquote(curr)
        if nxt == curr:
            break
        curr = nxt

    for candidate in (snapshot_name, curr):
        if (
            ".." in candidate
            or "/" in candidate
            or "\\" in candidate
            or ":" in candidate
            or not _VALID_SNAPSHOT_NAME_RE.match(candidate)
        ):
            raise PermissionError("Invalid or traversal snapshot_name rejected")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    raw_target = base_dir / snapshot_name
    if raw_target.is_symlink():
        raise PermissionError("Symlink snapshot access is forbidden")
    target_path = raw_target.resolve()
    if target_path.parent != base_dir or not target_path.is_relative_to(base_dir):
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
