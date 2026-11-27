# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。

纵深加固要点：

* **流式摘要**：审计流水按 ``log_id ASC`` 游标分块读取，边读边算滚动哈希与
  分布统计，**不再 fetchall 全表进内存**，也不再逐行 ``copy.deepcopy``；
* **模板沙箱**：标题渲染改为 **字面占位符白名单**（``{tenant_id}`` /
  ``{total_records}`` / ``{total_amount_cents}``），彻底移除 ``str.format`` 的
  属性反射（``{env.master_pepper}``）与宽度放大（``{tenant_id:0>200000}``）；
* **二阶注入封堵**：事件过滤器全部走参数化查询，杜绝「先落库、后拼接」的
  二阶 SQL 注入；
* **路径锚定**：快照读取以 ``realpath`` 锚定在租户快照目录内，
  多变体目录穿越（``../``、``..%2f``、绝对路径、符号链接）一律拒绝。
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
from typing import Any, Iterator

from .auth import CallerContext, require_admin
from .db import open_connection, write_transaction

# 允许的报表标题占位符（字面量白名单）。
ALLOWED_TITLE_PLACEHOLDERS = ("tenant_id", "total_records", "total_amount_cents")
# 事件名过滤的合法形态（仅大写字母、数字与下划线）。
_EVENT_FILTER_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
# 渲染结果长度上限（防标题放大）。
MAX_RENDERED_TITLE_LEN = 4096
# 快照文件体积上限。
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
# 审计流式读取分块大小。
_AUDIT_CHUNK = 500


def _iter_audit_rows(conn: Any, sql: str, params: tuple[Any, ...]) -> Iterator[Any]:
    """游标分块读取审计流水（常驻内存与总记录数解耦）。"""
    cursor = conn.execute(sql, params)
    try:
        while True:
            rows = cursor.fetchmany(_AUDIT_CHUNK)
            if not rows:
                break
            for row in rows:
                yield row
    finally:
        cursor.close()


def _accumulate_digest(
    tenant_id: str,
    rows: Iterator[Any],
    sample_limit: int,
) -> dict[str, Any]:
    """流式累计滚动摘要（内存占用与样本数成正比，与流水总量无关）。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    for rec in rows:
        sev = str(rec["severity"])
        evt = str(rec["event_type"])
        amt = int(rec["amount_cents"])
        masked = str(rec["masked_account"])
        ts = int(rec["ts"])
        log_id = int(rec["log_id"])

        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        event_counts[evt] = event_counts.get(evt, 0) + 1
        total_amount_cents += amt
        total_records += 1
        hasher.update(f"{log_id}|{evt}|{sev}|{amt}|{masked}|{ts}\n".encode("utf-8"))

        if len(samples) < capped_sample:
            samples.append(
                {
                    "log_id": log_id,
                    "event_type": evt,
                    "severity": sev,
                    "amount_cents": amt,
                    "masked_account": masked,
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
    """统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。"""
    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(int(start_ts))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(int(end_ts))
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity))

    sql = (
        "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
        "masked_account, ts, payload_json "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = open_connection(db_path)
    try:
        rows = _iter_audit_rows(conn, sql, tuple(params))
        return _accumulate_digest(caller.tenant_id, rows, sample_limit)
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
    """保存租户自定义审计汇总报表配置模板（供周期性渲染报表复用）。

    合法 title_format 支持占位符 {tenant_id}、{total_records}、{total_amount_cents}；
    extra_event_filter 为空字符串或目标事件类型名称（如 RISK_EVAL、DOC_ACCESS）。
    """
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    s_lim = max(0, min(int(sample_limit), 50))
    if not tpl_id or not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid template_id and title_format are required")
    if len(tpl_id) > 64:
        raise ValueError("template_id exceeds the maximum length")
    if evt_flt and not _EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("extra_event_filter must be a legal event name")

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
        with write_transaction(conn):
            conn.execute(
                "INSERT OR REPLACE INTO report_templates("
                "tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, tpl_id, t_fmt, evt_flt, s_lim, caller.user_id, now_ts),
            )
    finally:
        conn.close()

    return {
        "tenant_id": caller.tenant_id,
        "template_id": tpl_id,
        "title_format": t_fmt,
        "extra_event_filter": evt_flt,
        "sample_limit": s_lim,
    }


def render_report_title(
    title_format: str,
    *,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """按字面占位符白名单安全渲染报表标题。

    仅接受 ``{tenant_id}``、``{total_records}``、``{total_amount_cents}`` 三个
    占位符；任何格式说明符（``:0>200000``）、属性访问（``{env.secret}``）、
    下标访问或未知占位符一律拒绝，从根上消除格式化反射与放大面。
    """
    mapping = {
        "tenant_id": tenant_id,
        "total_records": total_records,
        "total_amount_cents": total_amount_cents,
    }
    out: list[str] = []
    idx = 0
    length = len(title_format)
    while idx < length:
        ch = title_format[idx]
        if ch == "{":
            if idx + 1 < length and title_format[idx + 1] == "{":
                out.append("{")
                idx += 2
                continue
            end = title_format.find("}", idx + 1)
            if end == -1:
                raise ValueError("Malformed placeholder in report title format")
            name = title_format[idx + 1 : end]
            if name not in mapping:
                raise ValueError(f"Unsupported placeholder in report title format: {name}")
            out.append(str(mapping[name]))
            idx = end + 1
            continue
        if ch == "}":
            if idx + 1 < length and title_format[idx + 1] == "}":
                out.append("}")
                idx += 2
                continue
            raise ValueError("Malformed placeholder in report title format")
        out.append(ch)
        idx += 1
    rendered = "".join(out)
    if len(rendered) > MAX_RENDERED_TITLE_LEN:
        raise ValueError("Rendered report title exceeds the maximum length")
    return rendered


def render_saved_report(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    start_ts: int | None = None,
    end_ts: int | None = None,
) -> dict[str, Any]:
    """读取已保存的报表模板并渲染生成带格式化标题的审计汇总报告。"""
    conn = open_connection(db_path)
    try:
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
            params.append(int(start_ts))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(int(end_ts))
        event_filter = str(tpl["extra_event_filter"] or "").strip()
        if event_filter:
            # 参数化：杜绝「模板落库 -> 渲染时拼接」的二阶注入。
            if not _EVENT_FILTER_RE.match(event_filter):
                raise ValueError("Stored report template carries an illegal event filter")
            clauses.append("event_type = ?")
            params.append(event_filter)

        sql = (
            "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
            "masked_account, ts, payload_json "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        rows = _iter_audit_rows(conn, sql, tuple(params))
        digest = _accumulate_digest(caller.tenant_id, rows, int(tpl["sample_limit"]))
    finally:
        conn.close()

    rendered_title = render_report_title(
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
    """读取当前租户归档目录下的合规季度快照文件（路径强锚定）。"""
    if not snapshot_name:
        raise ValueError("snapshot_name is required")

    decoded = urllib.parse.unquote(str(snapshot_name))
    if not decoded or len(decoded) > 256:
        raise ValueError("Invalid snapshot_name")
    if "\x00" in decoded:
        raise ValueError("Invalid snapshot_name")

    storage_root = pathlib.Path(storage_dir).resolve()
    base_dir = (storage_root / caller.tenant_id / "snapshots").resolve()
    # 租户目录本身必须位于存储根目录内（防止 tenant_id 越界）。
    try:
        base_dir.relative_to(storage_root)
    except ValueError as exc:
        raise LookupError(f"Snapshot file not found: {snapshot_name}") from exc

    candidate = (base_dir / decoded).resolve()
    try:
        candidate.relative_to(base_dir)
    except ValueError as exc:
        # 目录穿越 / 绝对路径 / 符号链接逃逸一律拒绝。
        raise LookupError(f"Snapshot file not found: {snapshot_name}") from exc

    if not candidate.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")
    try:
        size = candidate.stat().st_size
    except OSError as exc:
        raise LookupError(f"Snapshot file not found: {snapshot_name}") from exc
    if size > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot file exceeds the maximum size")

    raw_text = candidate.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
