# -*- coding: utf-8 -*-
"""合规审计流水流式常量内存摘要导出、纯字面模板安全渲染与路径锚定快照读取服务。"""
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
from .middleware import parse_strict_int
from .runtime import get_runtime

_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_EVENT_FILTER_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ALLOWED_PLACEHOLDERS = frozenset({"tenant_id", "total_records", "total_amount_cents"})

_STREAM_BATCH_SIZE = 512
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024  # 2 MiB


def _validate_and_render_title(
    title_format: str,
    values: dict[str, str] | None = None,
) -> str:
    """纯字面占位符白名单解析与渲染器（彻底废弃 str.format，零反射、零格式宽度放大）。

    仅允许 {tenant_id}、{total_records}、{total_amount_cents} 三个精确字面占位符，
    拒绝任何属性访问(.)、下标([])、转换(!)、宽度填充(:)或未授权变量名。
    """
    if not isinstance(title_format, str) or not title_format or len(title_format) > 200:
        raise ValueError("Valid title_format (1..200 chars) is required")

    out: list[str] = []
    n = len(title_format)
    i = 0
    while i < n:
        ch = title_format[i]
        if ch == "{":
            close_idx = title_format.find("}", i + 1)
            if close_idx == -1:
                raise ValueError("Unclosed '{' in title_format")
            token = title_format[i + 1: close_idx]
            if "{" in token or token not in _ALLOWED_PLACEHOLDERS:
                raise ValueError("Unsupported or unsafe placeholder in title_format")
            if values is not None:
                out.append(values[token])
            i = close_idx + 1
        elif ch == "}":
            raise ValueError("Unmatched '}' in title_format")
        else:
            out.append(ch)
            i += 1
    return "".join(out) if values is not None else title_format


def _stream_audit_digest(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
    tenant_id: str,
    sample_limit: int,
) -> dict[str, Any]:
    """O(1) 常量内存单遍流式游标聚合（fetchmany 分批迭代，不加载 payload_json，零 deepcopy）。"""
    capped_sample = max(0, min(int(sample_limit), 50))
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_records = 0
    total_amount_cents = 0
    samples: list[dict[str, Any]] = []

    cur = conn.execute(sql, params)
    while True:
        batch = cur.fetchmany(_STREAM_BATCH_SIZE)
        if not batch:
            break
        for r in batch:
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
        sev_str = str(severity).strip()
        if len(sev_str) > 32:
            raise ValueError("Invalid severity filter")
        clauses.append("severity = ?")
        params.append(sev_str)

    s_lim = parse_strict_int(sample_limit, "sample_limit", default=10, min_val=0)
    sql = (
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    rt = get_runtime(db_path)
    with rt.read_conn() as conn:
        return _stream_audit_digest(conn, sql, tuple(params), caller.tenant_id, s_lim)


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（写入侧严格校验字面占位符白名单与合法事件名）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)

    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    s_lim = max(0, min(parse_strict_int(sample_limit, "sample_limit", default=10, min_val=0), 50))

    if not tpl_id or not _TEMPLATE_ID_RE.match(tpl_id):
        raise ValueError("Valid template_id is required")
    _validate_and_render_title(t_fmt, values=None)
    if evt_flt and not _EVENT_FILTER_RE.match(evt_flt):
        raise ValueError("Invalid extra_event_filter: only [A-Z0-9_] event names are allowed")

    now_ts = int(caller.request_ts or int(time.time()))
    rt = get_runtime(db_path)
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
    """读取已保存的报表模板，以全参数化流式聚合与纯字面安全渲染生成审计汇总报告。"""
    tpl_id = str(template_id or "").strip()
    if not tpl_id or len(tpl_id) > 64:
        raise ValueError("Valid template_id is required")

    s_ts = parse_strict_int(start_ts, "start_ts") if start_ts is not None else None
    e_ts = parse_strict_int(end_ts, "end_ts") if end_ts is not None else None

    rt = get_runtime(db_path)
    with rt.read_conn() as conn:
        tpl = conn.execute(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, tpl_id),
        ).fetchone()
        if not tpl:
            raise LookupError(f"Report template not found: {tpl_id}")

        t_fmt = str(tpl["title_format"])
        # 读取侧二次校验模板安全性（抵御存量恶意数据）
        _validate_and_render_title(t_fmt, values=None)

        evt_flt = str(tpl["extra_event_filter"] or "").strip()
        if evt_flt and not _EVENT_FILTER_RE.match(evt_flt):
            raise ValueError("Stored template contains invalid event filter")

        # 全参数化 SQL 查询，彻底堵死二阶 SQL 注入
        clauses = ["tenant_id = ?"]
        params: list[Any] = [caller.tenant_id]
        if s_ts is not None:
            clauses.append("ts >= ?")
            params.append(s_ts)
        if e_ts is not None:
            clauses.append("ts <= ?")
            params.append(e_ts)
        if evt_flt:
            clauses.append("event_type = ?")
            params.append(evt_flt)

        sql = (
            "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        digest = _stream_audit_digest(
            conn,
            sql,
            tuple(params),
            caller.tenant_id,
            int(tpl["sample_limit"]),
        )

    rendered_title = _validate_and_render_title(
        t_fmt,
        values={
            "tenant_id": caller.tenant_id,
            "total_records": str(digest["total_records"]),
            "total_amount_cents": str(digest["total_amount_cents"]),
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
    """读取当前租户归档目录下的合规季度快照文件（多层目录穿越、双重编码与符号链接锚定防护）。"""
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")

    # 迭代解码最多 3 次，拦截任何单重/多重 URL 编码、反斜杠、空字节或路径穿越字符
    curr = snapshot_name
    for _ in range(3):
        if (
            "\x00" in curr
            or "/" in curr
            or "\\" in curr
            or ".." in curr
            or ":" in curr
        ):
            raise PermissionError("Invalid snapshot_name: path traversal detected")
        nxt = urllib.parse.unquote(curr)
        if nxt == curr:
            break
        curr = nxt

    if (
        "\x00" in curr
        or "/" in curr
        or "\\" in curr
        or ".." in curr
        or ":" in curr
        or not _SNAPSHOT_NAME_RE.match(curr)
    ):
        raise PermissionError("Invalid snapshot_name format")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    candidate = base_dir / curr

    if candidate.is_symlink():
        raise PermissionError("Symlink access is disallowed")

    resolved = candidate.resolve()
    if not resolved.is_relative_to(base_dir) or resolved == base_dir:
        raise PermissionError("Snapshot path escapes tenant sandbox")

    if not resolved.is_file():
        raise LookupError(f"Snapshot file not found: {curr}")

    if resolved.stat().st_size > _MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot file exceeds maximum allowed size")

    raw_text = resolved.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
