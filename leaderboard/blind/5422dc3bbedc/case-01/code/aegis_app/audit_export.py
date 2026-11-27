# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。

安全与性能契约：
- rolling_sha256 摘要用数据库游标流式计算（O(1) 常驻内存），彻底消除原版
  fetchall + 双重 deepcopy 的全量内存驻留；
- 报表标题仅支持 {tenant_id}、{total_records}、{total_amount_cents} 三个字面
  占位符（保存时白名单校验 + 渲染时手动安全替换），杜绝 str.format 反射
  链（如 {env.master_pepper}）与宽度放大（{total_records:0>200000}）攻击；
- 报表事件过滤与租户条件全参数化，消除存储型二阶 SQL 注入；
- 快照读取执行"单次解码 + 相对路径校验 + realpath 锚定"双重防护，多变体
  目录穿越（....//、..\\、绝对路径、NUL）一律毫秒级拒绝。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .config import (
    MAX_AUDIT_SAMPLE_LIMIT,
    MAX_SNAPSHOT_FILE_BYTES,
    MAX_SNAPSHOT_NAME_LEN,
    MAX_TITLE_FORMAT_LEN,
)
from .db import open_connection

_ALLOWED_PLACEHOLDERS = {"tenant_id", "total_records", "total_amount_cents"}
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")


def _validate_title_format(t_fmt: str) -> None:
    """模板占位符白名单校验：仅允许三个字面占位符，禁止任何其他花括号结构。"""
    if len(t_fmt) > MAX_TITLE_FORMAT_LEN:
        raise ValueError("Valid template_id and title_format are required")
    for match in _PLACEHOLDER_RE.finditer(t_fmt):
        if match.group()[1:-1] not in _ALLOWED_PLACEHOLDERS:
            raise ValueError("title_format supports only {tenant_id}, {total_records}, {total_amount_cents} placeholders")
    residual = _PLACEHOLDER_RE.sub("", t_fmt)
    if "{" in residual or "}" in residual:
        raise ValueError("title_format contains unbalanced or unsupported braces")


def _render_title_safe(
    t_fmt: str,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """手动安全替换三个字面占位符（绝不调用 str.format，杜绝属性反射与宽度放大）。"""
    rendered = (
        t_fmt.replace("{tenant_id}", tenant_id)
        .replace("{total_records}", str(total_records))
        .replace("{total_amount_cents}", str(total_amount_cents))
    )
    if "{" in rendered or "}" in rendered:
        raise ValueError("Template contains unsupported placeholders")
    return rendered


def _compute_digest_streaming(
    conn: Any,
    sql: str,
    params: tuple[Any, ...],
    tenant_id: str,
    sample_limit: int,
) -> dict[str, Any]:
    """游标流式计算滚动摘要：逐行哈希 + 计数，常驻内存 O(1)（样本仅保留前 N 条）。"""
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    capped_sample = max(0, min(int(sample_limit), MAX_AUDIT_SAMPLE_LIMIT))
    samples: list[dict[str, Any]] = []

    for r in conn.execute(sql, params):
        log_id = int(r["log_id"])
        evt = r["event_type"]
        sev = r["severity"]
        amt = int(r["amount_cents"])
        masked = r["masked_account"]
        ts = int(r["ts"])
        total_records += 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        event_counts[evt] = event_counts.get(evt, 0) + 1
        total_amount_cents += amt
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
    """统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希（游标流式）。"""
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
        params.append(severity)

    sql = (
        "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
        "masked_account, ts, payload_json "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = open_connection(db_path)
    try:
        return _compute_digest_streaming(conn, sql, tuple(params), caller.tenant_id, sample_limit)
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
    s_lim = max(0, min(int(sample_limit), MAX_AUDIT_SAMPLE_LIMIT))
    if not tpl_id or not t_fmt or len(t_fmt) > MAX_TITLE_FORMAT_LEN:
        raise ValueError("Valid template_id and title_format are required")
    if len(tpl_id) > 64:
        raise ValueError("Valid template_id and title_format are required")
    if len(evt_flt) > 128:
        raise ValueError("extra_event_filter exceeds length limit")
    _validate_title_format(t_fmt)

    now_ts = int(caller.request_ts or int(time.time()))
    conn = open_connection(db_path)
    try:
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
    """读取已保存的报表模板并渲染生成带格式化标题的审计汇总报告（安全沙箱渲染）。"""
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
        if tpl["extra_event_filter"]:
            # 二阶注入修复：存储在模板里的事件过滤一律参数化，绝不拼接
            clauses.append("event_type = ?")
            params.append(str(tpl["extra_event_filter"]))

        sql = (
            "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
            "masked_account, ts, payload_json "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        digest = _compute_digest_streaming(
            conn, sql, tuple(params), caller.tenant_id, int(tpl["sample_limit"])
        )
        t_fmt = str(tpl["title_format"])
    finally:
        conn.close()

    rendered_title = _render_title_safe(
        t_fmt,
        caller.tenant_id,
        digest["total_records"],
        digest["total_amount_cents"],
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
    """读取当前租户归档目录下的合规季度快照文件（路径双重锚定，零穿越逃逸）。"""
    if not snapshot_name:
        raise ValueError("snapshot_name is required")
    if len(snapshot_name) > MAX_SNAPSHOT_NAME_LEN:
        raise ValueError("snapshot_name exceeds length limit")
    if "\x00" in snapshot_name:
        raise ValueError("snapshot_name contains illegal characters")

    decoded_once = urllib.parse.unquote(snapshot_name)
    if "\x00" in decoded_once or "\\" in decoded_once:
        raise ValueError("snapshot_name contains illegal characters")

    # 相对路径校验：拒绝绝对路径与任何 ".." 分量（覆盖 ....//、..%2f 等所有变体）
    pure = pathlib.PurePosixPath(decoded_once)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        raise ValueError("snapshot_name must be a relative path without traversal segments")

    base_dir = pathlib.Path(os.path.join(storage_dir, caller.tenant_id, "snapshots"))
    target_path = (base_dir / pathlib.PurePosixPath(decoded_once)).resolve()
    # realpath 锚定双保险：最终解析路径必须仍位于本租户快照目录内
    if not str(target_path).startswith(str(base_dir.resolve()) + os.sep):
        raise ValueError("snapshot_name escapes tenant snapshot directory")

    if not target_path.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")
    if target_path.stat().st_size > MAX_SNAPSHOT_FILE_BYTES:
        raise ValueError("Snapshot file exceeds maximum allowed size")

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
