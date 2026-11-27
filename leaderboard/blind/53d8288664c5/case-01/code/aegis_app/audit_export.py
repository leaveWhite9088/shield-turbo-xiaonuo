# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。

安全与性能重构（正常业务输出 100% 零失真）：
- 摘要导出 / 报表渲染改为游标流式滚动哈希：内存占用 O(sample_limit)，
  不再 fetchall 全量入库（原版逐行 json.loads 解析后弃用的冗余一并去除）；
- 报表模板二阶注入双闸门：保存时「字面占位符白名单 + 合法事件名校验」，
  渲染时白名单复检并以安全逐字替换取代 str.format（杜绝 {env...} 反射
  泄密与 {:0>N} 宽度放大炸弹），审计查询全程参数化；
- 快照读取纯文件名白名单 + realpath 锚定校验，封死编码、嵌套、反斜杠、
  点段与符号链接等多变体目录穿越。
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
from typing import Any, Iterable

from .auth import CallerContext, require_admin
from .db import open_connection

_ALLOWED_TITLE_PLACEHOLDERS = ("{tenant_id}", "{total_records}", "{total_amount_cents}")
_EVENT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_MAX_TEMPLATE_ID_LEN = 128
_MAX_TITLE_FORMAT_LEN = 200


def _validate_title_format(t_fmt: str) -> None:
    """字面占位符白名单校验：除三个合法占位符外不得出现任何花括号结构。"""
    residue = t_fmt
    for ph in _ALLOWED_TITLE_PLACEHOLDERS:
        residue = residue.replace(ph, "")
    if "{" in residue or "}" in residue:
        raise ValueError(
            "title_format may only contain literal placeholders: "
            "{tenant_id}, {total_records}, {total_amount_cents}"
        )


def _render_template_title(
    t_fmt: str,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """安全标题渲染：渲染前复检白名单（纵深防御拦截历史遗留非法模板），
    再以纯字面替换生成标题，全程不触碰 str.format 的反射与格式说明符语法。"""
    _validate_title_format(t_fmt)
    return (
        t_fmt.replace("{tenant_id}", str(tenant_id))
        .replace("{total_records}", str(int(total_records)))
        .replace("{total_amount_cents}", str(int(total_amount_cents)))
    )


def _compute_digest_from_rows(
    tenant_id: str,
    rows: Iterable[Any],
    sample_limit: int,
) -> dict[str, Any]:
    """游标流式计算审计流水分布、总金额与 log_id ASC 滚动 SHA-256 摘要。

    常驻内存仅保留前 capped_sample 条样本，不将全量流水载入内存。
    """
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0

    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    for r in rows:
        log_id = int(r["log_id"])
        evt = r["event_type"]
        sev = r["severity"]
        amt = int(r["amount_cents"])
        masked_account = r["masked_account"]
        ts = int(r["ts"])

        total_records += 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        event_counts[evt] = event_counts.get(evt, 0) + 1
        total_amount_cents += amt

        line = f"{log_id}|{evt}|{sev}|{amt}|{masked_account}|{ts}\n"
        hasher.update(line.encode("utf-8"))

        if len(samples) < capped_sample:
            samples.append(
                {
                    "log_id": log_id,
                    "event_type": evt,
                    "severity": sev,
                    "amount_cents": amt,
                    "masked_account": masked_account,
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
        params.append(severity)

    sql = (
        "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
        "masked_account, ts, payload_json "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = open_connection(db_path)
    try:
        cursor = conn.execute(sql, tuple(params))
        return _compute_digest_from_rows(caller.tenant_id, cursor, sample_limit)
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

    合法 title_format 仅支持字面占位符 {tenant_id}、{total_records}、
    {total_amount_cents}；extra_event_filter 为空字符串或合法事件名
    （如 RISK_EVAL、DOC_ACCESS）——二阶注入载荷在保存时即被 400 拒绝。
    """
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    s_lim = max(0, min(int(sample_limit), 50))
    if not tpl_id or not t_fmt or len(t_fmt) > _MAX_TITLE_FORMAT_LEN:
        raise ValueError("Valid template_id and title_format are required")
    if len(tpl_id) > _MAX_TEMPLATE_ID_LEN:
        raise ValueError("template_id exceeds maximum length")
    _validate_title_format(t_fmt)
    if evt_flt and not _EVENT_NAME_RE.match(evt_flt):
        raise ValueError("extra_event_filter must be a valid event name")

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
        if tpl["extra_event_filter"]:
            clauses.append("event_type = ?")
            params.append(str(tpl["extra_event_filter"]))

        sql = (
            "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
            "masked_account, ts, payload_json "
            f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
        )
        cursor = conn.execute(sql, tuple(params))
        digest = _compute_digest_from_rows(caller.tenant_id, cursor, int(tpl["sample_limit"]))
    finally:
        conn.close()

    rendered_title = _render_template_title(
        str(tpl["title_format"]),
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
    """读取当前租户归档目录下的合规季度快照文件。

    路径安全契约：快照名必须为纯文件名（字母数字开头，仅含字母数字、点、
    下划线、连字符），拒绝任何路径分隔符、点段、空字节与编码残留；读取前
    经 realpath 锚定校验快照确实位于本租户 snapshots 目录内（含符号链接逃逸）。
    """
    if not snapshot_name:
        raise ValueError("snapshot_name is required")
    if len(snapshot_name) > 255 or not _SNAPSHOT_NAME_RE.match(snapshot_name) or ".." in snapshot_name:
        raise ValueError("Invalid snapshot name")

    base_dir = pathlib.Path(storage_dir) / caller.tenant_id / "snapshots"
    base_resolved = base_dir.resolve()
    target = base_resolved / snapshot_name

    if not target.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")
    resolved = target.resolve()
    if resolved.parent != base_resolved:
        raise LookupError(f"Snapshot file not found: {snapshot_name}")

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
