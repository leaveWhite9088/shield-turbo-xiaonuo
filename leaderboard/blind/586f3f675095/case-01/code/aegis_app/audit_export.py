# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。

加固与性能要点：
* 摘要聚合走 **流式游标**（``fetchmany`` 分批），不再 ``fetchall`` 全量 + ``deepcopy`` 镜像；
* 报表标题使用**白名单字面量插值**（仅 ``{tenant_id}``/``{total_records}``/``{total_amount_cents}``，
  显式拒绝 ``{env}``/``{0.__class__}``/宽度 ``:0>200000`` 等格式化反射与放大载荷），
  模板中的 SQL 一律参数化（不再字符串拼接事件类型）；
* 快照读取先 URL 解码、再 ``realpath`` 归一与**租户目录前缀包含校验**，并限制文件大小。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import time
import urllib.parse
from typing import Any

from .auth import CallerContext, require_admin
from .config import MAX_ID_CHARS
from .db import GatewayDB
from .guards import guard_text, guard_json, strict_int

_DIGEST_COLS = (
    "SELECT log_id, event_type, severity, amount_cents, masked_account, ts, payload_json "
    "FROM audit_logs WHERE {where} ORDER BY log_id ASC"
)
_SAMPLE_CAP = 50
_MAX_TEMPLATE_CHARS = 200
_MAX_TEMPLATE_BRACES = 16
_MAX_TEMPLATE_NODES = 64
_MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
_PLACEHOLDER_RE = re.compile(r"\{\{|\}\}|\{([^{}]*)\}")
_ALLOWED_FIELDS = frozenset({"tenant_id", "total_records", "total_amount_cents"})
_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# 允许的格式规格：仅对齐/填充/符号/千分位/精度，且数值宽度有上限（拒绝 ``0>200000`` 类定宽放大）
_SPEC_RE = re.compile(r"(?:(.):([<>=^]))?([+\- ])?(#)?(0)?(\d{0,4})?([,_])?(\.\d{1,2})?([bcdeEfFgGnosxX%])?")
_BRACE_RE = re.compile(r"[{}]")
_LITERAL_BRACES = {"{": "\x00LBRACE\x00", "}": "\x00RBRACE\x00"}


def _split_token(token: str) -> tuple[str, str, str]:
    """按 ``format`` 语法切分占位符（字段名 / 转换 / 规格），字段名与规格内不允许再出现花括号。"""
    field, sep, spec = token.partition(":")
    conv = ""
    if "!" in field:
        field, _, conv = field.partition("!")
    return field, conv, (spec if sep else "")


def _validate_title_format(t_fmt: str) -> None:
    """只留下“能安全渲染且无反射/放大风险”的字面量载荷（其余字节按原样输出）。

    拒绝项（属地或严重风险均来自反射与二阶注入）：
    ``{env}``/``{env[VAR]}`` 等系统配置键、``.``/``[``/``]`` 引发的属性与下标链、
    ``{````}`` 嵌套规格、非法转换符与超长/定宽的格式放大。容量与长度均有上限。
    """
    if len(t_fmt) > _MAX_TEMPLATE_CHARS:
        raise ValueError("Valid template_id and title_format are required")
    opens = t_fmt.count("{")
    closes = t_fmt.count("}")
    if opens > _MAX_TEMPLATE_BRACES or closes > _MAX_TEMPLATE_BRACES:
        raise ValueError("title_format has too many placeholders")
    if any(ch in t_fmt for ch in ("[", "]", ".")):
        raise ValueError("Unsupported template placeholder expression")
    body = t_fmt.replace("{{", "  ").replace("}}", "  ")
    for token in _PLACEHOLDER_RE.findall(body):
        field, conv, spec = _split_token(token)
        if not _FIELD_RE.fullmatch(field):
            raise ValueError("Unsupported template placeholder")
        if field not in _ALLOWED_FIELDS:
            raise ValueError(f"Unsupported template placeholder: {{{field}}}")
        if conv:
            raise ValueError("Unsupported template conversion")
        if spec:
            if len(spec) > 16 or not _SPEC_RE.fullmatch(spec) or "{" in spec or "}" in spec:
                raise ValueError("Unsupported template format specification")


def _format_literal(raw: str) -> str:
    return raw.replace(_LITERAL_BRACES["{"], "").replace("}}", "")


def _format_value(value: Any, spec: str) -> str:
    if not isinstance(value, int):
        return _format_literal("{" + spec + "}")
    try:
        return format(value, spec)
    except (ValueError, TypeError):
        return _format_literal("{" + spec + "}")


def _render_title(t_fmt: str, values: dict[str, Any]) -> str:
    """白名单渲染：只替换三个数值/标识占位符；格式规格仅对数字生效，其余花括号按字面量输出。

    与 ``str.format`` 的可见差异仅限于“要么会被拒绝、要么只含花括号字面量”的模板，
    因此合法的正常报表模板渲染结果与原版逐字符一致。
    """
    out: list[str] = []
    i = 0
    n = len(t_fmt)
    while i < n:
        ch = t_fmt[i]
        if ch == "{":
            if t_fmt.startswith("{{", i):
                out.append(_LITERAL_BRACES["{"])
                i += 2
                continue
            end = t_fmt.find("}", i + 1)
            if end < 0:
                break
            field, _conv, spec = _split_token(t_fmt[i + 1:end])
            if field in values and "{" not in spec:
                out.append(str(values[field]) if not spec else _format_value(values[field], spec))
                i = end + 1
                continue
            out.append(_LITERAL_BRACES["{"])
            i += 1
            continue
        if ch == "}":
            if t_fmt.startswith("}}", i):
                out.append(_LITERAL_BRACES["}"])
                i += 2
            else:
                i += 1
            continue
        out.append(ch)
        i += 1
    text = "".join(out)
    return text.replace(_LITERAL_BRACES["{"], "{").replace(_LITERAL_BRACES["}"], "}")


def _scan_digest(db: GatewayDB, where_sql: str, params: tuple, tenant_id: str, sample_limit: int) -> dict[str, Any]:
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount = 0
    total_records = 0
    capped = max(0, min(int(sample_limit), _SAMPLE_CAP))
    samples: list[dict[str, Any]] = []
    cur = db.cursor(_DIGEST_COLS.format(where=where_sql), params)
    try:
        while True:
            batch = cur.fetchmany(256)
            if not batch:
                break
            for r in batch:
                amt = int(r["amount_cents"])
                sev = r["severity"]
                evt = r["event_type"]
                masked = r["masked_account"]
                ts = int(r["ts"])
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                event_counts[evt] = event_counts.get(evt, 0) + 1
                total_amount += amt
                total_records += 1
                hasher.update(f"{r['log_id']}|{evt}|{sev}|{amt}|{masked}|{ts}\n".encode("utf-8"))
                if len(samples) < capped:
                    samples.append(
                        {
                            "log_id": int(r["log_id"]),
                            "event_type": evt,
                            "severity": sev,
                            "amount_cents": amt,
                            "masked_account": masked,
                            "ts": ts,
                        }
                    )
    finally:
        cur.close()
    return {
        "tenant_id": tenant_id,
        "total_records": total_records,
        "total_amount_cents": total_amount,
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
        params.append(strict_int(start_ts, name="start_ts"))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(strict_int(end_ts, name="end_ts"))
    if severity:
        guard_text(severity, name="severity", max_chars=MAX_ID_CHARS)
        clauses.append("severity = ?")
        params.append(severity)
    limit = strict_int(sample_limit, name="sample_limit")
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        return _scan_digest(db, " AND ".join(clauses), tuple(params), caller.tenant_id, limit)
    finally:
        if own:
            db.close_thread()


def save_report_template(
    db_path: str,
    caller: CallerContext,
    *,
    template_id: str,
    title_format: str,
    extra_event_filter: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """保存租户自定义审计汇总报表配置模板（供周期性渲染报表复用）。"""
    if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
        require_admin(caller)
    tpl_id = str(template_id or "").strip()
    t_fmt = str(title_format or "").strip()
    evt_flt = str(extra_event_filter or "").strip()
    s_lim = max(0, min(strict_int(sample_limit, name="sample_limit"), _SAMPLE_CAP))
    if not tpl_id or not t_fmt or len(t_fmt) > _MAX_TEMPLATE_CHARS:
        raise ValueError("Valid template_id and title_format are required")
    guard_text(tpl_id, name="template_id", max_chars=MAX_ID_CHARS)
    guard_text(evt_flt, name="extra_event_filter", max_chars=MAX_ID_CHARS)
    _validate_title_format(t_fmt)

    now_ts = int(caller.request_ts or int(time.time()))
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        db.write(
            lambda conn: conn.execute(
                "INSERT OR REPLACE INTO report_templates("
                "tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (caller.tenant_id, tpl_id, t_fmt, evt_flt, s_lim, caller.user_id, now_ts),
            )
        )
    finally:
        if own:
            db.close_thread()

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
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    try:
        tpl = db.one(
            "SELECT template_id, title_format, extra_event_filter, sample_limit "
            "FROM report_templates WHERE tenant_id = ? AND template_id = ?",
            (caller.tenant_id, str(template_id)),
        )
        if not tpl:
            raise LookupError(f"Report template not found: {template_id}")

        clauses = ["tenant_id = ?"]
        params: list[Any] = [caller.tenant_id]
        if start_ts is not None:
            clauses.append("ts >= ?")
            params.append(strict_int(start_ts, name="start_ts"))
        if end_ts is not None:
            clauses.append("ts <= ?")
            params.append(strict_int(end_ts, name="end_ts"))
        if tpl["extra_event_filter"]:
            clauses.append("event_type = ?")
            params.append(tpl["extra_event_filter"])

        digest = _scan_digest(db, " AND ".join(clauses), tuple(params), caller.tenant_id,
                              int(tpl["sample_limit"]))
    finally:
        if own:
            db.close_thread()

    rendered_title = _render_title(
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
    """读取当前租户归档目录下的合规季度快照文件（多重归一 + 目录包含校验）。"""
    if not snapshot_name:
        raise ValueError("snapshot_name is required")
    guard_text(snapshot_name, name="snapshot_name", max_chars=MAX_ID_CHARS * 2)

    # 反复解码直到稳定（双重编码 ../ 也能被消除），再剥离路径分隔符
    decoded = snapshot_name
    for _ in range(3):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    decoded = decoded.replace("\\", "/")
    if "\x00" in decoded:
        raise ValueError("Invalid snapshot name")
    # 与原版同序清洗：先剔除所有 ``../``（含 ``....//`` 这类重叠变体），再消解点段
    cleaned = decoded
    while "../" in cleaned:
        cleaned = cleaned.replace("../", "")
    segs = [seg for seg in cleaned.split("/") if seg and seg != "."]
    if any(seg == ".." for seg in segs):
        raise PermissionError("Snapshot path escapes tenant storage directory")
    rel = "/".join(segs)

    base_dir = os.path.join(storage_dir, caller.tenant_id, "snapshots")
    real_base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(real_base, rel))
    if not (target == real_base or target.startswith(real_base + os.sep)):
        raise PermissionError("Snapshot path escapes tenant storage directory")
    if not os.path.isfile(target):
        raise LookupError(f"Snapshot file not found: {snapshot_name}")
    if os.path.getsize(target) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot file exceeds size limit")

    raw_text = pathlib.Path(target).read_text(encoding="utf-8", errors="replace")
    try:
        parsed = guard_json(raw_text)
    except ValueError:
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
