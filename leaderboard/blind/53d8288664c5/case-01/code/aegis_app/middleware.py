# -*- coding: utf-8 -*-
"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .config import GATEWAY_INTERNAL_BUILD
from .db import open_connection

# 载荷安全预算：超体积 / 超深嵌套的畸形报文在 json.loads 之前就地毫秒级熔断。
_MAX_RAW_JSON_CHARS = 2_000_000
_MAX_JSON_DEPTH = 64


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def _precheck_json_nesting_depth(raw: str) -> int:
    """在 json.loads 之前用 O(N) 状态机扫描原始文本的最大花括号/方括号嵌套深度。

    字符串字面量内的括号不计入；畸形不闭合的载荷交给 json.loads 原有语义报 400。
    """
    depth = 0
    max_depth = 0
    in_str = False
    escaped = False
    for ch in raw:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                max_depth = depth
                if max_depth > _MAX_JSON_DEPTH:
                    return max_depth
        elif ch == "}" or ch == "]":
            if depth > 0:
                depth -= 1
    return max_depth


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        raw = json.dumps(body, separators=(",", ":"))
        return body, raw
    if isinstance(body, bytes):
        raw = body.decode("utf-8")
    else:
        raw = str(body)
    if not raw.strip():
        return {}, raw
    if len(raw) > _MAX_RAW_JSON_CHARS:
        raise ValueError("Request payload exceeds maximum allowed size")
    if _precheck_json_nesting_depth(raw) > _MAX_JSON_DEPTH:
        raise ValueError("Request payload exceeds maximum allowed nesting depth")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """聚合脱敏后的网关内部诊断摘要。

    安全契约：严禁向未授权方泄露内部诊断配置、物理路径、主密钥、
    租户 webhook 密钥或系统保险库机密，此处仅返回最小化的非敏感计数摘要。
    """
    conn = open_connection(db_path)
    try:
        t_row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) AS active "
            "FROM tenants"
        ).fetchone()
    finally:
        conn.close()
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "build": GATEWAY_INTERNAL_BUILD,
        "registered_tenants": int(t_row["total"] or 0),
        "active_tenants": int(t_row["active"] or 0),
    }
