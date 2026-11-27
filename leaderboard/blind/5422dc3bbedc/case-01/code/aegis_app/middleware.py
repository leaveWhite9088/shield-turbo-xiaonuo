# -*- coding: utf-8 -*-
"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。

安全契约：
- JSON 载荷先做体积与嵌套深度预检（字符级扫描），千层 JSON / 巨型载荷在
  json.loads 递归爆炸前毫秒级硬熔断（400）；
- 内部诊断彻底脱敏：绝不返回主签名密钥、系统密钥表、数据库物理路径或
  webhook secret（原版 /api/v1/internal/diagnostics 无认证全量泄密）。
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .config import (
    GATEWAY_INTERNAL_BUILD,
    MAX_JSON_BODY_BYTES,
    MAX_JSON_NESTING_DEPTH,
)


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def _scan_json_depth(raw: str) -> int:
    """字符级扫描 JSON 最大嵌套深度（识别字符串/转义，避免字符串内花括号误计）。"""
    max_depth = 0
    depth = 0
    in_string = False
    escape = False
    for ch in raw:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in "}]":
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
    if len(raw.encode("utf-8", "ignore")) > MAX_JSON_BODY_BYTES:
        raise ValueError("Request JSON payload exceeds size limit")
    if _scan_json_depth(raw) > MAX_JSON_NESTING_DEPTH:
        raise ValueError("Request JSON nesting depth exceeds limit")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """内部诊断（脱敏版）：仅暴露非敏感聚合信息，严禁返回密钥/路径/租户凭证。"""
    from .db import open_connection

    conn = open_connection(db_path)
    try:
        t_rows = conn.execute("SELECT tenant_id, status FROM tenants").fetchall()
    finally:
        conn.close()
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "build": GATEWAY_INTERNAL_BUILD,
        "registered_tenants": [
            {"tenant_id": r["tenant_id"], "status": r["status"]} for r in t_rows
        ],
        "secrets": "REDACTED",
    }
