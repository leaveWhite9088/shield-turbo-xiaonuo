# -*- coding: utf-8 -*-
"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。

纵深加固要点：

* **JSON 预检深度**：在 ``json.loads`` **之前** 以零额外内存的字符扫描判定
  嵌套深度与体积上限，畸形千层 JSON 在解析前即被毫秒级拒绝，
  杜绝「解析后再检查」造成的解析期资源放大；
* **诊断信息脱敏**：内部诊断聚合不再返回主密钥 pepper、系统密钥明文与
  物理磁盘路径，仅暴露无害的结构性计数。
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .config import GATEWAY_INTERNAL_BUILD
from .db import open_connection

# 请求体体积上限（防内存放大）。
MAX_REQUEST_BODY_BYTES = 1024 * 1024
# JSON 嵌套深度上限。
MAX_JSON_DEPTH = 32


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def measure_json_depth(raw: str) -> int:
    """零额外内存地扫描 JSON 文本的最大嵌套深度（解析前预检）。"""
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch == "}" or ch == "]":
            depth -= 1
    return max_depth


def measure_structure_depth(node: Any, depth: int = 0) -> int:
    """已解析对象（dict/list）的嵌套深度测量。"""
    if depth > MAX_JSON_DEPTH + 1:
        return depth
    max_depth = depth
    if isinstance(node, dict):
        for value in node.values():
            child = measure_structure_depth(value, depth + 1)
            if child > max_depth:
                max_depth = child
    elif isinstance(node, list):
        for value in node:
            child = measure_structure_depth(value, depth + 1)
            if child > max_depth:
                max_depth = child
    return max_depth


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        # 直传对象同样执行嵌套深度闸门，避免以对象形式绕过深度限制。
        if measure_structure_depth(body) > MAX_JSON_DEPTH:
            raise ValueError("Request JSON payload nesting depth exceeds the allowed limit")
        raw = json.dumps(body, separators=(",", ":"))
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_REQUEST_BODY_BYTES:
            raise ValueError("Request payload exceeds the maximum size")
        raw = body.decode("utf-8")
    else:
        raw = str(body)
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        raise ValueError("Request payload exceeds the maximum size")
    if not raw.strip():
        return {}, raw
    # 解析前预检嵌套深度：畸形千层 JSON 不进入解析器。
    if measure_json_depth(raw) > MAX_JSON_DEPTH:
        raise ValueError("Request JSON payload nesting depth exceeds the allowed limit")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """内部诊断聚合（已脱敏）。

    仅暴露结构性计数与版本信息；**绝不**返回主密钥 pepper、系统密钥明文、
    租户 webhook 密钥与物理磁盘路径。该接口在路由层还需 COMPLIANCE_ADMIN 鉴权。
    """
    conn = open_connection(db_path)
    try:
        tenant_count = int(
            conn.execute("SELECT COUNT(*) FROM tenants WHERE status = 'ACTIVE'").fetchone()[0]
        )
        secret_count = int(
            conn.execute("SELECT COUNT(*) FROM system_secrets").fetchone()[0]
        )
        return {
            "service": "aegis-gateway",
            "version": __version__,
            "build": GATEWAY_INTERNAL_BUILD,
            "active_tenant_count": tenant_count,
            "secret_record_count": secret_count,
        }
    finally:
        conn.close()
