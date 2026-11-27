# -*- coding: utf-8 -*-
"""网关请求载荷预检解析、严格类型守卫与脱敏运行状态组件。"""
from __future__ import annotations

import json
import math
import re
import urllib.parse
from typing import Any

from . import __version__
from .config import (
    INT64_MAX,
    INT64_MIN,
    MAX_JSON_BODY_BYTES,
    MAX_JSON_CONTAINER_NODES,
    MAX_JSON_DEPTH,
)

_STRICT_INT_STR_RE = re.compile(r"^[+-]?[0-9]{1,20}$")


def strict_int(
    value: Any,
    field_name: str = "integer",
    *,
    min_val: int = INT64_MIN,
    max_val: int = INT64_MAX,
    allow_str: bool = False,
) -> int:
    """严格整数校验：拒绝 bool、float、NaN/Inf、超 64 位整数及畸形数字字符串。"""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not boolean")
    if isinstance(value, int):
        parsed = value
    elif allow_str and isinstance(value, str):
        stripped = value.strip()
        if not _STRICT_INT_STR_RE.match(stripped):
            raise ValueError(f"Malformed integer for {field_name}")
        parsed = int(stripped, 10)
    else:
        raise ValueError(f"{field_name} must be an integer")

    if parsed < INT64_MIN or parsed > INT64_MAX:
        raise ValueError(f"{field_name} exceeds 64-bit integer range")
    if parsed < min_val or parsed > max_val:
        raise ValueError(f"{field_name} out of allowed bounds")
    return parsed


def strict_bool(value: Any, field_name: str = "boolean") -> bool:
    """严格布尔校验：仅允许布尔值或精确整数 0/1。"""
    if isinstance(value, bool):
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    raise ValueError(f"{field_name} must be a boolean")


def _reject_json_constant(const_str: str) -> Any:
    raise ValueError(f"Non-standard JSON constant is forbidden: {const_str}")


def _precheck_json_structure(raw: str) -> None:
    """在调用 json.loads 之前单遍扫描验证字节体积、括号嵌套深度与容器规模，防止千层 JSON 递归栈溢出。"""
    if len(raw) > MAX_JSON_BODY_BYTES:
        raise ValueError("JSON payload exceeds maximum size limit")

    depth = 0
    containers = 0
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
            containers += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting depth limit exceeded")
            if containers > MAX_JSON_CONTAINER_NODES:
                raise ValueError("JSON container node budget exceeded")
        elif ch == "}" or ch == "]":
            depth -= 1
            if depth < 0:
                raise ValueError("Malformed JSON bracket structure")


def _validate_python_payload_tree(root: dict[str, Any]) -> None:
    """针对进程内直接传入 dict 的调用路径执行深度、节点预算与 NaN/Inf/超大整数预检。"""
    stack: list[tuple[Any, int]] = [(root, 1)]
    containers = 0
    while stack:
        curr, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("Payload nesting depth limit exceeded")
        if isinstance(curr, dict):
            containers += 1
            if containers > MAX_JSON_CONTAINER_NODES:
                raise ValueError("Payload container budget exceeded")
            for k, v in curr.items():
                if not isinstance(k, str):
                    raise ValueError("JSON object keys must be strings")
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
                elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    raise ValueError("NaN or Infinity is not allowed in payload")
        elif isinstance(curr, list):
            containers += 1
            if containers > MAX_JSON_CONTAINER_NODES:
                raise ValueError("Payload container budget exceeded")
            for item in curr:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))
                elif isinstance(item, float) and (math.isnan(item) or math.isinf(item)):
                    raise ValueError("NaN or Infinity is not allowed in payload")


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Request URL length limit exceeded")
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    pairs = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)
    if len(pairs) > 64:
        raise ValueError("Too many query parameters")
    return route, dict(pairs)


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _validate_python_payload_tree(body)
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_JSON_BODY_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_JSON_BODY_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        try:
            raw = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid UTF-8 request body") from exc
    elif isinstance(body, str):
        if len(body.encode("utf-8")) > MAX_JSON_BODY_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        raw = body
    else:
        raise ValueError("Unsupported request body type")

    if not raw.strip():
        return {}, raw

    _precheck_json_structure(raw)
    data = json.loads(raw, parse_constant=_reject_json_constant)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """脱敏运行状态摘要（严禁暴露物理路径、主密钥、Webhook 密钥或系统机密表）。"""
    _ = (db_path, storage_dir)
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "status": "ok",
    }
