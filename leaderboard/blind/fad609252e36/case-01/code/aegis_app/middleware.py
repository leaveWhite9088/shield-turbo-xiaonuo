# -*- coding: utf-8 -*-
"""网关请求载荷解析、JSON 深度预检、严格数值/布尔类型守卫与脱敏诊断中间件。"""
from __future__ import annotations

import json
import math
import re
import urllib.parse
from typing import Any

from . import __version__
from .config import INT64_MAX, INT64_MIN, MAX_JSON_BYTES, MAX_JSON_DEPTH

_INT_STR_RE = re.compile(r"^[+-]?\d+$")


def strict_int(
    val: Any,
    field_name: str = "value",
    *,
    min_val: int = INT64_MIN,
    max_val: int = INT64_MAX,
) -> int:
    """严格整数校验：拒绝 bool、float、NaN/Inf、非数字字符串及超出 64 位有符号整数边界的值。"""
    if isinstance(val, bool) or val is None:
        raise ValueError(f"Invalid integer for {field_name}: boolean or null is not allowed")
    if isinstance(val, int):
        res = val
    elif isinstance(val, str):
        s = val.strip()
        if not s or len(s) > 32 or not _INT_STR_RE.match(s):
            raise ValueError(f"Invalid integer format for {field_name}")
        res = int(s)
    else:
        raise ValueError(f"Invalid type for integer field {field_name}")
    if res < min_val or res > max_val:
        raise ValueError(f"Integer value for {field_name} out of allowed bounds [{min_val}, {max_val}]")
    return res


def strict_bool(val: Any, field_name: str = "value") -> bool:
    """严格布尔值校验：仅接受 bool 或整数 0/1。"""
    if isinstance(val, bool):
        return val
    if isinstance(val, int) and val in (0, 1):
        return bool(val)
    raise ValueError(f"Invalid boolean value for {field_name}")


def _reject_nonfinite_constant(val: str) -> Any:
    raise ValueError(f"Non-finite JSON number constant is not permitted: {val}")


def _precheck_json_depth(raw: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    """在调用 json.loads 之前对原始 JSON 字符串执行单遍括号嵌套深度预检。"""
    if raw.count("{") + raw.count("[") <= max_depth:
        return
    depth = 0
    in_str = False
    escape = False
    for ch in raw:
        if escape:
            escape = False
            continue
        if in_str:
            if ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                raise ValueError(f"JSON nesting depth exceeds maximum allowed ({max_depth})")
        elif ch == "}" or ch == "]":
            if depth > 0:
                depth -= 1


def _validate_object_tree(obj: Any, max_depth: int = MAX_JSON_DEPTH, _depth: int = 0) -> None:
    """校验内存字典/列表对象的嵌套深度与非有限浮点数（NaN/Inf）。"""
    if _depth > max_depth:
        raise ValueError(f"Payload object depth exceeds maximum allowed ({max_depth})")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("JSON object keys must be strings")
            _validate_object_tree(v, max_depth, _depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _validate_object_tree(item, max_depth, _depth + 1)
    elif isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("Non-finite float (NaN/Infinity) is not permitted")


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Request URL path is invalid or too long")
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _validate_object_tree(body, MAX_JSON_DEPTH, 1)
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_JSON_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        try:
            raw = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Request body must be valid UTF-8") from exc
    elif isinstance(body, str):
        if len(body.encode("utf-8")) > MAX_JSON_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        raw = body
    else:
        raise ValueError("Unsupported request body type")

    if not raw.strip():
        return {}, raw

    _precheck_json_depth(raw, MAX_JSON_DEPTH)
    data = json.loads(raw, parse_constant=_reject_nonfinite_constant)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    _validate_object_tree(data, MAX_JSON_DEPTH, 1)
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """返回脱敏后的网关状态信息（严禁暴露物理路径、主密钥、租户回调密钥或系统机密表）。"""
    _ = (db_path, storage_dir)
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "status": "ok",
    }
