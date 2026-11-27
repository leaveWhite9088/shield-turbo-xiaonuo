# -*- coding: utf-8 -*-
"""网关请求载荷解析、严格类型边界守卫与抗复杂度炸弹 JSON 预检中间件。"""
from __future__ import annotations

import json
import math
import re
import urllib.parse
from typing import Any

from . import __version__

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1

MAX_PAYLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000
MAX_QUERY_PARAM_LEN = 2048

_STRICT_INT_STR_RE = re.compile(r"^[+-]?[0-9]{1,20}$")


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Request path too long or invalid")
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    for k, v in query_params.items():
        if len(k) > 128 or len(v) > MAX_QUERY_PARAM_LEN:
            raise ValueError("Query parameter exceeds length limit")
    return route, query_params


def parse_strict_int(
    value: Any,
    field_name: str,
    *,
    default: int | None = None,
    min_val: int | None = None,
    max_val: int | None = None,
    allow_str: bool = False,
) -> int:
    """严格校验 64 位有符号整数，明确拒绝 bool、float、NaN、Inf 与超 64 位大整数。"""
    if value is None:
        if default is not None:
            return default
        raise ValueError(f"{field_name} is required and must be an integer")

    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not boolean")

    if isinstance(value, int):
        num = value
    elif allow_str and isinstance(value, str):
        s = value.strip()
        if not s:
            if default is not None:
                return default
            raise ValueError(f"{field_name} must be a valid integer")
        if not _STRICT_INT_STR_RE.match(s):
            raise ValueError(f"{field_name} must be a valid integer")
        num = int(s)
    else:
        raise ValueError(f"{field_name} must be an integer")

    if num < INT64_MIN or num > INT64_MAX:
        raise ValueError(f"{field_name} exceeds 64-bit signed integer bounds")
    if min_val is not None and num < min_val:
        raise ValueError(f"{field_name} must be >= {min_val}")
    if max_val is not None and num > max_val:
        raise ValueError(f"{field_name} must be <= {max_val}")
    return num


def parse_strict_bool(value: Any, field_name: str, *, default: bool | None = None) -> bool:
    """严格校验布尔值，防止字符串 'false' 等被隐式转为 True。"""
    if value is None:
        if default is not None:
            return default
        raise ValueError(f"{field_name} must be a boolean")
    if isinstance(value, bool):
        return value
    raise ValueError(f"{field_name} must be a boolean")


def parse_strict_finite_number(value: Any, field_name: str) -> float:
    """严格校验有限实数（拒绝 bool、NaN、Infinity）。"""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be numeric, not boolean")
    if isinstance(value, int):
        if value < INT64_MIN or value > INT64_MAX:
            raise ValueError(f"{field_name} exceeds 64-bit integer bounds")
        return float(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field_name} must be finite")
        return value
    raise ValueError(f"{field_name} must be a finite number")


def _precheck_json_depth(raw: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    """在调用 json.loads 之前以 O(N) 线性状态机预检 JSON 嵌套深度，毫秒级拦截千层嵌套炸弹。"""
    depth = 0
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
                raise ValueError(f"JSON nesting depth exceeds maximum allowed ({max_depth})")
        elif ch == "}" or ch == "]":
            depth -= 1
            if depth < 0:
                raise ValueError("Malformed JSON structure")


def _check_object_budget(
    obj: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
) -> None:
    """对内存中的 dict/list 载荷做迭代栈深度、节点总量及 NaN/Inf/超 64 位整数检查。"""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    seen_containers = 0
    while stack:
        curr, depth = stack.pop()
        seen_containers += 1
        if seen_containers > max_nodes:
            raise ValueError("JSON payload exceeds maximum complexity budget")
        if depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum allowed ({max_depth})")
        if isinstance(curr, dict):
            for k, v in curr.items():
                if not isinstance(k, str):
                    raise ValueError("JSON object keys must be strings")
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
                elif isinstance(v, float) and not math.isfinite(v):
                    raise ValueError("Non-finite floating point value is not allowed")
        elif isinstance(curr, list):
            for item in curr:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))
                elif isinstance(item, float) and not math.isfinite(item):
                    raise ValueError("Non-finite floating point value is not allowed")


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"Unsupported JSON numeric constant: {token}")


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _check_object_budget(body)
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("Request payload exceeds maximum size limit")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_PAYLOAD_BYTES:
            raise ValueError("Request payload exceeds maximum size limit")
        raw = body.decode("utf-8")
    elif isinstance(body, str):
        if len(body.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("Request payload exceeds maximum size limit")
        raw = body
    else:
        raise ValueError("Unsupported request body type")

    if not raw.strip():
        return {}, raw

    _precheck_json_depth(raw, max_depth=MAX_JSON_DEPTH)
    data = json.loads(raw, parse_constant=_reject_json_constant)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    _check_object_budget(data)
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """脱敏诊断占位接口：绝不暴露物理路径、租户密钥或系统主密钥。"""
    _ = (db_path, storage_dir)
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "status": "ok",
    }
