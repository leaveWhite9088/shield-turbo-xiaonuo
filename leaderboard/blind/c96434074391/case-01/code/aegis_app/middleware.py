# -*- coding: utf-8 -*-
"""网关请求载荷解析、严格类型边界守卫、JSON 预检熔断与脱敏诊断中间件。"""
from __future__ import annotations

import json
import math
import re
import urllib.parse
from typing import Any

from . import __version__
from .config import (
    MAX_JSON_CONTAINER_NODES,
    MAX_JSON_DEPTH,
    MAX_REQUEST_BODY_BYTES,
    SQLITE_SAFE_INT_MAX,
)

_INT_STR_RE = re.compile(r"^[+-]?[0-9]{1,19}$")


def strict_int(
    val: Any,
    field_name: str = "value",
    *,
    min_val: int = -SQLITE_SAFE_INT_MAX,
    max_val: int = SQLITE_SAFE_INT_MAX,
    allow_str: bool = False,
) -> int:
    """严格整数校验：拦截 bool 子类混淆、float/NaN/Inf、畸形长数字串及超 64 位整数溢出。"""
    if isinstance(val, bool):
        raise ValueError(f"Boolean value is not allowed for integer field '{field_name}'")
    if isinstance(val, int):
        iv = val
    elif allow_str and isinstance(val, str):
        s = val.strip()
        if not _INT_STR_RE.match(s):
            raise ValueError(f"Malformed integer string for field '{field_name}'")
        iv = int(s)
    else:
        raise ValueError(f"Invalid integer type for field '{field_name}'")

    if iv < min_val or iv > max_val:
        raise ValueError(f"Integer out of bounds for field '{field_name}'")
    return iv


def strict_bool(val: Any, field_name: str = "flag") -> bool:
    """严格布尔类型校验：拒绝非布尔对象伪装成真值。"""
    if not isinstance(val, bool):
        raise ValueError(f"Field '{field_name}' must be a boolean")
    return val


def strict_finite_number(val: Any, field_name: str = "number") -> float:
    """严格有限实数校验：拒绝 bool、NaN、Infinity 与超大溢出数值。"""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"Field '{field_name}' must be a finite number")
    fv = float(val)
    if not math.isfinite(fv):
        raise ValueError(f"Non-finite number (NaN/Inf) not allowed in '{field_name}'")
    return fv


def _reject_non_finite_json_constant(token: str) -> Any:
    raise ValueError(f"Non-standard JSON numeric constant rejected: {token}")


def precheck_json_depth(raw: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    """在调用 json.loads 之前执行词法级括号深度预检，毫秒级阻断千层嵌套栈溢出炸弹。"""
    if len(raw) > MAX_REQUEST_BODY_BYTES:
        raise ValueError("Request JSON payload exceeds maximum byte budget")

    # 快速通道：左括号总数不超过上限时，嵌套深度在数学上不可能超限
    if raw.count("{") + raw.count("[") <= max_depth:
        return

    depth = 0
    in_string = False
    escaped = False
    container_count = 0

    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{" or ch == "[":
                depth += 1
                if depth > max_depth:
                    raise ValueError(f"JSON nesting depth exceeds limit ({max_depth})")
                container_count += 1
                if container_count > MAX_JSON_CONTAINER_NODES:
                    raise ValueError("JSON container complexity exceeds budget")
            elif ch == "}" or ch == "]":
                depth -= 1
                if depth < 0:
                    raise ValueError("Malformed JSON bracket sequence")


def _validate_in_memory_structure(obj: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    """迭代式校验进程内直接传入的 dict/list 结构深度、节点数与数值有限性。"""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    containers = 0
    while stack:
        curr, depth = stack.pop()
        if isinstance(curr, dict):
            if depth > max_depth:
                raise ValueError(f"Payload nesting depth exceeds limit ({max_depth})")
            containers += 1
            if containers > MAX_JSON_CONTAINER_NODES:
                raise ValueError("Payload container complexity exceeds budget")
            for k, v in curr.items():
                if not isinstance(k, str):
                    raise ValueError("JSON object keys must be strings")
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
                elif isinstance(v, float) and not math.isfinite(v):
                    raise ValueError("Non-finite float not allowed in payload")
                elif isinstance(v, int) and not isinstance(v, bool):
                    if v < -SQLITE_SAFE_INT_MAX or v > SQLITE_SAFE_INT_MAX:
                        raise ValueError("Integer exceeds safe 64-bit bounds")
        elif isinstance(curr, list):
            if depth > max_depth:
                raise ValueError(f"Payload nesting depth exceeds limit ({max_depth})")
            containers += 1
            if containers > MAX_JSON_CONTAINER_NODES:
                raise ValueError("Payload container complexity exceeds budget")
            for item in curr:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))
                elif isinstance(item, float) and not math.isfinite(item):
                    raise ValueError("Non-finite float not allowed in payload")
                elif isinstance(item, int) and not isinstance(item, bool):
                    if item < -SQLITE_SAFE_INT_MAX or item > SQLITE_SAFE_INT_MAX:
                        raise ValueError("Integer exceeds safe 64-bit bounds")


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Invalid request URI")
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _validate_in_memory_structure(body, MAX_JSON_DEPTH)
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_REQUEST_BODY_BYTES:
            raise ValueError("Request JSON payload exceeds maximum byte budget")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_REQUEST_BODY_BYTES:
            raise ValueError("Request body exceeds maximum byte budget")
        try:
            raw = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Request body must be valid UTF-8") from exc
    elif isinstance(body, str):
        if len(body.encode("utf-8")) > MAX_REQUEST_BODY_BYTES:
            raise ValueError("Request body exceeds maximum byte budget")
        raw = body
    else:
        raise ValueError("Unsupported request body type")

    if not raw.strip():
        return {}, raw

    precheck_json_depth(raw, MAX_JSON_DEPTH)
    data = json.loads(raw, parse_constant=_reject_non_finite_json_constant)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    _validate_in_memory_structure(data, MAX_JSON_DEPTH)
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """脱敏诊断摘要（严禁暴露物理路径、主签名密钥、Webhook Secret 或系统机密表）。"""
    del db_path, storage_dir
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "status": "ok",
    }
