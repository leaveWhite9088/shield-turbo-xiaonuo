# -*- coding: utf-8 -*-
"""有界 URL/JSON 解析、json.loads 前深度预检与脱敏诊断。"""
from __future__ import annotations

import json
import math
import urllib.parse
from typing import Any

from . import __version__
from .runtime import MAX_JSON_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Request target is invalid or too long")
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Absolute request targets are not accepted")
    route = parsed.path.rstrip("/") or "/"
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64))
    return route, query


def _preflight_json(raw: str) -> None:
    if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError("JSON payload exceeds the 1 MiB budget")
    depth = 0
    in_string = False
    escaped = False
    for char in raw:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds depth budget")
        elif char in "]}":
            depth = max(0, depth - 1)


def _validate_json_tree(root: Any) -> None:
    stack: list[tuple[Any, int]] = [(root, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("JSON structure exceeds complexity budget")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite JSON numbers are forbidden")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _validate_json_tree(body)
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
            raise ValueError("JSON payload exceeds the 1 MiB budget")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_JSON_BYTES:
            raise ValueError("JSON payload exceeds the 1 MiB budget")
        raw = body.decode("utf-8")
    elif isinstance(body, str):
        raw = body
    else:
        raise ValueError("Unsupported request body type")
    if not raw.strip():
        return {}, raw
    _preflight_json(raw)
    data = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    _validate_json_tree(data)
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    # 保留兼容函数，但任何调用方都拿不到路径、租户凭证或系统主密钥。
    return {"service": "aegis-gateway", "version": __version__, "status": "ok"}
