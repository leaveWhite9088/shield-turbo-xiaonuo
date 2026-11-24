# -*- coding: utf-8 -*-
"""安全请求解析中间件：O(N) 词法深度预检防千层 JSON 栈溢出、非有限浮点常量拦截与原始查询编码检查。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from .config import MAX_BODY_BYTES, MAX_JSON_NESTING_DEPTH


def _reject_non_finite_constant(token: str) -> Any:
    raise ValueError(f"Non-finite JSON number constant rejected: {token}")


def check_json_nesting_depth(raw_text: str, max_depth: int = MAX_JSON_NESTING_DEPTH) -> None:
    depth = 0
    in_str = False
    esc = False
    for ch in raw_text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in ("{", "["):
            depth += 1
            if depth > max_depth:
                raise ValueError(f"JSON nesting depth exceeds maximum {max_depth}")
        elif ch in ("}", "]"):
            depth = max(0, depth - 1)


def parse_url_and_query(path: str) -> tuple[str, dict[str, str], dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    raw_query_map: dict[str, str] = {}
    if parsed_url.query:
        for seg in parsed_url.query.split("&"):
            if "=" in seg:
                rk, rv = seg.split("=", 1)
                raw_query_map[urllib.parse.unquote_plus(rk)] = rv
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params, raw_query_map


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError("Payload size exceeds gateway limit")
        check_json_nesting_depth(raw)
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("Payload size exceeds gateway limit")
        raw = body.decode("utf-8")
    else:
        raw = str(body)
        if len(raw.encode("utf-8")) > MAX_BODY_BYTES:
            raise ValueError("Payload size exceeds gateway limit")
    if not raw.strip():
        return {}, raw
    check_json_nesting_depth(raw)
    data = json.loads(raw, parse_constant=_reject_non_finite_constant)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw
