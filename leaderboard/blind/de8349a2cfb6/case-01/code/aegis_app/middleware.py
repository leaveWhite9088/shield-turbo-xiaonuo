# -*- coding: utf-8 -*-
"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .config import (
    GATEWAY_INTERNAL_BUILD,
    MASTER_SIGNING_PEPPER,
    MAX_JSON_NESTING_DEPTH,
    MAX_JSON_PAYLOAD_BYTES,
)
from .db import open_connection


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def _check_json_raw_nesting_depth(raw: str, max_depth: int = MAX_JSON_NESTING_DEPTH) -> None:
    depth = 0
    in_str = False
    esc = False
    for ch in raw:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in "{[":
                depth += 1
                if depth > max_depth:
                    raise ValueError(f"JSON nesting depth exceeds maximum allowed ({max_depth})")
            elif ch in "}]":
                if depth > 0:
                    depth -= 1


def _check_dict_depth(obj: Any, max_depth: int = MAX_JSON_NESTING_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        curr, d = stack.pop()
        if d > max_depth:
            raise ValueError(f"Object nesting depth exceeds maximum allowed ({max_depth})")
        if isinstance(curr, dict):
            for v in curr.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))
        elif isinstance(curr, list):
            for v in curr:
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _check_dict_depth(body)
        raw = json.dumps(body, separators=(",", ":"))
        if len(raw) > MAX_JSON_PAYLOAD_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_JSON_PAYLOAD_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
        raw = body.decode("utf-8")
    else:
        raw = str(body)
        if len(raw) > MAX_JSON_PAYLOAD_BYTES:
            raise ValueError("Request JSON payload exceeds size limit")
    if not raw.strip():
        return {}, raw
    _check_json_raw_nesting_depth(raw)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "status": "restricted",
    }
