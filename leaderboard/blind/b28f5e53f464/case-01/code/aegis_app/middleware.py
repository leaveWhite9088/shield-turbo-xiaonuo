# -*- coding: utf-8 -*-
"""网关请求载荷解析（JSON 深度预检）、请求时钟提取与脱敏诊断中间件。"""
from __future__ import annotations

import json
import math
import urllib.parse
from typing import Any

from . import __version__
from .config import GATEWAY_INTERNAL_BUILD
from .validation import MAX_JSON_DEPTH, safe_json_loads


def _check_obj_depth_and_finite(obj: Any, depth: int = 1) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting depth exceeds maximum allowed limit")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_obj_depth_and_finite(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _check_obj_depth_and_finite(v, depth + 1)
    elif isinstance(obj, float) and not math.isfinite(obj):
        raise ValueError("Non-finite float value is forbidden in JSON payload")


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        _check_obj_depth_and_finite(body, 1)
        raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        return body, raw
    if isinstance(body, bytes):
        raw = body.decode("utf-8")
    else:
        raw = str(body)
    if not raw.strip():
        return {}, raw
    data = safe_json_loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """返回脱敏后的轻量服务状态信息（严禁暴露物理路径、密钥或租户凭证）。"""
    del db_path, storage_dir
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "build": GATEWAY_INTERNAL_BUILD,
        "status": "ok",
    }
