# -*- coding: utf-8 -*-
"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .config import GATEWAY_INTERNAL_BUILD
from .validation import check_json_depth_and_size


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


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
    check_json_depth_and_size(raw)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "build": GATEWAY_INTERNAL_BUILD,
    }
