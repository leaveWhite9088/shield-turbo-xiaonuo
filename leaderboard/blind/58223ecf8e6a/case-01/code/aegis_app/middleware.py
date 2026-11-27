# -*- coding: utf-8 -*-
"""有界 URL/JSON 请求解析与脱敏运行信息。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .config import GATEWAY_INTERNAL_BUILD
from .security import MAX_JSON_BYTES, parse_json_bytes, preflight_json_text, validate_json_value


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Request path exceeds size budget")
    parsed = urllib.parse.urlsplit(path)
    route = parsed.path.rstrip("/") or "/"
    pairs = urllib.parse.parse_qsl(
        parsed.query, keep_blank_values=True, max_num_fields=64, strict_parsing=False,
    )
    return route, dict(pairs)


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        validate_json_value(body)
        raw = json.dumps(body, allow_nan=False, separators=(",", ":"))
        if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
            raise ValueError("JSON payload exceeds size budget")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_JSON_BYTES:
            raise ValueError("JSON payload exceeds size budget")
        raw = body.decode("utf-8")
    elif isinstance(body, str):
        raw = body
    else:
        raise ValueError("Request body must be JSON bytes, text, or object")
    if not raw.strip():
        return {}, raw
    preflight_json_text(raw)
    data = parse_json_bytes(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """保留内部函数签名，但永不汇总凭证、物理路径或系统密钥。"""
    del db_path, storage_dir
    return {"service": "aegis-gateway", "version": __version__, "build": GATEWAY_INTERNAL_BUILD}
