# -*- coding: utf-8 -*-
"""请求解析中间件（5级平庸样本：未限制请求体积与 JSON 嵌套层数，未拦截 NaN/Infinity）。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any


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
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw
