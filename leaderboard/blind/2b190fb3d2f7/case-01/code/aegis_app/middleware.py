# -*- coding: utf-8 -*-
"""网关请求载荷安全解析（预检 JSON 嵌套深度、禁止 NaN/Inf）与脱敏元信息中间件。"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from . import __version__
from .runtime_state import (
    MAX_JSON_BYTES,
    check_object_depth_and_nodes,
    check_raw_json_depth,
)


def _reject_non_finite_constant(val: str) -> Any:
    raise ValueError(f"Non-finite JSON constant not allowed: {val}")


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
    return route, query_params


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        check_object_depth_and_nodes(body)
        try:
            raw = json.dumps(body, separators=(",", ":"), allow_nan=False)
        except ValueError as exc:
            raise ValueError("Invalid or non-finite values in JSON payload") from exc
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("Request payload exceeds maximum size limit")
        return body, raw
    if isinstance(body, bytes):
        if len(body) > MAX_JSON_BYTES:
            raise ValueError("Request payload exceeds maximum size limit")
        raw = body.decode("utf-8")
    else:
        raw = str(body)
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("Request payload exceeds maximum size limit")
    if not raw.strip():
        return {}, raw

    # 在 json.loads 之前线性预检嵌套深度，毫秒级阻断千层嵌套炸弹
    check_raw_json_depth(raw)
    data = json.loads(raw, parse_constant=_reject_non_finite_constant)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    check_object_depth_and_nodes(data)
    return data, raw


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """安全脱敏版状态摘要（严禁暴露物理路径、主密钥、租户秘钥或系统机密表）。"""
    _ = (db_path, storage_dir)
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "status": "ok",
    }
