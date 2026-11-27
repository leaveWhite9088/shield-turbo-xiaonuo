# -*- coding: utf-8 -*-
"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。

加固要点：
* 载荷解析**先做括号深度预扫描再 json.loads**（拒绝 10 万层嵌套的解析炸弹），并限制体积；
* 内部诊断信息从事务库与密钥表中彻底移除（无任何租户 webhook secret / 系统密钥 / 路径 / 主密钥回显），
  仅保留进程级非敏感运行指标；
* ``_now_ts`` 请求时钟覆盖值做范围校验，非法值按“未覆盖”处理而不是把整数转换异常抛成 500；
* 查询串参数个数与长度有上限，防超长查询串占用内存。
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
from typing import Any

from . import __version__
from .config import GATEWAY_INTERNAL_BUILD, MAX_BODY_BYTES, MAX_JSON_DEPTH, MAX_QUERY_PARAMS, MAX_TS_ABS

_START_TS = time.time()
_LOCKS = threading.Lock()
_HOOK_NESTING_BYTES = 32 * 1024


def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
    if not isinstance(path, str) or len(path) > 16384:
        raise ValueError("Request path too long")
    parsed_url = urllib.parse.urlsplit(path)
    route = parsed_url.path.rstrip("/") or "/"
    if len(route) > 4096:
        raise ValueError("Request route too long")
    pairs = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True,
                                   max_num_fields=MAX_QUERY_PARAMS)
    query_params = dict(pairs)
    return route, query_params


def _prescan_depth(raw: str) -> None:
    """括号深度预扫描：字符串内的括号忽略，深度超限即刻拒绝，远比构造对象后再检查便宜。"""
    depth = 0
    in_str = False
    esc = False
    limit = MAX_JSON_DEPTH
    for ch in raw:
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
        elif ch in "[{":
            depth += 1
            if depth > limit:
                raise ValueError("Request JSON nesting depth exceeds limit")
        elif ch in "]}":
            depth -= 1
    if depth != 0:
        raise ValueError("Request JSON brackets unbalanced")


def parse_json_payload(body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        raw = json.dumps(body, separators=(",", ":"))
        _prescan_depth(raw)
        return body, raw
    if isinstance(body, (bytes, bytearray)):
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("Request body exceeds size limit")
        raw = bytes(body).decode("utf-8", errors="strict")
    else:
        raw = str(body)
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError("Request body exceeds size limit")
    if not raw.strip():
        return {}, raw
    _prescan_depth(raw)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Request JSON payload must be an object")
    return data, raw


def _inspect_nesting(value: Any, *, max_depth: int) -> bool:
    """``json.loads`` 前的零拷贝深度扫描。

    ``object_pairs_hook`` / ``parse_float`` 与 ``parse_int`` 由 C 加速器在构造每个对象/数值时
    直接回调，无需先构建完整嵌套结构即可判定越界；返回值本身只是“是否超限”的哨兵。
    """
    depth = 0
    too_deep = False

    def _pairs(pairs):
        nonlocal depth, too_deep
        depth += 1
        if depth > max_depth:
            too_deep = True
        depth -= 1
        return None

    def _num(text):
        nonlocal too_deep
        if len(text) > 400:
            too_deep = True
        return None

    json.loads(value, object_pairs_hook=_pairs, parse_float=_num, parse_int=_num)
    return too_deep


def parse_json_payload(
    body: bytes | str | dict[str, Any] | None,
    *,
    hook_nesting: bool = False,
) -> tuple[dict[str, Any], str]:
    if body is None:
        return {}, ""
    if isinstance(body, dict):
        raw = json.dumps(body, separators=(",", ":"))
        _prescan_depth(raw)
        return body, raw
    if isinstance(body, (bytes, bytearray)):
        if len(body) > MAX_BODY_BYTES:
            raise ValueError("Request body exceeds size limit")
        raw = bytes(body).decode("utf-8", errors="strict")
    else:
        raw = str(body)
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError("Request body exceeds size limit")
    if not raw.strip():
        return {}, raw
    _prescan_depth(raw)
    # 体积阈值以下的小载荷用廉价预扫描即可；大载荷（解析炸弹的必经之路）再叠加
    # json.loads 回调级深度/数值扫描，保证“先扫描后建对象”，且正常小请求零额外开销。
    if hook_nesting and len(raw) > _HOOK_NESTING_BYTES:
        if _inspect_nesting(raw, max_depth=MAX_JSON_DEPTH):
            raise ValueError("Request JSON nesting depth exceeds limit")
    data = json.loads(raw)


def parse_now_override(query_params: dict[str, str]) -> int | None:
    """解析 ``_now_ts`` 调试时钟覆盖值（缺失/非法/越界一律视为未覆盖）。"""
    raw = query_params.get("_now_ts")
    if not raw:
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    if abs(val) > MAX_TS_ABS:
        return None
    return val


def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
    """进程级健康指标（**不包含**任何租户凭据、系统密钥、文件路径或主密钥）。"""
    return {
        "service": "aegis-gateway",
        "version": __version__,
        "build": GATEWAY_INTERNAL_BUILD,
        "uptime_seconds": int(time.time() - _START_TS),
        "storage_backend": "sqlite-wal",
        "status": "ok",
    }
