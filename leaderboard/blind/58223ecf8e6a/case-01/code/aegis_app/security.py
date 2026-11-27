# -*- coding: utf-8 -*-
"""共享的严格输入校验、低开销 JSON 预检与安全正则护栏。"""
from __future__ import annotations

import json
import math
import re
import threading
from typing import Any

MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_STRING = 262_144
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
_INTEGER_RE = re.compile(r"[+-]?[0-9]+\Z", re.ASCII)
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)


def strict_int(
    value: Any,
    name: str,
    *,
    minimum: int = INT64_MIN,
    maximum: int = INT64_MAX,
) -> int:
    """接受 JSON 整数或十进制整数字符串，拒绝 bool、float、NaN 与 64 位溢出。"""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and len(value) <= 32 and _INTEGER_RE.fullmatch(value.strip()):
        result = int(value.strip(), 10)
    else:
        raise ValueError(f"{name} must be an integer")
    if result < minimum or result > maximum:
        raise ValueError(f"{name} is outside the signed 64-bit range")
    return result


def strict_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    raise ValueError(f"{name} must be a boolean")


def bounded_text(
    value: Any,
    name: str,
    *,
    max_length: int = 256,
    allow_empty: bool = False,
    strip: bool = True,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    text = value.strip() if strip else value
    if (not allow_empty and not text) or len(text) > max_length or "\x00" in text:
        raise ValueError(f"{name} has invalid length or content")
    return text


def safe_identifier(value: Any, name: str, *, max_length: int = 128) -> str:
    text = bounded_text(value, name, max_length=max_length)
    if len(text) > 128 or not _SAFE_NAME_RE.fullmatch(text):
        raise ValueError(f"{name} contains unsupported characters")
    return text


def preflight_json_text(raw: str, *, max_bytes: int = MAX_JSON_BYTES) -> None:
    """在 json.loads 前限制体积和字符串感知的容器深度，避免畸形嵌套先耗尽栈。"""
    if len(raw.encode("utf-8")) > max_bytes:
        raise ValueError("JSON payload exceeds size budget")
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
                raise ValueError("JSON payload exceeds nesting budget")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                # 交给 JSON 解析器产生标准语法错误。
                return
    if depth != 0 or in_string:
        raise ValueError("Malformed or unterminated JSON payload")


def validate_json_value(value: Any, *, max_depth: int = MAX_JSON_DEPTH, max_nodes: int = 20_000) -> None:
    """校验直接传入的字典以及 json.loads 的结果；迭代实现，无递归耗尽。"""
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > max_nodes or depth > max_depth:
            raise ValueError("JSON value exceeds complexity budget")
        if item is None or isinstance(item, (bool, str, int)):
            if isinstance(item, str) and len(item) > MAX_STRING:
                raise ValueError("JSON string exceeds size budget")
            if isinstance(item, int) and not isinstance(item, bool) and not INT64_MIN <= item <= INT64_MAX:
                raise ValueError("JSON integer exceeds signed 64-bit range")
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("Non-finite JSON number is not allowed")
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
            continue
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise ValueError("Invalid JSON object key")
                stack.append((child, depth + 1))
            continue
        raise ValueError("Payload contains a non-JSON value")


def parse_json_bytes(raw: bytes | str) -> Any:
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    preflight_json_text(text)
    def reject_constant(token: str) -> None:
        raise ValueError(f"Non-finite JSON number is not allowed: {token}")
    value = json.loads(text, parse_constant=reject_constant)
    validate_json_value(value)
    return value


def finite_number(value: Any, name: str = "number") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{name} must be numeric")
    if isinstance(value, str) and len(value) > 64:
        raise ValueError(f"{name} is too long")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


def validate_contact_email(email: Any) -> bool:
    """与原格式等价的分段线性校验，不使用嵌套量词回溯正则。"""
    if not isinstance(email, str) or not email or len(email) > 254 or email.isascii() is False:
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return False
    segment: list[str] = []
    separated = False
    for char in local:
        if char.isascii() and char.isalnum():
            segment.append(char)
            separated = False
        elif char in "._-" and segment and not separated:
            separated = True
            segment.clear()
        else:
            return False
    if not segment or separated:
        return False
    for label in domain.split("."):
        if not label or any(not (c.isascii() and (c.isalnum() or c == "-")) for c in label):
            return False
    return True


_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}
_PATTERN_CACHE_LIMIT = 64
_PATTERN_CACHE_LOCK = threading.RLock()


def _validate_regex_ast(pattern: str) -> None:
    """拒绝嵌套/大量词重复、反向引用与可指数回溯的重复分支。"""
    try:
        parsed = re._parser.parse(pattern, 0)  # type: ignore[attr-defined]  # Python 标准库内部 AST
    except (re.error, RecursionError) as exc:
        raise ValueError("Invalid regular expression") from exc

    def contains_op(tokens: Any, wanted: Any) -> bool:
        for child_op, child_arg in tokens:
            if child_op is wanted:
                return True
            if child_op is re._parser.SUBPATTERN and contains_op(child_arg[-1], wanted):  # type: ignore[attr-defined]
                return True
            if child_op is re._parser.BRANCH and any(contains_op(branch, wanted) for branch in child_arg[1]):  # type: ignore[attr-defined]
                return True
            if child_op in (re._parser.MIN_REPEAT, re._parser.MAX_REPEAT, re._parser.POSSESSIVE_REPEAT):  # type: ignore[attr-defined]
                if contains_op(child_arg[2], wanted):
                    return True
        return False

    def walk(tokens: Any, inside_repeat: bool = False) -> None:
        for op, arg in tokens:
            if op in (re._parser.GROUPREF, re._parser.GROUPREF_EXISTS):  # type: ignore[attr-defined]
                raise ValueError("Regular expression backreferences are disabled")
            if op in (re._parser.MIN_REPEAT, re._parser.MAX_REPEAT, re._parser.POSSESSIVE_REPEAT):  # type: ignore[attr-defined]
                low, high, child = arg
                if high != re._parser.MAXREPEAT and high > 1000:  # type: ignore[attr-defined]
                    raise ValueError("Regular expression repeat bound is too large")
                if inside_repeat:
                    raise ValueError("Nested regular expression repeats are disabled")
                if contains_op(child, re._parser.BRANCH):  # type: ignore[attr-defined]
                    raise ValueError("Repeated alternation is disabled")
                walk(child, True)
            elif op is re._parser.SUBPATTERN:  # type: ignore[attr-defined]
                walk(arg[-1], inside_repeat)
            elif op is re._parser.BRANCH:  # type: ignore[attr-defined]
                for branch in arg[1]:
                    walk(branch, inside_repeat)
            elif op in (re._parser.ASSERT, re._parser.ASSERT_NOT):  # type: ignore[attr-defined]
                walk(arg[1], inside_repeat)

    walk(parsed)


def safe_regex_search(pattern: Any, actual: Any) -> bool:
    if not isinstance(pattern, str) or not isinstance(actual, str):
        return False
    if len(pattern) > 256 or len(actual) > 4096:
        raise ValueError("Regular expression input exceeds budget")
    with _PATTERN_CACHE_LOCK:
        compiled = _PATTERN_CACHE.get(pattern)
        if compiled is None:
            _validate_regex_ast(pattern)
            try:
                compiled = re.compile(pattern)
            except (re.error, RecursionError) as exc:
                raise ValueError("Invalid regular expression") from exc
            if len(_PATTERN_CACHE) >= _PATTERN_CACHE_LIMIT:
                _PATTERN_CACHE.pop(next(iter(_PATTERN_CACHE)))
            _PATTERN_CACHE[pattern] = compiled
    try:
        return compiled.search(actual) is not None
    except RecursionError as exc:
        raise ValueError("Regular expression evaluation budget exceeded") from exc
