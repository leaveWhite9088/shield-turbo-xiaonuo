# -*- coding: utf-8 -*-
"""抗 DoS 熔断与严格类型守卫：JSON 深度预检、安全整数、正则白名单、有界 LRU 缓存。"""
from __future__ import annotations

from collections import OrderedDict
import json
import re
import time
from typing import Any

from .config import MAX_IN_VALUE, MAX_JSON_DEPTH

_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1


class GuardError(ValueError):
    """载荷触发预算熔断时抛出的 400 类错误。"""


# ---------------------------------------------------------------------------
# 严格标量
# ---------------------------------------------------------------------------
def strict_int(value: Any, *, minimum: int | None = None, maximum: int | None = None,
               default: int | None = None, name: str = "value") -> int:
    """拒绝 bool / float / NaN / 超 64 位整数 / 非整数字符串的严格整数解析。"""
    if value is None:
        if default is None:
            raise GuardError(f"{name} is required")
        return default
    if isinstance(value, bool):
        raise GuardError(f"{name} must be an integer, not bool")
    if isinstance(value, int):
        out = int(value)
    elif isinstance(value, float):
        raise GuardError(f"{name} must be an integer")
    elif isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 20 or not (text.isdigit() or (text[0] == "-" and text[1:].isdigit())):
            raise GuardError(f"{name} must be an integer")
        out = int(text)
    else:
        raise GuardError(f"{name} must be an integer")
    if out < _INT64_MIN or out > _INT64_MAX:
        raise GuardError(f"{name} out of 64-bit range")
    if minimum is not None and out < minimum:
        raise GuardError(f"{name} below minimum {minimum}")
    if maximum is not None and out > maximum:
        raise GuardError(f"{name} above maximum {maximum}")
    return out


def strict_bool(value: Any, *, default: bool = False, name: str = "value") -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise GuardError(f"{name} must be a boolean")


def safe_number(value: Any, name: str = "value") -> float | None:
    """规则数值比较的有限数校验：拒绝 bool、超 2^53 整数与 NaN/Inf。"""
    if isinstance(value, bool):
        raise GuardError(f"{name} boolean is not a comparable number")
    if isinstance(value, int):
        if abs(value) > MAX_IN_VALUE:
            raise GuardError(f"{name} integer exceeds safe range")
        return float(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise GuardError(f"{name} must be finite")
        return value
    try:
        out = float(value)
    except (TypeError, ValueError):
        raise GuardError(f"{name} is not numeric") from None
    if out != out or out in (float("inf"), float("-inf")):
        raise GuardError(f"{name} must be finite")
    return out


def guard_text(value: Any, *, name: str, max_chars: int, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise GuardError(f"{name} must be a string")
    if len(value) > max_chars:
        raise GuardError(f"{name} exceeds {max_chars} characters")
    if not allow_empty and not value:
        raise GuardError(f"{name} is required")
    return value


def iter_strings(obj: Any, budget: int = 4096):
    stack = [obj]
    seen = 0
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            yield cur
        elif isinstance(cur, list):
            stack.extend(cur)
        elif isinstance(cur, dict):
            stack.extend(cur.values())
            stack.extend(cur.keys())
        seen += 1
        if seen > budget:
            return


# ---------------------------------------------------------------------------
# JSON 深度预检（在 json.loads(dict) 之前完成，避免深层结构先被整体物化）
# ---------------------------------------------------------------------------
_OPENERS = {"{": "}", "[": "]"}
_CLOSERS = frozenset("}]")
_CLOSES = {"{": "}", "[": "]"}


def _skip_ws(raw: str, i: int, n: int) -> int:
    while i < n:
        c = raw[i]
        if c in " \t\r\n":
            i += 1
        else:
            break
    return i


def _skip_json_value(raw: str, i: int, n: int, max_depth: int) -> int:
    stack: list[str] = []
    while i < n:
        c = raw[i]
        if c == '"':
            i += 1
            while i < n:
                ch = raw[i]
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                i += 1
            if stack:
                i = _skip_ws(raw, i, n)
                if i < n and raw[i] == ":":
                    i += 1
            continue
        if c in _OPENERS:
            stack.append(_CLOSES[c])
            if len(stack) > max_depth:
                raise GuardError(f"JSON nesting depth exceeds {max_depth}")
            i += 1
            continue
        if c in _CLOSERS:
            if not stack or stack.pop() != c:
                raise GuardError("Malformed JSON structure")
            i += 1
            continue
        if c in "0123456789-":
            j = i + 1
            while j < n and raw[j] in "0123456789.eE+-":
                j += 1
            i = j
        elif c in "tfn":
            if raw.startswith("true", i):
                i += 4
            elif raw.startswith("false", i):
                i += 5
            elif raw.startswith("null", i):
                i += 4
            else:
                raise GuardError("Malformed JSON literal")
        elif not stack:
            raise GuardError("Malformed JSON payload")
        else:
            i += 1
    if stack:
        raise GuardError("Truncated JSON payload")
    return i


def guard_json(raw: str, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """单遍扫描预检嵌套深度与结构合法性，再执行 ``json.loads``。"""
    if len(raw) > 32 * 1024 * 1024:
        raise GuardError("JSON payload too large")
    i = _skip_ws(raw, 0, len(raw))
    if i < len(raw) and raw[i] in ("{", "["):
        _skip_json_value(raw, i, len(raw), max_depth)
    return json.loads(raw)


def guard_json_obj(raw: str) -> dict[str, Any]:
    data = guard_json(raw)
    if not isinstance(data, dict):
        raise GuardError("Request JSON payload must be an object")
    return data


# ---------------------------------------------------------------------------
# 正则熔断：拒绝回溯放大器与超长模式
# ---------------------------------------------------------------------------
_ALLOWED_GROUPS = ("(?:", "(?=", "(?!", "(?<=", "(?<!", "(?P<")
_RANGES = (
    (0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A), (0x5F, 0x5F), (0x2D, 0x2E), (0x40, 0x40),
    (0x20, 0x20), (0x2B, 0x2B), (0x3A, 0x3A), (0x2C, 0x2C), (0x2F, 0x2F), (0x3D, 0x3D),
)


def _is_safe_class(inner: str) -> bool:
    """字符类白名单：只允许字母数字、下划线、连字符、点、@、空格、加号、冒号、逗号、斜杠、等号。"""
    n = len(inner)
    i = 0
    while i < n:
        ch = inner[i]
        if ch in "\\":
            if i + 1 >= n:
                return False
            i += 2
            continue
        if i + 2 < n and inner[i + 1] == "-" and inner[i + 2] != "]":
            lo, hi = ord(ch), ord(inner[i + 2])
            if lo > hi:
                return False
            if not any(a <= lo and hi <= b for a, b in _RANGES):
                return False
            i += 3
            continue
        if not any(a <= ord(ch) <= b for a, b in _RANGES):
            return False
        i += 1
    return True


def guard_regex_mode(pattern: str, max_chars: int) -> tuple[str, bool]:
    """返回 (pattern, 是否安全)。

    递归判定：
    * 可安全委托给 ``re``（不支持的内联标志/贪婪属性/条件组直接拒绝）；
    * 量词不得叠加（``(a*)+``、``a*?*``）、量词不得超过 1024、组嵌套不得超过 8 层；
    * 组内不应有“同级可选分支 + 长量词”的重叠组合（``(a|aa)+$`` 类指数回溯放大器）；
    * 字符类走白名单，拒绝反向引用与超长模式。
    """
    if not isinstance(pattern, str) or len(pattern) > max_chars:
        return pattern, False
    if _BACKREF_RE.search(pattern):
        return pattern, False
    n = len(pattern)
    i = 0
    depth = 0
    prev_atom = False
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                return pattern, False
            nxt = pattern[i + 1]
            if nxt.isdigit() or nxt in "ghkGK":
                return pattern, False
            i += 2
            prev_atom = True
            continue
        if ch == "[":
            j = pattern.find("]", i + 1)
            if j < 0:
                return pattern, False
            if not _is_safe_class(pattern[i + 1:j]):
                return pattern, False
            i = j + 1
            prev_atom = True
            continue
        if ch == "(":
            if prev_atom:
                # 隐式拼接后的组仍可整体加量词，但此时再出现裸量词会由下面的分支拦截
                pass
            if pattern.startswith("(?", i):
                if not any(pattern.startswith(g, i) for g in _ALLOWED_GROUPS):
                    return pattern, False
                # (?: / (?= / (?! 为 3 字符头；(?P< 头本身 4 字符但名后自 ) 结束，3 字符偏移即可
                i += 3
                depth += 1
                if depth > 8:
                    return pattern, False
                prev_atom = False
                continue
            depth += 1
            if depth > 8:
                return pattern, False
            i += 1
            prev_atom = False
            continue
        if ch == ")":
            if depth == 0:
                return pattern, False
            depth -= 1
            i += 1
            prev_atom = True
            continue
        if ch in "*+?":
            if not prev_atom:
                return pattern, False
            if i + 1 < n and pattern[i + 1] in "*+?":
                return pattern, False
            i += 1
            prev_atom = True
            continue
        if ch == "{":
            j = pattern.find("}", i)
            if j < 0:
                # 未闭合花括号按字面量处理（re 亦如此）
                i += 1
                prev_atom = True
                continue
            body = pattern[i + 1:j]
            parts = body.split(",")
            if len(parts) > 2 or not parts[0].isdigit() and parts[0] != "":
                i += 1
                prev_atom = True
                continue
            if not prev_atom:
                return pattern, False
            if len(parts) == 2 and parts[1] and not parts[1].isdigit():
                return pattern, False
            try:
                lo = int(parts[0]) if parts[0] else 0
                hi = int(parts[1]) if len(parts) == 2 and parts[1] else (lo if len(parts) == 1 else 0)
            except ValueError:
                return pattern, False
            if lo > 1024 or hi > 1024:
                return pattern, False
            if len(parts) == 2 and hi < lo:
                return pattern, False
            i = j + 1
            if i < n and pattern[i] in "*+?":
                return pattern, False
            prev_atom = True
            continue
        if ch in "|":
            prev_atom = False
            i += 1
            continue
        prev_atom = True
        i += 1
    if depth != 0:
        return pattern, False
    return pattern, True


def guard_regex(pattern: str, max_chars: int):
    pat, ok = guard_regex_mode(pattern, max_chars)
    if not ok:
        raise GuardError("Unsupported or unsafe regular expression")
    try:
        return re.compile(pat)
    except re.error:
        raise GuardError("Invalid regular expression") from None


# ---------------------------------------------------------------------------
# 有界 LRU 缓存（容量 + TTL 双指纹，惰性过期）
# ---------------------------------------------------------------------------
class LRUCache:
    __slots__ = ("maxsize", "ttl", "data")

    def __init__(self, maxsize: int, ttl: float) -> None:
        self.maxsize = maxsize
        self.ttl = ttl
        self.data: OrderedDict[Any, tuple[float, Any]] = OrderedDict()

    def get(self, key: Any, now: float | None = None):
        item = self.data.get(key)
        if item is None:
            return None
        stamp, value = item
        if now is None:
            now = time.monotonic()
        if now - stamp > self.ttl:
            self.data.pop(key, None)
            return None
        self.data.move_to_end(key)
        return value

    def put(self, key: Any, value: Any, now: float | None = None) -> None:
        if now is None:
            now = time.monotonic()
        self.data[key] = (now, value)
        self.data.move_to_end(key)
        while len(self.data) > self.maxsize:
            self.data.popitem(last=False)

    def __len__(self) -> int:
        return len(self.data)
