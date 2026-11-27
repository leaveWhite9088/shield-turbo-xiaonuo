# -*- coding: utf-8 -*-
"""统一严格类型校验、JSON 嵌套深度预检、正则安全编译与字面模板沙箱模块。"""
from __future__ import annotations

import math
import re
from typing import Any

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_REGEX_LEN = 256
MAX_REGEX_SUBJECT_LEN = 4096

ALLOWED_TEMPLATE_PLACEHOLDERS = frozenset({
    "tenant_id",
    "total_records",
    "total_amount_cents",
})
EVENT_FILTER_RE = re.compile(r"^[A-Za-z0-9_]{0,64}$")
_BACKREF_RE = re.compile(r"\\([1-9][0-9]*)|\(\?P=")
_LOOKAROUND_RE = re.compile(r"\(\?(?:[=!<]|<[=!])")
_LARGE_BRACE_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")


def parse_strict_int(
    val: Any,
    field_name: str,
    *,
    min_val: int | None = None,
    max_val: int | None = None,
) -> int:
    """严格解析 64 位有符号整数，拒绝 bool、NaN/Inf、非整数浮点及越界大整数。"""
    if isinstance(val, bool) or val is None:
        raise ValueError(f"Invalid integer for {field_name}")
    if isinstance(val, int):
        res = val
    elif isinstance(val, float):
        if math.isnan(val) or math.isinf(val) or not val.is_integer():
            raise ValueError(f"Invalid integer for {field_name}")
        res = int(val)
    elif isinstance(val, str):
        s = val.strip()
        if not s:
            raise ValueError(f"Invalid integer for {field_name}")
        if s[0] in ("+", "-"):
            if len(s) == 1 or not s[1:].isdigit():
                raise ValueError(f"Invalid integer for {field_name}")
        elif not s.isdigit():
            raise ValueError(f"Invalid integer for {field_name}")
        res = int(s, 10)
    else:
        raise ValueError(f"Invalid integer for {field_name}")

    if res < INT64_MIN or res > INT64_MAX:
        raise ValueError(f"Integer out of 64-bit range for {field_name}")
    if min_val is not None and res < min_val:
        raise ValueError(f"{field_name} must be >= {min_val}")
    if max_val is not None and res > max_val:
        raise ValueError(f"{field_name} must be <= {max_val}")
    return res


def parse_strict_number(val: Any, field_name: str = "number") -> float:
    """严格解析有限数值，拒绝 bool、NaN 与 Inf。"""
    if isinstance(val, bool) or val is None:
        raise ValueError(f"Invalid number for {field_name}")
    if isinstance(val, (int, float)):
        fval = float(val)
    elif isinstance(val, str):
        fval = float(val.strip())
    else:
        raise ValueError(f"Invalid number for {field_name}")
    if math.isnan(fval) or math.isinf(fval):
        raise ValueError(f"Non-finite number not allowed for {field_name}")
    return fval


def check_json_depth_and_size(
    raw: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
) -> None:
    """在调用 json.loads 之前以 O(N) 线性扫描校验字节大小与最大括号嵌套深度。"""
    if len(raw.encode("utf-8", errors="ignore")) > max_bytes:
        raise ValueError("JSON payload exceeds maximum allowed size")
    depth = 0
    in_string = False
    escaped = False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in ("{", "["):
            depth += 1
            if depth > max_depth:
                raise ValueError(f"JSON nesting depth exceeds maximum ({max_depth})")
        elif ch in ("}", "]"):
            if depth > 0:
                depth -= 1


def _has_nested_quantifier(pattern: str) -> bool:
    """线性扫描检测分组内含重复量词且分组自身带量词的回溯风险模式。"""
    stack: list[bool] = []
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            i += 1
            continue
        if ch == "(":
            stack.append(False)
            i += 1
            continue
        if ch == ")":
            has_inner_q = stack.pop() if stack else False
            nxt_idx = i + 1
            if nxt_idx < n and pattern[nxt_idx] in ("+", "*", "?", "{"):
                if has_inner_q:
                    return True
                if stack:
                    stack[-1] = True
            elif has_inner_q and stack:
                stack[-1] = True
            i += 1
            continue
        if ch in ("+", "*", "?", "{"):
            if stack:
                stack[-1] = True
        i += 1
    return False


def compile_safe_regex(pattern: str) -> re.Pattern[str]:
    """校验并编译规则正则，阻断回溯、反向引用、环视与超大上界量词炸弹。"""
    if not isinstance(pattern, str) or len(pattern) > MAX_REGEX_LEN:
        raise ValueError("Regex pattern exceeds maximum length")
    if _BACKREF_RE.search(pattern):
        raise ValueError("Regex backreferences are not permitted")
    if _LOOKAROUND_RE.search(pattern):
        raise ValueError("Regex lookarounds are not permitted")
    for m in _LARGE_BRACE_RE.finditer(pattern):
        low = int(m.group(1))
        high_str = m.group(2)
        if low > 100 or (high_str is not None and (high_str == "" or int(high_str) > 100)):
            raise ValueError("Regex quantifier bound exceeds safe limit (100)")
    if _has_nested_quantifier(pattern):
        raise ValueError("Nested quantifiers in regex are not permitted")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern: {exc}") from exc


def validate_literal_template(title_format: str) -> None:
    """严格校验报表标题模板，仅允许白名单字面占位符，禁止格式化属性/宽度注入。"""
    i = 0
    n = len(title_format)
    while i < n:
        ch = title_format[i]
        if ch == "{":
            end = title_format.find("}", i + 1)
            if end == -1:
                raise ValueError("Unmatched '{' in title_format")
            token = title_format[i + 1 : end]
            if token not in ALLOWED_TEMPLATE_PLACEHOLDERS:
                raise ValueError(f"Unsupported or unsafe template placeholder: {{{token}}}")
            i = end + 1
        elif ch == "}":
            raise ValueError("Unmatched '}' in title_format")
        else:
            i += 1


def render_literal_template(
    title_format: str,
    *,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    """使用纯字面替换安全渲染报表标题，完全绕开 str.format。"""
    validate_literal_template(title_format)
    return (
        title_format.replace("{tenant_id}", str(tenant_id))
        .replace("{total_records}", str(int(total_records)))
        .replace("{total_amount_cents}", str(int(total_amount_cents)))
    )
