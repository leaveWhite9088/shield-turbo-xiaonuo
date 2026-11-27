# -*- coding: utf-8 -*-
"""严格输入校验、JSON 深度预检、无回溯正则安全审计与模板白名单沙箱模块。"""
from __future__ import annotations

import json
import math
import re
from typing import Any

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_REGEX_LEN = 200
MAX_REGEX_BRACE = 64
MAX_REGEX_INPUT_LEN = 4096
MAX_RULE_DEPTH = 12
MAX_RULE_NODES = 128

_EMAIL_LOCAL_RE = re.compile(r"^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*$")
_EMAIL_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$")
_EVENT_FILTER_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
_SAFE_TITLE_PLACEHOLDER_RE = re.compile(r"\{(tenant_id|total_records|total_amount_cents)\}")
_ALLOWED_PLACEHOLDERS = frozenset({"tenant_id", "total_records", "total_amount_cents"})


def strict_int(
    value: Any,
    field_name: str,
    *,
    min_val: int | None = None,
    max_val: int | None = None,
    allow_str: bool = False,
) -> int:
    """严格整数转换：拒绝 bool、浮点数、NaN/Inf 与超出有符号 64 位整数范围的值。"""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not boolean")
    if isinstance(value, int):
        res = value
    elif allow_str and isinstance(value, str):
        s = value.strip()
        if not s or not re.fullmatch(r"[+-]?[0-9]+", s):
            raise ValueError(f"{field_name} must be a valid integer")
        res = int(s, 10)
    else:
        raise ValueError(f"{field_name} must be an integer")

    if res < INT64_MIN or res > INT64_MAX:
        raise ValueError(f"{field_name} exceeds 64-bit integer bounds")
    if min_val is not None and res < min_val:
        raise ValueError(f"{field_name} must be >= {min_val}")
    if max_val is not None and res > max_val:
        raise ValueError(f"{field_name} must be <= {max_val}")
    return res


def strict_finite_float(value: Any, field_name: str) -> float:
    """严格有限数值转换：拒绝 bool、非数值及 NaN/Inf。"""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be numeric, not boolean")
    if not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be numeric")
    try:
        num = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} is not a valid number") from exc
    if not math.isfinite(num):
        raise ValueError(f"{field_name} must be finite")
    return num


def _reject_non_finite_json(token: str) -> Any:
    raise ValueError(f"Non-finite JSON constant is forbidden: {token}")


def precheck_json_raw(
    raw: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
) -> None:
    """在调用 json.loads 前执行 O(N) 字节长度与括号嵌套深度预检。"""
    if len(raw.encode("utf-8", errors="replace")) > max_bytes:
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
        elif ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                raise ValueError("JSON nesting depth exceeds maximum allowed limit")
        elif ch == "}" or ch == "]":
            if depth > 0:
                depth -= 1


def safe_json_loads(
    raw: str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
) -> Any:
    precheck_json_raw(raw, max_bytes=max_bytes, max_depth=max_depth)
    return json.loads(raw, parse_constant=_reject_non_finite_json)


def validate_contact_email(email: Any) -> bool:
    """线性时间无回溯邮箱格式校验，免疫 ReDoS。"""
    if not isinstance(email, str) or not email or len(email) > 254:
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain or len(local) > 64 or len(domain) > 253:
        return False
    return (_EMAIL_LOCAL_RE.fullmatch(local) is not None) and (
        _EMAIL_DOMAIN_RE.fullmatch(domain) is not None
    )


def validate_safe_regex(pattern: str) -> re.Pattern[str]:
    """对用户自定义正则进行抗 ReDoS 安全审计并预编译。

    禁止：超长模式、反向引用、环视断言、嵌套量词、带量词分组内的分支或内层量词、大上界花括号。
    """
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("REGEX pattern must be a non-empty string")
    if len(pattern) > MAX_REGEX_LEN:
        raise ValueError("REGEX pattern exceeds maximum length")

    n = len(pattern)
    i = 0
    in_class = False
    # 栈记录每个左括号内的结构特征: [has_quantifier_inside, has_alternation_inside]
    group_stack: list[list[bool]] = []
    last_atom_is_quantifiable = False
    last_group_has_quant_or_alt = False
    last_was_quantifier = False

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                raise ValueError("Trailing backslash in REGEX pattern")
            nxt = pattern[i + 1]
            if nxt in "123456789":
                raise ValueError("Backreferences are forbidden in REGEX pattern")
            if nxt == "x":
                i += 4
            elif nxt == "u":
                i += 6
            else:
                i += 2
            last_atom_is_quantifiable = True
            last_group_has_quant_or_alt = False
            last_was_quantifier = False
            continue

        if in_class:
            if ch == "]":
                in_class = False
                last_atom_is_quantifiable = True
                last_group_has_quant_or_alt = False
                last_was_quantifier = False
            i += 1
            continue

        if ch == "[":
            in_class = True
            last_atom_is_quantifiable = False
            last_group_has_quant_or_alt = False
            last_was_quantifier = False
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue

        if ch == "(":
            if i + 1 < n and pattern[i + 1] == "?":
                # 仅允许非捕获分组 (?:...)，禁止环视 (?= / (?! / (?<= / (?<!、命名反向引用 (?P=、条件等
                if i + 2 >= n or pattern[i + 2] != ":":
                    raise ValueError("Unsupported or unsafe regex group extension")
                i += 3
            else:
                i += 1
            group_stack.append([False, False])
            last_atom_is_quantifiable = False
            last_group_has_quant_or_alt = False
            last_was_quantifier = False
            continue

        if ch == ")":
            if not group_stack:
                raise ValueError("Unbalanced ')' in REGEX pattern")
            has_q, has_alt = group_stack.pop()
            if group_stack:
                if has_q:
                    group_stack[-1][0] = True
                if has_alt:
                    group_stack[-1][1] = True
            last_atom_is_quantifiable = True
            last_group_has_quant_or_alt = has_q or has_alt
            last_was_quantifier = False
            i += 1
            continue

        if ch == "|":
            if group_stack:
                group_stack[-1][1] = True
            last_atom_is_quantifiable = False
            last_group_has_quant_or_alt = False
            last_was_quantifier = False
            i += 1
            continue

        if ch in ("*", "+", "?"):
            if last_was_quantifier:
                # 允许惰性修饰符 *? +? ?? {m,n}? 仅一次
                if ch == "?":
                    last_was_quantifier = False
                    last_atom_is_quantifiable = False
                    i += 1
                    continue
                raise ValueError("Nested or chained quantifiers are forbidden in REGEX")
            if not last_atom_is_quantifiable:
                raise ValueError("Dangling quantifier in REGEX")
            if last_group_has_quant_or_alt:
                raise ValueError("Quantified group must not contain inner quantifiers or alternations")
            if group_stack:
                group_stack[-1][0] = True
            last_was_quantifier = True
            last_atom_is_quantifiable = False
            last_group_has_quant_or_alt = False
            i += 1
            continue

        if ch == "{":
            close_idx = pattern.find("}", i + 1)
            if close_idx != -1:
                inner = pattern[i + 1 : close_idx]
                m_brace = re.fullmatch(r"([0-9]+)(?:,([0-9]*))?", inner)
                if m_brace:
                    if last_was_quantifier or not last_atom_is_quantifiable:
                        raise ValueError("Invalid brace quantifier placement in REGEX")
                    if last_group_has_quant_or_alt:
                        raise ValueError("Quantified group must not contain inner quantifiers or alternations")
                    low_num = int(m_brace.group(1))
                    high_str = m_brace.group(2)
                    if low_num > MAX_REGEX_BRACE:
                        raise ValueError("REGEX brace quantifier lower bound exceeds safe limit")
                    if high_str is not None and high_str != "":
                        high_num = int(high_str)
                        if high_num > MAX_REGEX_BRACE or high_num < low_num:
                            raise ValueError("REGEX brace quantifier upper bound invalid or exceeds safe limit")
                    if group_stack:
                        group_stack[-1][0] = True
                    last_was_quantifier = True
                    last_atom_is_quantifiable = False
                    last_group_has_quant_or_alt = False
                    i = close_idx + 1
                    continue
            # 字面量 '{'
            last_atom_is_quantifiable = True
            last_group_has_quant_or_alt = False
            last_was_quantifier = False
            i += 1
            continue

        last_atom_is_quantifiable = ch not in ("^", "$")
        last_group_has_quant_or_alt = False
        last_was_quantifier = False
        i += 1

    if in_class or group_stack:
        raise ValueError("Unclosed character class or group in REGEX")

    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid REGEX pattern: {exc}") from exc


def validate_event_filter(event_filter: str) -> str:
    cleaned = str(event_filter or "").strip()
    if not cleaned:
        return ""
    if not _EVENT_FILTER_RE.fullmatch(cleaned):
        raise ValueError("extra_event_filter must be empty or a valid uppercase event name")
    return cleaned


def validate_title_format(title_format: str) -> str:
    """严格白名单校验报表标题模板：仅允许字面文本与 {tenant_id}/{total_records}/{total_amount_cents}。"""
    if not isinstance(title_format, str):
        raise ValueError("title_format must be a string")
    t_fmt = title_format.strip()
    if not t_fmt or len(t_fmt) > 200:
        raise ValueError("Valid title_format (1..200 chars) is required")

    idx = 0
    n = len(t_fmt)
    while idx < n:
        ch = t_fmt[idx]
        if ch == "{":
            end = t_fmt.find("}", idx + 1)
            if end == -1:
                raise ValueError("Unclosed placeholder in title_format")
            key = t_fmt[idx + 1 : end]
            if key not in _ALLOWED_PLACEHOLDERS:
                raise ValueError(f"Forbidden template placeholder: {{{key}}}")
            idx = end + 1
        elif ch == "}":
            raise ValueError("Unmatched '}' in title_format")
        else:
            idx += 1
    return t_fmt


def render_safe_title(
    title_format: str,
    *,
    tenant_id: str,
    total_records: int,
    total_amount_cents: int,
) -> str:
    validated = validate_title_format(title_format)
    mapping = {
        "tenant_id": str(tenant_id),
        "total_records": str(total_records),
        "total_amount_cents": str(total_amount_cents),
    }
    return _SAFE_TITLE_PLACEHOLDER_RE.sub(lambda m: mapping[m.group(1)], validated)
