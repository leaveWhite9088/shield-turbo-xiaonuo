# -*- coding: utf-8 -*-
"""模型标识归一化与运行目录命名安全校验（对齐 silicon-rider-xiaonuo）。"""
from __future__ import annotations

import re

_BATCH_SUFFIX_RE = re.compile(
    r"-(?:"
    r"(?:h|s)(?:[-_]?\d+)?"
    r"|(?!(?:v|ver|r|k|m)[-_]?\d+$)[a-z](?:[-_]?\d+)"
    r"|(?:batch|run|round|trial|seed|rep|repeat)(?:[-_]?\d+)?"
    r")$",
    re.IGNORECASE,
)

_SAFE_RUN_RE = re.compile(r"^[A-Za-z0-9._\-\u4e00-\u9fff（）()]{1,96}$")


def sanitize_run_name(raw_name: str) -> str:
    """校验并返回合法的运行目录名称，禁止路径分隔符与越界字符。"""
    text = (raw_name or "").strip()
    if not text:
        raise ValueError("模型或运行名称不能为空")
    if "/" in text or "\\" in text or ".." in text or not _SAFE_RUN_RE.match(text):
        raise ValueError(f"非法的模型或运行标识: {raw_name!r}")
    return text


def canonical_model_id(name: str) -> str:
    """剥离末尾已知批次后缀（如 -s1 / -run2），返回小写规范模型 ID。"""
    text = (name or "").strip()
    if not text:
        return ""
    stripped = _BATCH_SUFFIX_RE.sub("", text)
    return (stripped or text).lower()


def matches_batch_run(model_name: str, run_name: str) -> bool:
    """判断 run_name 是否归属于指定批次前缀 model_name。"""
    m = (model_name or "").strip().lower()
    r = (run_name or "").strip().lower()
    if not m or not r:
        return False
    if r == m:
        return True
    if r.startswith(m + "-") or r.startswith(m + "_"):
        return True
    if m[-1].isalpha():
        return re.match(r"^" + re.escape(m) + r"\d+(?:[-_].*)?$", r) is not None
    return False
