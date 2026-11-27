# -*- coding: utf-8 -*-
"""进程内有界运行设施：分租户锁与严格数值/大小守卫。"""
from __future__ import annotations

import math
import threading
from typing import Any

MAX_SQLITE_INT = (1 << 63) - 1
MIN_SQLITE_INT = -(1 << 63)
MAX_BATCH_SIZE = 512
MAX_JSON_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000


class TenantLocks:
    """只在查找锁对象时持有全局锁；业务期间仅持有本租户锁。"""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[tuple[str, str], threading.RLock] = {}

    def for_tenant(self, db_path: str, tenant_id: str) -> threading.RLock:
        key = (str(db_path), str(tenant_id))
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._locks[key] = lock
            return lock


TENANT_LOCKS = TenantLocks()


def tenant_write_lock(db_path: str, tenant_id: str) -> threading.RLock:
    return TENANT_LOCKS.for_tenant(db_path, tenant_id)


def strict_int(
    value: Any,
    field: str,
    *,
    minimum: int = MIN_SQLITE_INT,
    maximum: int = MAX_SQLITE_INT,
) -> int:
    """拒绝 bool、NaN/Inf、非整浮点和 SQLite 无法表示的大整数。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{field} is outside the signed 64-bit range")
    return value


def bounded_text(value: Any, field: str, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value.strip()
    if (not allow_empty and not text) or len(text) > maximum or "\x00" in text:
        raise ValueError(f"Invalid or oversized {field}")
    return text


def finite_number(value: Any, field: str = "number") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field} must be finite")
    return result
