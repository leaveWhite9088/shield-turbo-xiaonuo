# -*- coding: utf-8 -*-
"""进程内运行时状态管理、多维解耦纪元、全局锁偏序与严格输入/复杂度守卫。"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
import math
import pathlib
import re
import threading
from typing import Any, Iterator

MAX_INT64 = (1 << 63) - 1
MIN_INT64 = -(1 << 63)

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000

MAX_REGEX_LEN = 128
MAX_REGEX_QUANTIFIER_BOUND = 50
MAX_REGEX_QUANTIFIERS = 8
MAX_REGEX_ALTERNATIONS = 10

_INT_STR_RE = re.compile(r"^[+-]?[0-9]+$")


def parse_strict_int(
    value: Any,
    *,
    field_name: str = "value",
    min_val: int = MIN_INT64,
    max_val: int = MAX_INT64,
) -> int:
    """严格整数解析：拒绝 bool、float、NaN/Inf 及超出 64 位整数边界的输入。"""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"Invalid integer for {field_name}")
    if isinstance(value, int):
        res = value
    elif isinstance(value, str):
        s = value.strip()
        if not s or len(s) > 24 or not _INT_STR_RE.match(s):
            raise ValueError(f"Invalid integer string for {field_name}")
        res = int(s)
    else:
        raise ValueError(f"Invalid integer type for {field_name}")
    if res < min_val or res > max_val:
        raise ValueError(f"Integer out of range for {field_name}")
    return res


def parse_strict_number(value: Any, *, field_name: str = "value") -> float:
    """严格数值解析（用于规则比较）：拒绝 bool、NaN、Inf 与非数值类型。"""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"Invalid number for {field_name}")
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        s = value.strip()
        if not s or len(s) > 64:
            raise ValueError(f"Invalid number string for {field_name}")
        try:
            num = float(s)
        except ValueError as exc:
            raise ValueError(f"Invalid number string for {field_name}") from exc
    else:
        raise ValueError(f"Invalid number type for {field_name}")
    if math.isnan(num) or math.isinf(num):
        raise ValueError(f"Non-finite number not allowed for {field_name}")
    return num


def check_raw_json_depth(raw: str, max_depth: int = MAX_JSON_DEPTH) -> None:
    """在 json.loads 之前以线性扫描预检 JSON 嵌套深度，毫秒级拦截千层嵌套炸弹。"""
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Request payload exceeds maximum size limit")
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
        else:
            if ch == '"':
                in_string = True
            elif ch == "{" or ch == "[":
                depth += 1
                if depth > max_depth:
                    raise ValueError("JSON nesting depth exceeds maximum allowed limit")
            elif ch == "}" or ch == "]":
                depth -= 1


def check_object_depth_and_nodes(
    obj: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
) -> None:
    """对直接传入的 Python 对象预检嵌套深度与节点数，防止深度递归攻击。"""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    seen_nodes = 0
    while stack:
        curr, d = stack.pop()
        if d > max_depth:
            raise ValueError("Payload nesting depth exceeds maximum allowed limit")
        seen_nodes += 1
        if seen_nodes > max_nodes:
            raise ValueError("Payload node count exceeds maximum allowed limit")
        if isinstance(curr, dict):
            for v in curr.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))
        elif isinstance(curr, list):
            for v in curr:
                if isinstance(v, (dict, list)):
                    stack.append((v, d + 1))


def validate_safe_regex(pattern: str) -> None:
    """静态安全审计正则表达式：阻断回溯嵌套量词、超大花括号上界、反向引用与环视。"""
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("Regex pattern must be a non-empty string")
    if len(pattern) > MAX_REGEX_LEN:
        raise ValueError("Regex pattern exceeds maximum length")

    n = len(pattern)
    i = 0
    in_char_class = False
    # group_stack tracks [has_quantifier_or_alt] for each open '('
    group_stack: list[bool] = []
    last_atom_has_quant = False
    total_quantifiers = 0
    total_alternations = 0

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                raise ValueError("Trailing backslash in regex")
            nxt = pattern[i + 1]
            if not in_char_class and nxt.isdigit():
                raise ValueError("Backreferences are not allowed in regex")
            last_atom_has_quant = False
            i += 2
            continue

        if in_char_class:
            if ch == "]":
                in_char_class = False
                last_atom_has_quant = False
            i += 1
            continue

        if ch == "[":
            in_char_class = True
            i += 1
            continue

        if ch == "(":
            if i + 1 < n and pattern[i + 1] == "?":
                # Allow non-capturing (?:...) and simple flags; reject lookarounds & backrefs
                if i + 2 < n and pattern[i + 2] in ("=", "!", "<"):
                    raise ValueError("Lookaround assertions are not allowed in regex")
                if pattern[i : i + 4] == "(?P=":
                    raise ValueError("Named backreferences are not allowed in regex")
            group_stack.append(False)
            last_atom_has_quant = False
            i += 1
            continue

        if ch == ")":
            if not group_stack:
                raise ValueError("Unbalanced parenthesis in regex")
            grp_has_q = group_stack.pop()
            last_atom_has_quant = grp_has_q
            if grp_has_q and group_stack:
                group_stack[-1] = True
            i += 1
            continue

        if ch == "|":
            total_alternations += 1
            if total_alternations > MAX_REGEX_ALTERNATIONS:
                raise ValueError("Too many alternations in regex")
            if group_stack:
                group_stack[-1] = True
            last_atom_has_quant = False
            i += 1
            continue

        if ch in ("*", "+", "?"):
            total_quantifiers += 1
            if total_quantifiers > MAX_REGEX_QUANTIFIERS:
                raise ValueError("Too many quantifiers in regex")
            if last_atom_has_quant:
                raise ValueError("Nested quantifiers are not allowed in regex")
            if group_stack:
                group_stack[-1] = True
            last_atom_has_quant = True
            # Handle optional lazy/possessive modifier ? or +
            if i + 1 < n and pattern[i + 1] in ("?", "+"):
                i += 2
            else:
                i += 1
            continue

        if ch == "{":
            close_idx = pattern.find("}", i + 1)
            if close_idx != -1:
                inner = pattern[i + 1 : close_idx]
                parts = inner.split(",")
                if len(parts) in (1, 2) and all(p == "" or p.isdigit() for p in parts):
                    total_quantifiers += 1
                    if total_quantifiers > MAX_REGEX_QUANTIFIERS:
                        raise ValueError("Too many quantifiers in regex")
                    if last_atom_has_quant:
                        raise ValueError("Nested quantifiers are not allowed in regex")
                    for p in parts:
                        if p and int(p) > MAX_REGEX_QUANTIFIER_BOUND:
                            raise ValueError("Regex repetition bound exceeds limit")
                    if group_stack:
                        group_stack[-1] = True
                    last_atom_has_quant = True
                    i = close_idx + 1
                    if i < n and pattern[i] == "?":
                        i += 1
                    continue
            last_atom_has_quant = False
            i += 1
            continue

        last_atom_has_quant = False
        i += 1


class TenantState:
    """单租户隔离状态：解耦多维纪元、细粒度租户锁及各域增量索引/缓存槽位。"""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id

        # 多维解耦纪元（互不连坐）
        self.doc_epoch: int = 0
        self.acl_epoch: int = 0
        self.perm_epoch: int = 0
        self.policy_epoch: int = 0
        self.sanction_epoch: int = 0

        # 严格全局锁偏序：
        # Level 1: risk_lock（风控批次评估锁）
        # Level 2: quota_locks[bucket] 按 bucket 名称字典序获取
        # Level 3: SQLite BEGIN IMMEDIATE 写事务
        self.risk_lock = threading.Lock()
        self._quota_locks_guard = threading.Lock()
        self._quota_locks: dict[str, threading.Lock] = {}

        # 独立域细粒度读写协调锁（不阻塞跨租户或无关域）
        self.doc_lock = threading.RLock()
        self.acl_lock = threading.RLock()
        self.perm_lock = threading.RLock()
        self.meta_lock = threading.RLock()

        # 各域缓存/增量索引槽位（由对应模块懒加载与增量维护）
        self.doc_index: Any = None
        self.acl_snapshot: Any = None
        self.acl_snapshot_epoch: int = -1
        self.perm_snapshot: Any = None
        self.perm_snapshot_epoch: int = -1
        self.policy_cache: dict[str, Any] | None = None
        self.policy_cache_epoch: int = -1
        self.sanctions_cache: frozenset[str] | None = None
        self.sanctions_cache_epoch: int = -1

        # 风控滑窗与三跳传染图增量状态（受 risk_lock 保护）
        self.risk_windows: Any = None
        self.contagion_graph: Any = None
        self.risk_loaded: bool = False

    def get_quota_lock(self, quota_type: str) -> threading.Lock:
        with self._quota_locks_guard:
            lock = self._quota_locks.get(quota_type)
            if lock is None:
                lock = threading.Lock()
                self._quota_locks[quota_type] = lock
            return lock

    @contextmanager
    def acquire_quota_locks(self, *quota_types: str) -> Iterator[None]:
        """按字典序获取一个或多个配额池锁（Level 2），杜绝跨池双向调拨死锁。"""
        ordered = sorted(set(quota_types))
        locks = [self.get_quota_lock(qt) for qt in ordered]
        acquired: list[threading.Lock] = []
        try:
            for lk in locks:
                lk.acquire()
                acquired.append(lk)
            yield
        finally:
            for lk in reversed(acquired):
                lk.release()

    def invalidate_risk_state(self) -> None:
        """在批次异常回滚后清空内存风控滑窗与传染图状态，确保零内存污染。"""
        self.risk_windows = None
        self.contagion_graph = None
        self.risk_loaded = False


class GatewayRuntime:
    """绑定到单个 db_path 的进程内运行时容器（含连接池与多租户隔离状态）。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._tenants_guard = threading.Lock()
        self._tenants: dict[str, TenantState] = {}
        self._pool_guard = threading.Lock()
        self._conn_pool: list[Any] = []
        self._pool_max_size: int = 16

    def get_tenant(self, tenant_id: str) -> TenantState:
        ts = self._tenants.get(tenant_id)
        if ts is not None:
            return ts
        with self._tenants_guard:
            ts = self._tenants.get(tenant_id)
            if ts is None:
                ts = TenantState(tenant_id)
                self._tenants[tenant_id] = ts
            return ts

    def close_pool(self) -> None:
        with self._pool_guard:
            for conn in self._conn_pool:
                try:
                    conn.close()
                except Exception:
                    pass
            self._conn_pool.clear()


_RUNTIMES_GUARD = threading.Lock()
_RUNTIMES: OrderedDict[str, GatewayRuntime] = OrderedDict()
_MAX_RUNTIMES = 16


def _norm_db_path(db_path: str | pathlib.Path) -> str:
    return str(pathlib.Path(db_path).resolve())


def get_runtime(db_path: str | pathlib.Path) -> GatewayRuntime:
    key = _norm_db_path(db_path)
    with _RUNTIMES_GUARD:
        rt = _RUNTIMES.get(key)
        if rt is not None:
            _RUNTIMES.move_to_end(key)
            return rt
        rt = GatewayRuntime(key)
        _RUNTIMES[key] = rt
        while len(_RUNTIMES) > _MAX_RUNTIMES:
            _, evicted = _RUNTIMES.popitem(last=False)
            evicted.close_pool()
        return rt


def reset_runtime(db_path: str | pathlib.Path) -> None:
    """重置指定 db_path 的运行时缓存与连接池（在 seed_dataset 或网关重新挂载时调用）。"""
    key = _norm_db_path(db_path)
    with _RUNTIMES_GUARD:
        old = _RUNTIMES.pop(key, None)
        if old is not None:
            old.close_pool()
