# -*- coding: utf-8 -*-
"""网关共享运行时状态、有界连接池、租户级锁偏序与多维解耦纪元管理器。"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
import pathlib
import sqlite3
import threading
from typing import Any, Iterator

from .db import open_connection


class ConnectionPool:
    """线程安全的有界 SQLite 连接池。"""

    def __init__(self, db_path: str, max_size: int = 16) -> None:
        self.db_path = db_path
        self.max_size = max_size
        self._lock = threading.Lock()
        self._pool: deque[sqlite3.Connection] = deque()

    @contextmanager
    def borrow(self) -> Iterator[sqlite3.Connection]:
        conn: sqlite3.Connection | None = None
        with self._lock:
            if self._pool:
                conn = self._pool.pop()
        if conn is None:
            conn = open_connection(self.db_path)
        try:
            yield conn
        except Exception:
            try:
                if conn.in_transaction:
                    conn.rollback()
            except sqlite3.Error:
                pass
            raise
        else:
            try:
                if conn.in_transaction:
                    conn.rollback()
            except sqlite3.Error:
                pass
        finally:
            returned = False
            with self._lock:
                if len(self._pool) < self.max_size:
                    self._pool.append(conn)
                    returned = True
            if not returned:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

    def close_all(self) -> None:
        with self._lock:
            while self._pool:
                conn = self._pool.popleft()
                try:
                    conn.close()
                except sqlite3.Error:
                    pass


class TokenInterner:
    """线程安全的词元整数驻留表，用于压缩倒排索引与词序列堆内存。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._str_to_id: dict[str, int] = {}
        self._next_id = 1

    def intern(self, token: str) -> int:
        tid = self._str_to_id.get(token)
        if tid is not None:
            return tid
        with self._lock:
            tid = self._str_to_id.get(token)
            if tid is None:
                tid = self._next_id
                self._next_id += 1
                self._str_to_id[token] = tid
            return tid

    def lookup(self, token: str) -> int | None:
        return self._str_to_id.get(token)


class TenantState:
    """单租户隔离状态：独立细粒度锁偏序、解耦纪元与领域增量索引容器。"""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        # 严格全局锁偏序：risk_lock -> quota_lock -> SQLite BEGIN IMMEDIATE
        self.risk_lock = threading.RLock()
        self.quota_lock = threading.RLock()
        self.doc_lock = threading.RLock()
        self.perm_lock = threading.RLock()
        self.acl_lock = threading.RLock()
        self.policy_lock = threading.RLock()
        self.sanction_lock = threading.RLock()

        # 多维解耦纪元（互不污染）
        self.doc_epoch = 0
        self.acl_epoch = 0
        self.perm_epoch = 0
        self.policy_epoch = 0
        self.sanction_epoch = 0

        # 懒加载的领域缓存/增量结构
        self.doc_index: Any = None
        self.perm_cache: Any = None
        self.acl_cache: Any = None
        self.policy_cache: dict[str, Any] | None = None
        self.policy_cache_epoch: int = -1
        self.sanction_set: set[str] | None = None
        self.sanction_cache_epoch: int = -1
        self.risk_graph_state: Any = None


class GatewayState:
    """绑定到特定 db_path 的网关运行时状态。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self.pool = ConnectionPool(self.db_path, max_size=16)
        self.interner = TokenInterner()
        self._tenants_lock = threading.Lock()
        self._tenants: dict[str, TenantState] = {}

    def tenant(self, tenant_id: str) -> TenantState:
        ts = self._tenants.get(tenant_id)
        if ts is not None:
            return ts
        with self._tenants_lock:
            ts = self._tenants.get(tenant_id)
            if ts is None:
                ts = TenantState(tenant_id)
                self._tenants[tenant_id] = ts
            return ts


_STATES_LOCK = threading.Lock()
_STATES_BY_PATH: dict[str, GatewayState] = {}


def get_gateway_state(db_path: str | pathlib.Path) -> GatewayState:
    resolved = str(pathlib.Path(db_path).resolve())
    st = _STATES_BY_PATH.get(resolved)
    if st is not None:
        return st
    with _STATES_LOCK:
        st = _STATES_BY_PATH.get(resolved)
        if st is None:
            if len(_STATES_BY_PATH) >= 64:
                oldest_key = next(iter(_STATES_BY_PATH))
                old_st = _STATES_BY_PATH.pop(oldest_key)
                old_st.pool.close_all()
            st = GatewayState(resolved)
            _STATES_BY_PATH[resolved] = st
        return st


def register_gateway_state(db_path: str | pathlib.Path) -> GatewayState:
    """为新创建的 AegisGateway 实例重置并注册干净的 GatewayState（确保复用同路径新库时无陈旧缓存）。"""
    resolved = str(pathlib.Path(db_path).resolve())
    with _STATES_LOCK:
        old = _STATES_BY_PATH.pop(resolved, None)
        if old is not None:
            old.pool.close_all()
        st = GatewayState(resolved)
        _STATES_BY_PATH[resolved] = st
        return st
