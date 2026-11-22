# -*- coding: utf-8 -*-
"""运行时并发协调、线程本地连接复用、细粒度锁与防竞态 Epoch 缓存管理。"""
from __future__ import annotations

import pathlib
import sqlite3
import threading
from typing import Any


class ConflictError(Exception):
    """表示资源状态冲突或幂等唯一约束冲突（映射为 HTTP 409）。"""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class DBRuntime:
    """单个数据库路径对应的运行时协调器（细粒度锁、连接池与 Epoch 隔离缓存）。"""

    def __init__(self, norm_db_path: str) -> None:
        self.db_path = norm_db_path
        self._local = threading.local()
        self._meta_lock = threading.Lock()
        self._tenant_locks: dict[str, threading.Lock] = {}
        self._resource_locks: dict[tuple[str, str], threading.Lock] = {}

        # 按租户隔离的版本号与缓存映射（防跨租户串味、防并发撤权回填竞态）
        self._epoch_lock = threading.Lock()
        self._perm_epochs: dict[str, int] = {}
        self._doc_epochs: dict[str, int] = {}
        self._policy_epochs: dict[str, int] = {}

        self._perm_cache: dict[tuple[str, str], tuple[int, Any]] = {}
        self._doc_index_cache: dict[str, tuple[int, Any]] = {}
        self._policy_cache: dict[str, tuple[int, dict[str, Any]]] = {}

        self.schema_initialized = False

    def get_connection(self) -> sqlite3.Connection:
        """获取当前线程复用的 SQLite 连接，并在首次创建时配置高性能 PRAGMA。"""
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA cache_size=-32000;")
        conn.execute("PRAGMA busy_timeout=30000;")
        self._local.conn = conn
        return conn

    def reset_thread_connection(self) -> None:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def get_tenant_lock(self, tenant_id: str) -> threading.Lock:
        with self._meta_lock:
            lock = self._tenant_locks.get(tenant_id)
            if lock is None:
                lock = threading.Lock()
                self._tenant_locks[tenant_id] = lock
            return lock

    def get_resource_lock(self, tenant_id: str, resource_key: str) -> threading.Lock:
        key = (tenant_id, resource_key)
        with self._meta_lock:
            lock = self._resource_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._resource_locks[key] = lock
            return lock

    def get_epoch(self, domain: str, tenant_id: str) -> int:
        with self._epoch_lock:
            if domain == "perm":
                return self._perm_epochs.get(tenant_id, 0)
            if domain == "doc":
                return self._doc_epochs.get(tenant_id, 0)
            if domain == "policy":
                return self._policy_epochs.get(tenant_id, 0)
            raise ValueError(f"Unknown cache domain: {domain}")

    def bump_epoch(self, domain: str, tenant_id: str) -> int:
        with self._epoch_lock:
            if domain == "perm":
                new_ep = self._perm_epochs.get(tenant_id, 0) + 1
                self._perm_epochs[tenant_id] = new_ep
                stale_keys = [k for k in self._perm_cache if k[0] == tenant_id]
                for k in stale_keys:
                    self._perm_cache.pop(k, None)
                return new_ep
            if domain == "doc":
                new_ep = self._doc_epochs.get(tenant_id, 0) + 1
                self._doc_epochs[tenant_id] = new_ep
                self._doc_index_cache.pop(tenant_id, None)
                return new_ep
            if domain == "policy":
                new_ep = self._policy_epochs.get(tenant_id, 0) + 1
                self._policy_epochs[tenant_id] = new_ep
                self._policy_cache.pop(tenant_id, None)
                return new_ep
            raise ValueError(f"Unknown cache domain: {domain}")

    def get_perm_cached(self, tenant_id: str, user_id: str) -> tuple[int, Any | None]:
        with self._epoch_lock:
            ep = self._perm_epochs.get(tenant_id, 0)
            entry = self._perm_cache.get((tenant_id, user_id))
            if entry is not None and entry[0] == ep:
                return ep, entry[1]
            return ep, None

    def put_perm_cached(self, tenant_id: str, user_id: str, expected_epoch: int, value: Any) -> None:
        with self._epoch_lock:
            if self._perm_epochs.get(tenant_id, 0) == expected_epoch:
                self._perm_cache[(tenant_id, user_id)] = (expected_epoch, value)

    def get_doc_index_cached(self, tenant_id: str) -> tuple[int, Any | None]:
        with self._epoch_lock:
            ep = self._doc_epochs.get(tenant_id, 0)
            entry = self._doc_index_cache.get(tenant_id)
            if entry is not None and entry[0] == ep:
                return ep, entry[1]
            return ep, None

    def put_doc_index_cached(self, tenant_id: str, expected_epoch: int, value: Any) -> None:
        with self._epoch_lock:
            if self._doc_epochs.get(tenant_id, 0) == expected_epoch:
                self._doc_index_cache[tenant_id] = (expected_epoch, value)

    def get_policy_cached(self, tenant_id: str) -> tuple[int, dict[str, Any] | None]:
        with self._epoch_lock:
            ep = self._policy_epochs.get(tenant_id, 0)
            entry = self._policy_cache.get(tenant_id)
            if entry is not None and entry[0] == ep:
                return ep, entry[1]
            return ep, None

    def put_policy_cached(self, tenant_id: str, expected_epoch: int, value: dict[str, Any]) -> None:
        with self._epoch_lock:
            if self._policy_epochs.get(tenant_id, 0) == expected_epoch:
                self._policy_cache[tenant_id] = (expected_epoch, value)


_RUNTIMES_LOCK = threading.Lock()
_RUNTIMES: dict[str, DBRuntime] = {}


def get_runtime(db_path: str | pathlib.Path) -> DBRuntime:
    norm = str(pathlib.Path(db_path).resolve())
    with _RUNTIMES_LOCK:
        rt = _RUNTIMES.get(norm)
        if rt is None:
            rt = DBRuntime(norm)
            _RUNTIMES[norm] = rt
        return rt
