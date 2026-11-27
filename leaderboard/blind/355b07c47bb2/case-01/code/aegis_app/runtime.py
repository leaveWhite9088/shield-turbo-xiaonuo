# -*- coding: utf-8 -*-
"""网关运行时状态管理：有界 SQLite 连接池、多维解耦纪元、全局统一锁偏序与租户内存状态容器。"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
import os
import pathlib
import queue
import sqlite3
import threading
import time
from typing import Any, Iterator

MAX_POOL_CONNECTIONS = 32
MAX_RUNTIMES = 16
MAX_SEARCH_CACHE_PER_TENANT = 128


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -16384")


class BoundedLRUCache:
    """线程安全的有界 LRU 缓存。"""

    __slots__ = ("_max_size", "_data", "_lock")

    def __init__(self, max_size: int = MAX_SEARCH_CACHE_PER_TENANT) -> None:
        self._max_size = max(1, int(max_size))
        self._data: OrderedDict[Any, Any] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        with self._lock:
            val = self._data.get(key)
            if val is not None:
                self._data.move_to_end(key)
            return val

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            while len(self._data) > self._max_size:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class BoundedConnectionPool:
    """按数据库路径隔离的有界 SQLite 连接池（显式事务控制，严防连接泄漏与隐式锁升级）。"""

    def __init__(self, db_path: str, max_size: int = MAX_POOL_CONNECTIONS) -> None:
        self.db_path = db_path
        self._max_size = max_size
        self._idle: queue.LifoQueue[sqlite3.Connection] = queue.LifoQueue(maxsize=max_size)
        self._sem = threading.BoundedSemaphore(max_size)
        self._all_lock = threading.Lock()
        self._all_conns: set[sqlite3.Connection] = set()
        self._closed = False

    def _create_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        _configure_connection(conn)
        with self._all_lock:
            self._all_conns.add(conn)
        return conn

    def acquire(self) -> sqlite3.Connection:
        self._sem.acquire()
        try:
            while True:
                try:
                    conn = self._idle.get_nowait()
                except queue.Empty:
                    return self._create_conn()
                try:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    return conn
                except sqlite3.Error:
                    self._discard(conn)
        except BaseException:
            self._sem.release()
            raise

    def _discard(self, conn: sqlite3.Connection) -> None:
        with self._all_lock:
            self._all_conns.discard(conn)
        try:
            conn.close()
        except sqlite3.Error:
            pass

    def release(self, conn: sqlite3.Connection, *, broken: bool = False) -> None:
        try:
            if broken or self._closed:
                self._discard(conn)
                return
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                self._idle.put_nowait(conn)
            except (queue.Full, sqlite3.Error):
                self._discard(conn)
        finally:
            self._sem.release()

    def close_all(self) -> None:
        self._closed = True
        while True:
            try:
                conn = self._idle.get_nowait()
            except queue.Empty:
                break
            self._discard(conn)
        with self._all_lock:
            remaining = list(self._all_conns)
            self._all_conns.clear()
        for conn in remaining:
            try:
                conn.close()
            except sqlite3.Error:
                pass


class TenantEpochs:
    """租户内 5 维完全解耦纪元：变更单维状态绝不连带清空无关索引。"""

    __slots__ = (
        "doc_epoch",
        "acl_epoch",
        "perm_epoch",
        "policy_epoch",
        "sanction_epoch",
    )

    def __init__(self) -> None:
        self.doc_epoch: int = 1
        self.acl_epoch: int = 1
        self.perm_epoch: int = 1
        self.policy_epoch: int = 1
        self.sanction_epoch: int = 1


class GatewayRuntime:
    """单个数据库实例对应的运行时引擎（连接池、统一偏序锁、解耦缓存与增量索引容器）。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.pool = BoundedConnectionPool(db_path, max_size=MAX_POOL_CONNECTIONS)
        self._meta_lock = threading.Lock()

        # 租户级多维解耦纪元
        self._epochs: dict[str, TenantEpochs] = {}

        # 全局无死锁严格偏序锁集合：
        #   Level 1: tenant_risk_locks[tenant_id]
        #   Level 2: quota_locks[(tenant_id, bucket)] (必须按 bucket 字典序升序获取)
        #   Level 3: SQLite BEGIN IMMEDIATE 写事务
        self._risk_locks: dict[str, threading.Lock] = {}
        self._quota_locks: dict[tuple[str, str], threading.Lock] = {}

        # 各独立子域租户细粒度锁（均在进入 Level 3 SQLite 写事务前按需获取，不与 Level 1/2 交叉成环）
        self._doc_locks: dict[str, threading.RLock] = {}
        self._acl_locks: dict[str, threading.RLock] = {}
        self._perm_locks: dict[str, threading.RLock] = {}
        self._policy_locks: dict[str, threading.RLock] = {}
        self._sanction_locks: dict[str, threading.RLock] = {}

        # 各模块按租户挂载的内存状态对象
        self.auth_lock = threading.RLock()
        self.tenants_cache: dict[str, tuple[str, str]] = {}  # tenant_id -> (status, webhook_secret)
        self.users_cache: dict[tuple[str, str], dict[str, Any]] = {}  # (tenant_id, user_id) -> user info

        self.org_cache: dict[str, dict[str, Any]] = {}
        self.perm_states: dict[str, Any] = {}
        self.acl_indices: dict[str, Any] = {}
        self.doc_indices: dict[str, Any] = {}
        self.search_caches: dict[str, BoundedLRUCache] = {}
        self.policy_cache: dict[str, dict[str, Any]] = {}
        self.sanction_cache: dict[str, set[str]] = {}
        self.risk_states: dict[str, Any] = {}

        # 记录数据库文件 inode 便于检测外部删库重建
        self._db_fingerprint = _stat_fingerprint(db_path)

    def epochs(self, tenant_id: str) -> TenantEpochs:
        ep = self._epochs.get(tenant_id)
        if ep is None:
            with self._meta_lock:
                ep = self._epochs.get(tenant_id)
                if ep is None:
                    ep = TenantEpochs()
                    self._epochs[tenant_id] = ep
        return ep

    def risk_lock(self, tenant_id: str) -> threading.Lock:
        """Level 1 锁：单租户风控批次串行与原子回滚锁（跨租户完全并发）。"""
        lk = self._risk_locks.get(tenant_id)
        if lk is None:
            with self._meta_lock:
                lk = self._risk_locks.get(tenant_id)
                if lk is None:
                    lk = threading.Lock()
                    self._risk_locks[tenant_id] = lk
        return lk

    def _quota_lock(self, tenant_id: str, bucket: str) -> threading.Lock:
        key = (tenant_id, bucket)
        lk = self._quota_locks.get(key)
        if lk is None:
            with self._meta_lock:
                lk = self._quota_locks.get(key)
                if lk is None:
                    lk = threading.Lock()
                    self._quota_locks[key] = lk
        return lk

    @contextmanager
    def acquire_quota_locks(self, tenant_id: str, buckets: list[str] | tuple[str, ...]) -> Iterator[None]:
        """Level 2 锁：按配额池名称字典序严格升序加锁，彻底消除跨池双向调拨与风控告警扣减的 AB-BA 死锁。"""
        ordered = sorted(set(buckets))
        acquired: list[threading.Lock] = []
        try:
            for b in ordered:
                lk = self._quota_lock(tenant_id, b)
                lk.acquire()
                acquired.append(lk)
            yield
        finally:
            for lk in reversed(acquired):
                lk.release()

    def doc_lock(self, tenant_id: str) -> threading.RLock:
        lk = self._doc_locks.get(tenant_id)
        if lk is None:
            with self._meta_lock:
                lk = self._doc_locks.get(tenant_id)
                if lk is None:
                    lk = threading.RLock()
                    self._doc_locks[tenant_id] = lk
        return lk

    def acl_lock(self, tenant_id: str) -> threading.RLock:
        lk = self._acl_locks.get(tenant_id)
        if lk is None:
            with self._meta_lock:
                lk = self._acl_locks.get(tenant_id)
                if lk is None:
                    lk = threading.RLock()
                    self._acl_locks[tenant_id] = lk
        return lk

    def perm_lock(self, tenant_id: str) -> threading.RLock:
        lk = self._perm_locks.get(tenant_id)
        if lk is None:
            with self._meta_lock:
                lk = self._perm_locks.get(tenant_id)
                if lk is None:
                    lk = threading.RLock()
                    self._perm_locks[tenant_id] = lk
        return lk

    def policy_lock(self, tenant_id: str) -> threading.RLock:
        lk = self._policy_locks.get(tenant_id)
        if lk is None:
            with self._meta_lock:
                lk = self._policy_locks.get(tenant_id)
                if lk is None:
                    lk = threading.RLock()
                    self._policy_locks[tenant_id] = lk
        return lk

    def sanction_lock(self, tenant_id: str) -> threading.RLock:
        lk = self._sanction_locks.get(tenant_id)
        if lk is None:
            with self._meta_lock:
                lk = self._sanction_locks.get(tenant_id)
                if lk is None:
                    lk = threading.RLock()
                    self._sanction_locks[tenant_id] = lk
        return lk

    def search_cache(self, tenant_id: str) -> BoundedLRUCache:
        sc = self.search_caches.get(tenant_id)
        if sc is None:
            with self._meta_lock:
                sc = self.search_caches.get(tenant_id)
                if sc is None:
                    sc = BoundedLRUCache(MAX_SEARCH_CACHE_PER_TENANT)
                    self.search_caches[tenant_id] = sc
        return sc

    @contextmanager
    def read_conn(self) -> Iterator[sqlite3.Connection]:
        conn = self.pool.acquire()
        broken = False
        try:
            yield conn
        except sqlite3.DatabaseError:
            broken = True
            raise
        finally:
            self.pool.release(conn, broken=broken)

    @contextmanager
    def write_tx(self, *, max_retries: int = 8) -> Iterator[sqlite3.Connection]:
        """Level 3 锁：显式 BEGIN IMMEDIATE 写事务，支持偶发 BUSY 退避与自动 ROLLBACK。"""
        conn = self.pool.acquire()
        broken = False
        try:
            attempt = 0
            while True:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    break
                except sqlite3.OperationalError as exc:
                    msg = str(exc).lower()
                    if ("locked" in msg or "busy" in msg) and attempt < max_retries:
                        attempt += 1
                        time.sleep(min(0.05, 0.002 * (1 << min(attempt, 5))))
                        continue
                    raise
            try:
                yield conn
                if conn.in_transaction:
                    conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        broken = True
                raise
        except sqlite3.DatabaseError:
            broken = True
            raise
        finally:
            self.pool.release(conn, broken=broken)

    def close(self) -> None:
        self.pool.close_all()


def _stat_fingerprint(db_path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(db_path)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


_REGISTRY_LOCK = threading.Lock()
_RUNTIMES: OrderedDict[str, GatewayRuntime] = OrderedDict()


def normalize_db_path(db_path: str | pathlib.Path) -> str:
    return str(pathlib.Path(db_path).resolve())


def get_runtime(db_path: str | pathlib.Path) -> GatewayRuntime:
    key = normalize_db_path(db_path)
    fp = _stat_fingerprint(key)
    with _REGISTRY_LOCK:
        rt = _RUNTIMES.get(key)
        if rt is not None:
            if fp is not None and rt._db_fingerprint is not None and fp != rt._db_fingerprint:
                # 底层文件已被外部删除并重建，清理旧运行时
                _RUNTIMES.pop(key, None)
                rt.close()
                rt = None
            else:
                if rt._db_fingerprint is None and fp is not None:
                    rt._db_fingerprint = fp
                _RUNTIMES.move_to_end(key)
                return rt
        rt = GatewayRuntime(key)
        _RUNTIMES[key] = rt
        while len(_RUNTIMES) > MAX_RUNTIMES:
            _, evicted = _RUNTIMES.popitem(last=False)
            evicted.close()
        return rt


def reset_runtime(db_path: str | pathlib.Path) -> GatewayRuntime:
    """重置指定 db_path 的全部内存运行时状态（用于重新建库或挂载新网关实例时）。"""
    key = normalize_db_path(db_path)
    with _REGISTRY_LOCK:
        old = _RUNTIMES.pop(key, None)
        if old is not None:
            old.close()
        rt = GatewayRuntime(key)
        _RUNTIMES[key] = rt
        while len(_RUNTIMES) > MAX_RUNTIMES:
            _, evicted = _RUNTIMES.popitem(last=False)
            evicted.close()
        return rt
