# -*- coding: utf-8 -*-
"""跨模块并发控制的全局统一锁偏序（Global Lock Partial Order）。

锁序铁律（全网关唯一实现，任何新增写路径都必须遵守）：

    第一级：Python 细粒度业务锁（按 (tenant_id, quota_type) 维度分片）
    第二级：SQLite 写锁（``BEGIN IMMEDIATE``）

    * 任何代码路径都 **必须先获取 Python 业务锁，再申请数据库写锁**；
    * 提交/回滚完成后 **先释放数据库写锁，再释放 Python 业务锁**。

由于「持有数据库写锁的线程永远不会等待 Python 业务锁」，且多个业务锁之间
按 ``(tenant_id, quota_type)`` 升序获取（全局全序），系统图中不存在环路，
故并发 ``quotas/transfer`` 双向交叉调拨、``quotas/consume`` 与
``risk/evaluate-batch`` 联动扣减 ``REALTIME_ALERT_POOL`` 时既不会死锁，
也不会出现丢失更新或配额超扣。

锁分片设计避免了「全局大锁」对跨租户读写的阻塞：不同租户、不同配额池
之间互不加锁，同一租户不同配额池之间也仅在确有交集时才产生等待。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

_REGISTRY_LOCK = threading.Lock()
_QUOTA_LOCKS: dict[tuple[str, str], threading.RLock] = {}
_TENANT_LOCKS: dict[str, threading.RLock] = {}

# 锁表容量上限：租户/配额池基数受业务约束，异常输入（伪造租户号）不得
# 无界扩张进程内锁对象数量。
_MAX_LOCK_OBJECTS = 512


def _acquire_registry_lock() -> None:
    _REGISTRY_LOCK.acquire()


def quota_lock(tenant_id: str, quota_type: str) -> threading.RLock:
    """获取（线程可重入的）配额池维度业务锁。"""
    key = (str(tenant_id), str(quota_type))
    with _REGISTRY_LOCK:
        lock = _QUOTA_LOCKS.get(key)
        if lock is None:
            if len(_QUOTA_LOCKS) >= _MAX_LOCK_OBJECTS:
                # 极端基数下复用最旧锁槽，避免锁对象无界增长。
                key = next(iter(_QUOTA_LOCKS))
                lock = _QUOTA_LOCKS[key]
            else:
                lock = threading.RLock()
                _QUOTA_LOCKS[key] = lock
        return lock


def tenant_lock(tenant_id: str) -> threading.RLock:
    """获取租户维度业务锁（用于同一租户内的强一致复合写入）。"""
    key = str(tenant_id)
    with _REGISTRY_LOCK:
        lock = _TENANT_LOCKS.get(key)
        if lock is None:
            if len(_TENANT_LOCKS) >= _MAX_LOCK_OBJECTS:
                key = next(iter(_TENANT_LOCKS))
                lock = _TENANT_LOCKS[key]
            else:
                lock = threading.RLock()
                _TENANT_LOCKS[key] = lock
        return lock


@contextmanager
def quota_locks(tenant_id: str, *quota_types: str) -> Iterator[None]:
    """按全局升序获取多个配额池锁（严格避免交叉调拨死锁）。"""
    unique = sorted({str(q) for q in quota_types if q})
    acquired: list[threading.RLock] = []
    try:
        for quota_type in unique:
            lock = quota_lock(tenant_id, quota_type)
            lock.acquire()
            acquired.append(lock)
        yield
    finally:
        for lock in reversed(acquired):
            try:
                lock.release()
            except RuntimeError:
                pass


@contextmanager
def tenant_write_scope(tenant_id: str, *quota_types: str) -> Iterator[None]:
    """租户写作用域：先租户锁、再配额锁（仍满足全局升序）。"""
    tlock = tenant_lock(tenant_id)
    tlock.acquire()
    try:
        with quota_locks(tenant_id, *quota_types):
            yield
    finally:
        try:
            tlock.release()
        except RuntimeError:
            pass
