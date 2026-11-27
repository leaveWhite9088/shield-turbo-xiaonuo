# -*- coding: utf-8 -*-
"""按数据库/租户分片的锁、短寿命纪元与有界 LRU 运行时缓存。

所有缓存只保存小型权限元数据；文档正文与风控大表不进入这里。纪元按
ACL 与认证/委托分别失效，避免修改一条隔离墙规则清空文档索引。
"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
import hashlib
import pathlib
import threading
from typing import Any, Iterator


def db_key(db_path: str) -> str:
    return str(pathlib.Path(db_path).resolve())


class _BoundedLRU:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._lock = threading.RLock()
        self._values: OrderedDict[Any, Any] = OrderedDict()

    def get(self, key: Any, epoch: int) -> Any | None:
        with self._lock:
            item = self._values.get(key)
            if item is None or item[0] != epoch:
                return None
            self._values.move_to_end(key)
            return item[1]

    def put(self, key: Any, epoch: int, value: Any) -> None:
        with self._lock:
            self._values[key] = (epoch, value)
            self._values.move_to_end(key)
            while len(self._values) > self.capacity:
                self._values.popitem(last=False)

    def clear_tenant(self, db: str, tenant_id: str) -> None:
        with self._lock:
            for key in [k for k in self._values if k[:2] == (db, tenant_id)]:
                self._values.pop(key, None)


class RuntimeRegistry:
    """全局注册表只保存固定数量的分片锁和缓存元数据，不持有业务大对象。"""

    def __init__(self) -> None:
        self._epoch_lock = threading.RLock()
        self._epochs: dict[tuple[str, str, str], int] = {}
        self._tenant_locks: list[threading.RLock] = [threading.RLock() for _ in range(256)]
        self.base_roles = _BoundedLRU(2048)
        self.delegations = _BoundedLRU(128)
        self.acl_rules = _BoundedLRU(128)
        self.org_lineage = _BoundedLRU(2048)

    def epoch(self, db_path: str, tenant_id: str, domain: str) -> int:
        key = (db_key(db_path), tenant_id, domain)
        with self._epoch_lock:
            return self._epochs.get(key, 0)

    def bump(self, db_path: str, tenant_id: str, domain: str) -> int:
        db = db_key(db_path)
        key = (db, tenant_id, domain)
        with self._epoch_lock:
            value = self._epochs.get(key, 0) + 1
            self._epochs[key] = value
        if domain == "auth":
            self.base_roles.clear_tenant(db, tenant_id)
            self.delegations.clear_tenant(db, tenant_id)
        elif domain == "acl":
            self.acl_rules.clear_tenant(db, tenant_id)
        return value

    @contextmanager
    def tenant_write(self, db_path: str, tenant_id: str) -> Iterator[None]:
        """统一锁偏序：租户分片 Python 锁 -> SQLite BEGIN IMMEDIATE。

        配额 consume/transfer/evaluate-batch 均走同一把分片锁；不在 SQLite
        写事务内再获取其他 Python 锁，跨租户操作不相互阻塞。
        """
        db = db_key(db_path)
        digest = hashlib.blake2s(f"{db}\0{tenant_id}".encode("utf-8"), digest_size=8).digest()
        lock = self._tenant_locks[int.from_bytes(digest, "big") % len(self._tenant_locks)]
        lock.acquire()
        try:
            yield
        finally:
            lock.release()


RUNTIME = RuntimeRegistry()
