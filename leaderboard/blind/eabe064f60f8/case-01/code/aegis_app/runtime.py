# -*- coding: utf-8 -*-
"""分租户多维版本戳缓存、倒排索引视图与细粒度并发控制运行时。"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import pathlib
import threading
from typing import Any


@dataclass(slots=True)
class IndexedDoc:
    """预分词与预聚合引用的只读合规文档索引条目。"""

    idx: int
    doc_id: str
    category: str
    regulation_code: str
    clearance_level: int
    risk_weight: int
    custom_tag: str
    title: str
    snippet: str
    citation_count: int
    base_score: float
    updated_at: int
    title_tf_capped: dict[str, int]
    body_tf_capped: dict[str, int]
    token_set: frozenset[str]
    token_set_len: int


@dataclass(slots=True)
class TenantDocIndex:
    """租户级内存倒排索引与属性过滤索引（绑定 doc_epoch）。"""

    epoch: int
    docs: list[IndexedDoc]
    inverted: dict[str, list[int]]
    by_category: dict[str, frozenset[int]]
    by_tag: dict[str, frozenset[int]]


@dataclass(slots=True)
class TenantAclSnapshot:
    """租户级利益冲突隔离墙（Chinese Wall）DENY 规则快照（绑定 acl_epoch）。"""

    epoch: int
    user_denies: dict[str, frozenset[str]]
    org_denies: dict[str, frozenset[str]]


@dataclass(slots=True)
class OrgTreeSnapshot:
    """租户组织架构树预计算快照：每个节点对应完整祖先链与继承角色集合。"""

    ancestors_by_node: dict[str, tuple[str, ...]]
    inherited_roles_by_node: dict[str, frozenset[str]]


@dataclass(slots=True)
class CachedUserRecord:
    user_id: str
    tenant_id: str
    username: str
    org_node_id: str
    base_role: str
    api_token_hash: str
    active: int


class TenantRuntime:
    """单租户隔离运行时：独立锁、独立版本戳与有界安全隔离缓存。"""

    SEARCH_LRU_CAPACITY = 256

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.lock = threading.RLock()
        self._resource_locks: dict[str, threading.Lock] = {}

        # 多维单调递增版本戳（CAS 校验防并发撤权/隔离后的旧读回填竞态）
        self.doc_epoch: int = 0
        self.perm_epoch: int = 0
        self.acl_epoch: int = 0
        self.policy_epoch: int = 0

        # 缓存槽
        self.tenant_info: tuple[str, str] | None = None  # (status, webhook_secret)
        self.org_tree: OrgTreeSnapshot | None = None
        self.users: dict[str, CachedUserRecord] = {}
        self.perm_cache: dict[str, tuple[int, frozenset[str], int]] = {}  # user_id -> (perm_epoch, roles, max_cl)
        self.acl_snapshot: TenantAclSnapshot | None = None
        self.doc_index: TenantDocIndex | None = None
        self.policy_snapshot: tuple[int, dict[str, Any]] | None = None  # (policy_epoch, policy_dict)
        self.search_lru: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()

    def get_resource_lock(self, resource_key: str) -> threading.Lock:
        """获取租户内按资源键分片的细粒度锁（用于配额扣减、令牌核销等，绝不阻塞跨租户或不同资源）。"""
        with self.lock:
            lk = self._resource_locks.get(resource_key)
            if lk is None:
                lk = threading.Lock()
                self._resource_locks[resource_key] = lk
            return lk

    def get_search_epochs(self) -> tuple[int, int, int]:
        with self.lock:
            return self.doc_epoch, self.perm_epoch, self.acl_epoch

    def bump_doc_epoch(self) -> int:
        with self.lock:
            self.doc_epoch += 1
            self.doc_index = None
            self.search_lru.clear()
            return self.doc_epoch

    def bump_perm_epoch(self) -> int:
        with self.lock:
            self.perm_epoch += 1
            self.perm_cache.clear()
            self.search_lru.clear()
            return self.perm_epoch

    def bump_acl_epoch(self) -> int:
        with self.lock:
            self.acl_epoch += 1
            self.acl_snapshot = None
            self.search_lru.clear()
            return self.acl_epoch

    def bump_policy_epoch(self) -> int:
        with self.lock:
            self.policy_epoch += 1
            self.policy_snapshot = None
            return self.policy_epoch

    def get_cached_perm(self, user_id: str) -> tuple[frozenset[str], int] | None:
        with self.lock:
            entry = self.perm_cache.get(user_id)
            if entry is not None and entry[0] == self.perm_epoch:
                return entry[1], entry[2]
            return None

    def put_cached_perm(self, user_id: str, expected_epoch: int, roles: frozenset[str], max_cl: int) -> None:
        with self.lock:
            if self.perm_epoch == expected_epoch:
                self.perm_cache[user_id] = (expected_epoch, roles, max_cl)

    def get_cached_acl(self) -> TenantAclSnapshot | None:
        with self.lock:
            snap = self.acl_snapshot
            if snap is not None and snap.epoch == self.acl_epoch:
                return snap
            return None

    def put_cached_acl(self, snap: TenantAclSnapshot) -> None:
        with self.lock:
            if self.acl_epoch == snap.epoch:
                self.acl_snapshot = snap

    def get_cached_doc_index(self) -> TenantDocIndex | None:
        with self.lock:
            idx = self.doc_index
            if idx is not None and idx.epoch == self.doc_epoch:
                return idx
            return None

    def put_cached_doc_index(self, idx: TenantDocIndex) -> None:
        with self.lock:
            if self.doc_epoch == idx.epoch:
                self.doc_index = idx

    def get_cached_policy(self) -> dict[str, Any] | None:
        with self.lock:
            snap = self.policy_snapshot
            if snap is not None and snap[0] == self.policy_epoch:
                return snap[1]
            return None

    def put_cached_policy(self, expected_epoch: int, policy: dict[str, Any]) -> None:
        with self.lock:
            if self.policy_epoch == expected_epoch:
                self.policy_snapshot = (expected_epoch, policy)

    def get_search_lru(self, cache_key: tuple[Any, ...]) -> dict[str, Any] | None:
        with self.lock:
            hit = self.search_lru.get(cache_key)
            if hit is not None:
                self.search_lru.move_to_end(cache_key)
                return hit
            return None

    def put_search_lru(
        self,
        cache_key: tuple[Any, ...],
        expected_epochs: tuple[int, int, int],
        value: dict[str, Any],
    ) -> None:
        with self.lock:
            if (self.doc_epoch, self.perm_epoch, self.acl_epoch) != expected_epochs:
                return
            self.search_lru[cache_key] = value
            self.search_lru.move_to_end(cache_key)
            while len(self.search_lru) > self.SEARCH_LRU_CAPACITY:
                self.search_lru.popitem(last=False)


class DatabaseRuntime:
    """按 SQLite 文件路径隔离的数据库运行时，管理所有分租户 TenantRuntime。"""

    def __init__(self, norm_db_path: str) -> None:
        self.db_path = norm_db_path
        self._lock = threading.Lock()
        self._tenants: dict[str, TenantRuntime] = {}

    def tenant(self, tenant_id: str) -> TenantRuntime:
        tr = self._tenants.get(tenant_id)
        if tr is not None:
            return tr
        with self._lock:
            tr = self._tenants.get(tenant_id)
            if tr is None:
                tr = TenantRuntime(tenant_id)
                self._tenants[tenant_id] = tr
            return tr

    def clear(self) -> None:
        with self._lock:
            self._tenants.clear()


_REG_LOCK = threading.Lock()
_DB_RUNTIMES: dict[str, DatabaseRuntime] = {}


def get_db_runtime(db_path: str | pathlib.Path) -> DatabaseRuntime:
    norm = str(pathlib.Path(db_path).resolve())
    rt = _DB_RUNTIMES.get(norm)
    if rt is not None:
        return rt
    with _REG_LOCK:
        rt = _DB_RUNTIMES.get(norm)
        if rt is None:
            rt = DatabaseRuntime(norm)
            _DB_RUNTIMES[norm] = rt
        return rt


def reset_db_runtime(db_path: str | pathlib.Path) -> None:
    """在数据库被重新初始化（如 seed_dataset）时清空对应路径的内存缓存。"""
    norm = str(pathlib.Path(db_path).resolve())
    with _REG_LOCK:
        rt = _DB_RUNTIMES.pop(norm, None)
        if rt is not None:
            rt.clear()
