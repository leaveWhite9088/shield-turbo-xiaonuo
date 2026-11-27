# -*- coding: utf-8 -*-
"""多维纪元（Epoch）解耦的运行时状态与租户级缓存注册中心。

原实现把「组织树 / 用户角色 / 隔离墙规则 / 借调委托 / 制裁名单 / 租户策略 /
文档索引」全部当作无状态数据在每次调用中反复全表查询，既造成查询放大，
也无法在高频动态权限切换下做到「零脏读」。

本模块为每个业务域引入 **独立纪元计数器**：

    * 文档域（compliance_docs + doc_citations）—— doc epoch
    * 隔离墙域（doc_acl_rules）—— acl epoch
    * 权限域（users / org_nodes / role_grants）—— org epoch
    * 借调域（delegation_grants）—— deleg epoch
    * 黑名单域（sanctioned_entities）—— sanction epoch
    * 策略域（tenant_policies）—— policy epoch

各域纪元 **互不牵连**：修改单条 ``doc-acl`` 规则只推进 acl 纪元，
不会清空文档倒排索引；撤销角色只推进 org 纪元，不会使文档索引失效。
写路径推进纪元后，对应域的缓存在下一次访问时按纪元惰性失效重建，
从而在不引入全局大锁的前提下保证跨模块实时一致性。
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Callable

DOMAIN_ORG = "org"
DOMAIN_ACL = "acl"
DOMAIN_DELEG = "deleg"
DOMAIN_SANCTION = "sanction"
DOMAIN_POLICY = "policy"
DOMAIN_DOC = "doc"

_ALL_DOMAINS = (
    DOMAIN_ORG,
    DOMAIN_ACL,
    DOMAIN_DELEG,
    DOMAIN_SANCTION,
    DOMAIN_POLICY,
    DOMAIN_DOC,
)

# 运行时缓存注册中心容量上限（不同库路径的网关实例数受限，避免无界增长）。
_MAX_RUNTIME_STATES = 4


class TenantRuntime:
    """单租户的多维纪元与缓存槽。"""

    __slots__ = ("tenant_id", "_epochs", "_caches", "_lock")

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._epochs: dict[str, int] = {domain: 0 for domain in _ALL_DOMAINS}
        self._caches: dict[str, tuple[int, Any]] = {}
        self._lock = threading.RLock()

    def epoch(self, domain: str) -> int:
        return self._epochs.get(domain, 0)

    def bump(self, domain: str) -> int:
        """推进某业务域纪元（该域缓存随即惰性失效），其余域不受影响。"""
        with self._lock:
            value = self._epochs.get(domain, 0) + 1
            self._epochs[domain] = value
            self._caches.pop(domain, None)
            return value

    def cached(self, domain: str, builder: Callable[[], Any]) -> Any:
        """按纪元读取缓存；纪元不匹配时重建并登记。"""
        return self.cached_sig(domain, None, builder)

    def cached_sig(self, domain: str, sig: Any, builder: Callable[[], Any]) -> Any:
        """按（纪元 + 轻量签名）读取缓存。

        ``sig`` 为一次廉价聚合查询得到的结构指纹（如计数/最大时间戳），
        用于感知「绕过本进程写路径的外部数据库改动」，避免陈旧缓存长期滞留。
        """
        current = self.epoch(domain)
        entry = self._caches.get(domain)
        if entry is not None and entry[0] == current and entry[1] == sig:
            return entry[2]
        with self._lock:
            entry = self._caches.get(domain)
            if entry is not None and entry[0] == current and entry[1] == sig:
                return entry[2]
            value = builder()
            self._caches[domain] = (current, sig, value)
            return value

    def invalidate(self, domain: str) -> None:
        with self._lock:
            self._caches.pop(domain, None)

    def refresh_sig(self, domain: str, sig: Any, value: Any) -> None:
        """本进程写路径完成后刷新缓存签名（保持缓存对象不变，仅更新指纹）。"""
        with self._lock:
            current = self.epoch(domain)
            entry = self._caches.get(domain)
            if entry is not None and entry[0] == current and entry[2] is value:
                self._caches[domain] = (current, sig, value)

    def peek(self, domain: str) -> Any:
        """取出当前纪元下的缓存对象（不触发重建），用于写路径做增量更新。"""
        current = self.epoch(domain)
        entry = self._caches.get(domain)
        if entry is not None and entry[0] == current:
            return entry[2]
        return None


class RuntimeState:
    """单个数据库文件的运行时状态容器（按租户再分片）。"""

    __slots__ = ("db_path", "_tenants", "_lock")

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._tenants: dict[str, TenantRuntime] = {}
        self._lock = threading.RLock()

    def tenant(self, tenant_id: str) -> TenantRuntime:
        with self._lock:
            runtime = self._tenants.get(tenant_id)
            if runtime is None:
                runtime = TenantRuntime(tenant_id)
                self._tenants[tenant_id] = runtime
            return runtime

    def bump(self, tenant_id: str, domain: str) -> int:
        return self.tenant(tenant_id).bump(domain)

    def epoch(self, tenant_id: str, domain: str) -> int:
        return self.tenant(tenant_id).epoch(domain)

    def cached(self, tenant_id: str, domain: str, builder: Callable[[], Any]) -> Any:
        return self.tenant(tenant_id).cached(domain, builder)


_STATE_LOCK = threading.Lock()
_RUNTIME_STATES: "OrderedDict[str, RuntimeState]" = OrderedDict()


def get_runtime_state(db_path: str) -> RuntimeState:
    """获取（并登记）指定数据库的运行时状态；注册中心容量有界（LRU）。"""
    key = str(db_path)
    with _STATE_LOCK:
        state = _RUNTIME_STATES.get(key)
        if state is not None:
            _RUNTIME_STATES.move_to_end(key)
            return state
        state = RuntimeState(key)
        _RUNTIME_STATES[key] = state
        while len(_RUNTIME_STATES) > _MAX_RUNTIME_STATES:
            _RUNTIME_STATES.popitem(last=False)
        return state
