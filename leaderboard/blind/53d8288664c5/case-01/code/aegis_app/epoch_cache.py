# -*- coding: utf-8 -*-
"""全局多租户纪元失效缓存注册中心（线程安全、零脏读、有界常驻内存）。

设计契约：
- 每个可变业务域（role_grants / delegation / acl / docs / citations / policy /
  sanctions / quotas / webhook ...）拥有一个按 (db_path, domain) 寻址的单调递增
  纪元计数器；
- 任何写入方在事务提交之后必须立即 bump_epoch() 使对应域纪元 +1；
- 读方缓存条目以 (db_key, 纪元组合 token, 业务键) 寻址：纪元一变旧条目自动失联，
  并在容量超限时被批量清扫，从而在零锁竞争放大的前提下保证跨模块联动零脏读；
- users / org_nodes 为挂载后无写入路由的静态数据，以 "org"+"users" 纪元
  （恒为 0）缓存租户静态组织图与用户档案，供权限/隔离墙/借调模块共享复用。
"""
from __future__ import annotations

import threading
from typing import Any

from .db import open_connection

_lock = threading.RLock()
_epoch_counters: dict[tuple[str, str], int] = {}

CACHE_MISS = object()


def bump_epoch(db_path: str, *domains: str) -> None:
    """写入方提交变更后使指定业务域纪元 +1，令相关读缓存全部失效。"""
    if not domains:
        return
    db_key = str(db_path)
    with _lock:
        for domain in domains:
            k = (db_key, domain)
            _epoch_counters[k] = _epoch_counters.get(k, 0) + 1


def epoch_token(db_path: str, *domains: str) -> tuple[int, ...]:
    """读取若干业务域的当前纪元组合，作为读缓存的作用域令牌。"""
    db_key = str(db_path)
    with _lock:
        return tuple(_epoch_counters.get((db_key, d), 0) for d in domains)


class EpochScopedCache:
    """以 (db_key, epoch_token) 为作用域的有界线程安全缓存。

    超过容量上限时优先清扫同库陈旧纪元条目，仍超限则按插入序淘汰最旧条目，
    保证常驻堆内存有界。
    """

    __slots__ = ("name", "max_entries", "_data")

    def __init__(self, name: str, max_entries: int = 8192) -> None:
        self.name = name
        self.max_entries = max(64, int(max_entries))
        self._data: dict[tuple[str, tuple[int, ...], Any], Any] = {}

    def get(self, db_key: str, token: tuple[int, ...], key: Any) -> Any:
        with _lock:
            return self._data.get((db_key, token, key), CACHE_MISS)

    def put(self, db_key: str, token: tuple[int, ...], key: Any, value: Any) -> None:
        with _lock:
            self._data[(db_key, token, key)] = value
            if len(self._data) > self.max_entries:
                self._sweep(db_key, token)

    def _sweep(self, db_key: str, token: tuple[int, ...]) -> None:
        data = self._data
        for k in [k for k in data if k[0] == db_key and k[1] != token]:
            del data[k]
        while len(data) > self.max_entries:
            data.pop(next(iter(data)))


_static_cache = EpochScopedCache("tenant_static", 256)


def load_tenant_static(db_path: str, tenant_id: str) -> dict[str, Any]:
    """加载租户静态组织图与用户档案（users / org_nodes 挂载后无写入路由）。

    返回结构：
        users: {user_id: (active:int, org_node_id:str|None, base_role:str)}
        org:   {node_id: (parent_node_id:str|None, inherited_role:str)}
    """
    db_key = str(db_path)
    token = epoch_token(db_path, "org", "users")
    hit = _static_cache.get(db_key, token, tenant_id)
    if hit is not CACHE_MISS:
        return hit

    conn = open_connection(db_path)
    try:
        u_rows = conn.execute(
            "SELECT user_id, org_node_id, base_role, active FROM users WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        n_rows = conn.execute(
            "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    static = {
        "users": {
            str(r["user_id"]): (int(r["active"]), r["org_node_id"], str(r["base_role"] or ""))
            for r in u_rows
        },
        "org": {
            str(r["node_id"]): (r["parent_node_id"], str(r["inherited_role"] or ""))
            for r in n_rows
        },
    }
    _static_cache.put(db_key, token, tenant_id, static)
    return static
