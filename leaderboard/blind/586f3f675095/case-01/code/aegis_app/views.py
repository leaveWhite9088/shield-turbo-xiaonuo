# -*- coding: utf-8 -*-
"""按需正文词位缓存与检索视图惰性包装（正文不常驻、按命中热度限量缓存）。"""
from __future__ import annotations

import threading
from typing import Any

from .config import HOT_VIEW_MAX, HOT_VIEW_TTL_SECONDS


class HotViewCache:
    """命中文档正文的“词 -> 词位列表”缓存：LRU + TTL，自动淘汰最久未用项。"""

    __slots__ = ("data", "order", "limit", "ttl", "lock")

    def __init__(self, limit: int = HOT_VIEW_MAX, ttl: int = HOT_VIEW_TTL_SECONDS) -> None:
        self.data: dict[str, tuple[float, dict[str, list[int]]]] = {}
        self.order: dict[str, None] = {}
        self.limit = limit
        self.ttl = ttl
        self.lock = threading.Lock()

    def get(self, doc_id: str) -> dict[str, list[int]] | None:
        import time
        entry = self.data.get(doc_id)
        if entry is None:
            return None
        stamp, payload = entry
        if time.monotonic() - stamp > self.ttl:
            with self.lock:
                self.data.pop(doc_id, None)
                self.order.pop(doc_id, None)
            return None
        self.order[doc_id] = None
        return payload

    def put(self, doc_id: str, payload: dict[str, list[int]]) -> None:
        import time
        with self.lock:
            self.data[doc_id] = (time.monotonic(), payload)
            self.order[doc_id] = None
            if len(self.order) > self.limit:
                excess = len(self.order) - self.limit
                for old in list(self.order)[:excess]:
                    self.order.pop(old, None)
                    self.data.pop(old, None)

    def drop(self, doc_id: str) -> None:
        with self.lock:
            self.data.pop(doc_id, None)
            self.order.pop(doc_id, None)

    def clear(self) -> None:
        with self.lock:
            self.data.clear()
            self.order.clear()


_HOT = HotViewCache()
_ACTIVE: "HotViewCache | None" = None      # 当前网关实例的正文词位缓存（供按 doc_id 寻址的消费方）
_CALLER = threading.local()


def set_active_views(cache: HotViewCache) -> None:
    global _ACTIVE
    _ACTIVE = cache


def current_caller() -> Any:
    """当前线程正在处理的调用方上下文（由请求入口显式绑定，不跨请求泄漏）。"""
    return getattr(_CALLER, "caller", None)


def bind_caller(caller: Any) -> None:
    _CALLER.caller = caller


def hot_views() -> HotViewCache:
    return _ACTIVE if _ACTIVE is not None else _HOT


class LazyDocumentIndex:
    """首次访问某租户时才从 SQLite 增量装载其倒排视图（避免启动期全库拉取）。"""

    __slots__ = ("inner", "loader", "loaded", "lock", "epoch")

    def __init__(self, inner: Any, loader) -> None:
        self.inner = inner
        self.loader = loader
        self.loaded: set[str] = set()
        self.lock = threading.Lock()
        self.epoch = inner.epoch

    def view(self, tenant_id: str):
        if tenant_id in self.loaded:
            return self.inner.view(tenant_id)
        with self.lock:
            if tenant_id not in self.loaded:
                self.loader(tenant_id)
                self.loaded.add(tenant_id)
        return self.inner.view(tenant_id)

    def __getattr__(self, name: str):
        return getattr(self.inner, name)
