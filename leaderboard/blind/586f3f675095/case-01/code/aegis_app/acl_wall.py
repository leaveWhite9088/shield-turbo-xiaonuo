# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎（acl 维度纪元 + 血缘指纹缓存）。

裁决优先级规则（从高到低，与原版逐条一致且有对应回归用例）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（同节点 DENY 优先）；
4. 整条链路均无匹配规则时默认放行（返回 False 表示未封禁）。

性能设计：
* 组织血缘以 (node_id, 全租户父指针链指纹) 为键缓存，层级变更即整体失效，O(1) 命中；
* 单文档的有效规则集合按 (tenant, doc) 缓存，判定时只与调用者个人规则与自身血缘求交，
  **判定成本与该租户文档/规则规模无关**；
* 规则变更只递增 ``acl`` 维度纪元，按代际惰性失效，文档倒排索引完全不受影响。
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

from .config import CACHE_MAX_ACL
from .db import EpochBus, GatewayDB, SharedResources


class WindowAclCache:
    """acl 维度缓存：``(tenant, doc) -> (纪元指纹, {"USER": {...}, "ORG": {...}})``，容量有界。"""

    __slots__ = ("store", "lock")

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], tuple[bytes, dict[str, dict[str, set[str]]]]] = {}
        self.lock = threading.Lock()

    @staticmethod
    def fingerprint(epoch: EpochBus, stamp: int) -> bytes:
        return epoch.get("acl").to_bytes(8, "big") + (stamp & 0xFFFFFFFF).to_bytes(4, "big")

    def rules(self, db: GatewayDB, epoch: EpochBus, stamp: int, tenant_id: str,
              doc_id: str, *, strict: bool = False) -> dict[str, dict[str, set[str]]]:
        key = (tenant_id, doc_id)
        fp = self.fingerprint(epoch, stamp)
        entry = self.store.get(key)
        if entry is not None and entry[0] == fp:
            return entry[1]
        users: dict[str, set[str]] = {}
        orgs: dict[str, set[str]] = {}
        for r in db.rows(
            "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
            (tenant_id, doc_id),
        ):
            st = r["subject_type"]
            eff = str(r["effect"]) if strict else str(r["effect"]).upper()
            if st == "USER":
                users.setdefault(r["subject_id"], set()).add(eff)
            elif st == "ORG_NODE":
                orgs.setdefault(r["subject_id"], set()).add(eff)
        rules = {"USER": users, "ORG": orgs}
        with self.lock:
            if len(self.store) >= CACHE_MAX_ACL:
                for old in list(self.store)[: CACHE_MAX_ACL // 4]:
                    self.store.pop(old, None)
            self.store[key] = (fp, rules)
        return rules


def compute_org_lineage(db: GatewayDB, tenant_id: str, start_node: str) -> tuple[list[str], list[str], dict[str, str | None]]:
    """返回 (从起点到根部的血缘链, 稳定排序的全部节点, 父指针表)。带环保护（visited 集合）。"""
    parents: dict[str, str | None] = {}
    for r in db.rows("SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?", (tenant_id,)):
        parents[r["node_id"]] = r["parent_node_id"]
    lineage: list[str] = []
    curr = start_node
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        curr = parents.get(curr)
    return lineage, sorted(parents), parents


def hierarchy_fingerprint(nodes: list[str], parents: dict[str, str | None]) -> bytes:
    raw = "\x1f".join(f"{n}>{parents.get(n) or ''}" for n in nodes).encode("utf-8")
    return hashlib.blake2b(raw, digest_size=16).digest()


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str, *, shared: SharedResources | None = None) -> list[str]:
    """按由近及远顺序返回组织节点链（共享实例走指纹缓存，否则回源数据库）。"""
    if shared is None or shared.db.path != db_path:
        from .db import open_connection
        conn = open_connection(db_path)
        try:
            parents = {
                r["node_id"]: r["parent_node_id"]
                for r in conn.execute("SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?", (tenant_id,))
            }
        finally:
            conn.close()
        lineage: list[str] = []
        curr = start_node_id
        seen: set[str] = set()
        while curr and curr not in seen:
            seen.add(curr)
            lineage.append(curr)
            curr = parents.get(curr)
        return lineage

    db = shared.db
    lineage, nodes, parents = compute_org_lineage(db, tenant_id, start_node_id)
    fp = hierarchy_fingerprint(nodes, parents)
    key = (tenant_id, start_node_id)
    entry = shared.org_cache.get(key)
    if entry is not None and entry[0] == fp:
        return entry[1]
    with shared.lock:
        if len(shared.org_cache) >= 4096:
            for old in list(shared.org_cache)[:1024]:
                shared.org_cache.pop(old, None)
        shared.org_cache[key] = (fp, lineage)
    return lineage


class WallChecker:
    """单次请求内复用的隔离墙判定器（同一次请求内只解析一次血缘，规则按文档 O(1) 命中）。

    ``strict=True`` 为兼容模式：规则取值/匹配大小写敏感（与原版逐行 SQL 判定的可见行为一致），
    供旧函数签名 ``is_doc_blocked_by_wall(db_path, ...)`` 使用。
    """

    __slots__ = ("shared", "tenant_id", "user_id", "lineage", "strict", "node", "db_path")

    def __init__(self, shared: SharedResources | None, tenant_id: str, user_id: str,
                 org_node_id: str, *, strict: bool = False, node: str | None = None,
                 db_path: str = "") -> None:
        self.shared = shared
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.strict = strict
        self.node = node
        self.db_path = db_path
        if shared is not None:
            self.lineage = get_org_lineage(shared.db.path, tenant_id, org_node_id, shared=shared)
        else:
            self.lineage = []

    @classmethod
    def from_db(cls, db_path: str, tenant_id: str, user_id: str, *, strict: bool = False) -> "WallChecker":
        """兼容入口：按原版顺序查用户所在组织节点（未知/停用用户一律视为封禁）。"""
        from .db import open_connection

        node: str | None = None
        conn = open_connection(db_path)
        try:
            u_row = conn.execute(
                "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
                (tenant_id, user_id),
            ).fetchone()
            if u_row is not None:
                node = u_row["org_node_id"]
        finally:
            conn.close()
        checker = cls(None, tenant_id, user_id, node or "", strict=strict, node=node, db_path=db_path)
        if node is not None:
            checker.lineage = get_org_lineage(db_path, tenant_id, node, shared=None)
        return checker

    def _rules(self, doc_id: str) -> dict[str, dict[str, set[str]]]:
        shared = self.shared
        if shared is not None:
            return shared.acl_cache.rules(
                shared.db, shared.epoch, shared.stamp, self.tenant_id, doc_id, strict=self.strict,
            )
        from .db import open_connection

        conn = open_connection(self.db_path)
        try:
            rows = conn.execute(
                "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
                "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
                (self.tenant_id, doc_id),
            ).fetchall()
        finally:
            conn.close()
        users: dict[str, set[str]] = {}
        orgs: dict[str, set[str]] = {}
        for r in rows:
            eff = str(r["effect"]) if self.strict else str(r["effect"]).upper()
            if r["subject_type"] == "USER":
                users.setdefault(r["subject_id"], set()).add(eff)
            elif r["subject_type"] == "ORG_NODE":
                orgs.setdefault(r["subject_id"], set()).add(eff)
        return {"USER": users, "ORG": orgs}

    def blocked(self, doc_id: str) -> bool:
        if doc_id is None:
            return False
        if self.node is None and self.shared is None:
            return True
        rules = self._rules(doc_id)
        ue = rules["USER"].get(self.user_id)
        if ue:
            if "ALLOW" in ue:
                return False
            if "DENY" in ue:
                return True
        orgs = rules["ORG"]
        if orgs:
            for node_id in self.lineage:
                effs = orgs.get(node_id)
                if effs:
                    return "DENY" in effs
        return False


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str, *,
                           org_node_id: str | None = None,
                           shared: SharedResources | None = None,
                           checker: WallChecker | None = None) -> bool:
    """按三级优先级判定操作员是否被隔离墙禁止访问目标文档（兼容入口）。"""
    from .db import open_connection

    if checker is None:
        checker = WallChecker.from_db(db_path, tenant_id, user_id, strict=True)
    if checker is not None:
        return checker.blocked(doc_id)
    if shared is None or shared.db.path != db_path:
        conn = open_connection(db_path)
        try:
            u_row = conn.execute(
                "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
                (tenant_id, user_id),
            ).fetchone()
            acl_rows = conn.execute(
                "SELECT subject_type, subject_id, effect FROM doc_acl_rules "
                "WHERE tenant_id = ? AND doc_id = ? AND active = 1",
                (tenant_id, doc_id),
            ).fetchall()
        finally:
            conn.close()
        if not u_row:
            return True
        user_effects = {str(r["effect"]).upper() for r in acl_rows
                        if r["subject_type"] == "USER" and r["subject_id"] == user_id}
        if "ALLOW" in user_effects:
            return False
        if "DENY" in user_effects:
            return True
        org_effects: dict[str, set[str]] = {}
        for r in acl_rows:
            if r["subject_type"] == "ORG_NODE":
                org_effects.setdefault(r["subject_id"], set()).add(str(r["effect"]).upper())
        for node_id in get_org_lineage(db_path, tenant_id, u_row["org_node_id"]):
            effs = org_effects.get(node_id)
            if effs:
                return "DENY" in effs
        return False
    if org_node_id is None:
        return True
    return WallChecker(shared, tenant_id, user_id, org_node_id).blocked(doc_id)


def upsert_doc_acl_rule(
    db_path: str,
    tenant_id: str,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
    db: GatewayDB | None = None,
    epoch: EpochBus | None = None,
    now_ts: int | None = None,
) -> dict[str, Any]:
    """配置或停用文档利益冲突隔离墙规则（支持 USER / ORG_NODE 与 DENY / ALLOW）。"""
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")
    stamp = int(now_ts if now_ts is not None else time.time())

    def _apply(conn) -> None:
        doc_row = conn.execute(
            "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchone()
        if not doc_row:
            raise LookupError(f"Document not found in tenant: {doc_id}")
        if active:
            conn.execute(
                "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 1, ?)",
                (tenant_id, doc_id, norm_type, subject_id, norm_effect, stamp),
            )
        else:
            conn.execute(
                "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                (stamp, tenant_id, doc_id, norm_type, subject_id, norm_effect),
            )

    if db is not None and db.path == db_path:
        db.write(_apply)
        if epoch is not None:
            epoch.bump("acl")
    else:
        from .db import open_connection
        conn = open_connection(db_path)
        try:
            _apply(conn)
            conn.commit()
        finally:
            conn.close()

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }

