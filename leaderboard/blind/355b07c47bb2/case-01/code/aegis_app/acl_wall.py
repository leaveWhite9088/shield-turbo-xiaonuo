# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）内存索引裁决引擎。

裁决优先级规则（从高到低）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。
"""
from __future__ import annotations

import time
from typing import Any

from .runtime import GatewayRuntime, get_runtime


class TenantOrgCache:
    """租户组织树祖先链与继承角色内存快照（防环路）。"""

    __slots__ = ("lineages", "inherited_roles", "parents")

    def __init__(self) -> None:
        self.parents: dict[str, str | None] = {}
        self.lineages: dict[str, tuple[str, ...]] = {}
        self.inherited_roles: dict[str, frozenset[str]] = {}

    @classmethod
    def load(cls, rt: GatewayRuntime, tenant_id: str) -> "TenantOrgCache":
        obj = cls()
        node_role: dict[str, str | None] = {}
        with rt.read_conn() as conn:
            rows = conn.execute(
                "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
        for r in rows:
            nid = str(r["node_id"])
            obj.parents[nid] = str(r["parent_node_id"]) if r["parent_node_id"] else None
            node_role[nid] = str(r["inherited_role"]) if r["inherited_role"] else None

        for nid in obj.parents:
            lineage: list[str] = []
            roles: set[str] = set()
            curr: str | None = nid
            visited: set[str] = set()
            while curr and curr not in visited:
                visited.add(curr)
                lineage.append(curr)
                ir = node_role.get(curr)
                if ir:
                    roles.add(ir)
                curr = obj.parents.get(curr)
            obj.lineages[nid] = tuple(lineage)
            obj.inherited_roles[nid] = frozenset(roles)
        return obj

    def get_lineage(self, start_node_id: str) -> tuple[str, ...]:
        lin = self.lineages.get(start_node_id)
        if lin is not None:
            return lin
        return (start_node_id,) if start_node_id else ()

    def get_inherited_roles(self, start_node_id: str) -> frozenset[str]:
        return self.inherited_roles.get(start_node_id, frozenset())


class TenantAclIndex:
    """按文档分桶的隔离墙内存规则索引（与 doc_epoch 及倒排索引完全解耦）。"""

    __slots__ = ("rules_by_doc",)

    def __init__(self) -> None:
        # doc_id -> (user_effects: {uid: set[str]}, org_effects: {node_id: set[str]})
        self.rules_by_doc: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]] = {}

    @classmethod
    def load(cls, rt: GatewayRuntime, tenant_id: str) -> "TenantAclIndex":
        idx = cls()
        with rt.read_conn() as conn:
            rows = conn.execute(
                "SELECT doc_id, subject_type, subject_id, effect "
                "FROM doc_acl_rules WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
        for r in rows:
            idx.apply_rule(
                str(r["doc_id"]),
                str(r["subject_type"]).upper(),
                str(r["subject_id"]),
                str(r["effect"]).upper(),
                active=True,
            )
        return idx

    def apply_rule(
        self,
        doc_id: str,
        subject_type: str,
        subject_id: str,
        effect: str,
        *,
        active: bool,
    ) -> None:
        entry = self.rules_by_doc.get(doc_id)
        if active:
            if entry is None:
                entry = ({}, {})
                self.rules_by_doc[doc_id] = entry
            target_map = entry[0] if subject_type == "USER" else entry[1]
            effs = target_map.get(subject_id)
            if effs is None:
                effs = set()
                target_map[subject_id] = effs
            effs.add(effect)
        else:
            if entry is None:
                return
            target_map = entry[0] if subject_type == "USER" else entry[1]
            effs = target_map.get(subject_id)
            if effs is not None:
                effs.discard(effect)
                if not effs:
                    target_map.pop(subject_id, None)
            if not entry[0] and not entry[1]:
                self.rules_by_doc.pop(doc_id, None)

    def is_blocked(self, user_id: str, org_lineage: tuple[str, ...], doc_id: str) -> bool:
        entry = self.rules_by_doc.get(doc_id)
        if entry is None:
            return False
        user_map, org_map = entry
        user_effs = user_map.get(user_id)
        if user_effs:
            if "ALLOW" in user_effs:
                return False
            if "DENY" in user_effs:
                return True
        if org_map:
            for node_id in org_lineage:
                effs = org_map.get(node_id)
                if effs:
                    if "DENY" in effs:
                        return True
                    if "ALLOW" in effs:
                        return False
        return False


def get_org_cache(db_path: str, tenant_id: str) -> TenantOrgCache:
    rt = get_runtime(db_path)
    cached = rt.org_cache.get(tenant_id)
    if cached is not None:
        return cached
    with rt.acl_lock(tenant_id):
        cached = rt.org_cache.get(tenant_id)
        if cached is None:
            cached = TenantOrgCache.load(rt, tenant_id)
            rt.org_cache[tenant_id] = cached
        return cached


def get_acl_index(db_path: str, tenant_id: str) -> TenantAclIndex:
    rt = get_runtime(db_path)
    idx = rt.acl_indices.get(tenant_id)
    if idx is not None:
        return idx
    with rt.acl_lock(tenant_id):
        idx = rt.acl_indices.get(tenant_id)
        if idx is None:
            idx = TenantAclIndex.load(rt, tenant_id)
            rt.acl_indices[tenant_id] = idx
        return idx


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    return list(get_org_cache(db_path, tenant_id).get_lineage(start_node_id))


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    rt = get_runtime(db_path)
    u_info = rt.users_cache.get((tenant_id, user_id))
    if u_info is None:
        with rt.read_conn() as conn:
            u_row = conn.execute(
                "SELECT org_node_id, active FROM users WHERE tenant_id = ? AND user_id = ?",
                (tenant_id, user_id),
            ).fetchone()
        if not u_row or not int(u_row["active"]):
            return True
        org_node_id = str(u_row["org_node_id"])
    else:
        if not u_info["active"]:
            return True
        org_node_id = str(u_info["org_node_id"])

    lineage = get_org_cache(db_path, tenant_id).get_lineage(org_node_id)
    with rt.acl_lock(tenant_id):
        idx = get_acl_index(db_path, tenant_id)
        return idx.is_blocked(user_id, lineage, doc_id)


def upsert_doc_acl_rule(
    db_path: str,
    tenant_id: str,
    *,
    doc_id: str,
    subject_type: str,
    subject_id: str,
    effect: str = "DENY",
    active: bool = True,
) -> dict[str, Any]:
    """配置或停用文档利益冲突隔离墙规则，仅增量更新 ACL 索引并递增 acl_epoch（绝不重建文档倒排索引）。"""
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    norm_doc_id = str(doc_id or "").strip()
    norm_subject_id = str(subject_id or "").strip()
    if not norm_doc_id or not norm_subject_id:
        raise ValueError("doc_id and subject_id are required")
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")

    now_ts = int(time.time())
    rt = get_runtime(db_path)
    with rt.acl_lock(tenant_id):
        with rt.write_tx() as conn:
            doc_row = conn.execute(
                "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, norm_doc_id),
            ).fetchone()
            if not doc_row:
                raise LookupError(f"Document not found in tenant: {norm_doc_id}")

            if active:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, norm_doc_id, norm_type, norm_subject_id, norm_effect, now_ts),
                )
            else:
                conn.execute(
                    "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                    "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                    (now_ts, tenant_id, norm_doc_id, norm_type, norm_subject_id, norm_effect),
                )

        # 仅增量更新本租户内存 ACL 索引并递增 acl_epoch，彻底解耦 doc_epoch 与倒排索引
        idx = rt.acl_indices.get(tenant_id)
        if idx is not None:
            idx.apply_rule(norm_doc_id, norm_type, norm_subject_id, norm_effect, active=bool(active))
        rt.epochs(tenant_id).acl_epoch += 1

    return {
        "tenant_id": tenant_id,
        "doc_id": norm_doc_id,
        "subject_type": norm_type,
        "subject_id": norm_subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
