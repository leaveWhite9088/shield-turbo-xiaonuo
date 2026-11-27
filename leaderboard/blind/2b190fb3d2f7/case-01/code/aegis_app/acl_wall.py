# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎（独立 acl_epoch 缓存解耦）。

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

from .db import borrow_connection, write_transaction
from .runtime_state import get_runtime


class AclSnapshot:
    """租户级隔离墙只读快照，仅绑定 acl_epoch（与文档倒排索引 doc_epoch 彻底解耦）。"""

    __slots__ = ("org_lineage", "user_org", "doc_rules")

    def __init__(
        self,
        org_lineage: dict[str, tuple[str, ...]],
        user_org: dict[str, str],
        doc_rules: dict[str, tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]],
    ) -> None:
        self.org_lineage = org_lineage
        self.user_org = user_org
        self.doc_rules = doc_rules


def _build_org_lineages(parent_map: dict[str, str | None]) -> dict[str, tuple[str, ...]]:
    lineages: dict[str, tuple[str, ...]] = {}
    for node_id in parent_map:
        chain: list[str] = []
        curr: str | None = node_id
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            chain.append(curr)
            curr = parent_map.get(curr)
        lineages[node_id] = tuple(chain)
    return lineages


def get_acl_snapshot(db_path: str, tenant_id: str) -> AclSnapshot:
    rt = get_runtime(db_path)
    tstate = rt.get_tenant(tenant_id)
    snap = tstate.acl_snapshot
    if snap is not None and tstate.acl_snapshot_epoch == tstate.acl_epoch:
        return snap

    with tstate.acl_lock:
        if tstate.acl_snapshot is not None and tstate.acl_snapshot_epoch == tstate.acl_epoch:
            return tstate.acl_snapshot

        target_epoch = tstate.acl_epoch
        with borrow_connection(db_path) as conn:
            org_rows = conn.execute(
                "SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchall()
            user_rows = conn.execute(
                "SELECT user_id, org_node_id FROM users WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()
            rule_rows = conn.execute(
                "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
                "WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            ).fetchall()

        parent_map: dict[str, str | None] = {
            str(r["node_id"]): (str(r["parent_node_id"]) if r["parent_node_id"] else None)
            for r in org_rows
        }
        org_lineage = _build_org_lineages(parent_map)
        user_org = {str(r["user_id"]): str(r["org_node_id"]) for r in user_rows}

        raw_user: dict[str, dict[str, set[str]]] = {}
        raw_org: dict[str, dict[str, set[str]]] = {}
        doc_ids_seen: set[str] = set()
        for r in rule_rows:
            did = str(r["doc_id"])
            stype = str(r["subject_type"]).upper()
            sid = str(r["subject_id"])
            eff = str(r["effect"]).upper()
            doc_ids_seen.add(did)
            if stype == "USER":
                raw_user.setdefault(did, {}).setdefault(sid, set()).add(eff)
            elif stype == "ORG_NODE":
                raw_org.setdefault(did, {}).setdefault(sid, set()).add(eff)

        doc_rules: dict[str, tuple[dict[str, frozenset[str]], dict[str, frozenset[str]]]] = {}
        for did in doc_ids_seen:
            u_map = {k: frozenset(v) for k, v in raw_user.get(did, {}).items()}
            o_map = {k: frozenset(v) for k, v in raw_org.get(did, {}).items()}
            doc_rules[did] = (u_map, o_map)

        snap = AclSnapshot(org_lineage=org_lineage, user_org=user_org, doc_rules=doc_rules)
        tstate.acl_snapshot = snap
        tstate.acl_snapshot_epoch = target_epoch
        return snap


def is_doc_blocked_with_snapshot(snap: AclSnapshot, user_id: str, doc_id: str) -> bool:
    """基于内存 AclSnapshot 以 O(depth) 完成三级隔离墙裁决。"""
    org_node = snap.user_org.get(user_id)
    if org_node is None:
        return True
    rules = snap.doc_rules.get(doc_id)
    if rules is None:
        return False

    user_map, org_map = rules
    user_effs = user_map.get(user_id)
    if user_effs:
        if "ALLOW" in user_effs:
            return False
        if "DENY" in user_effs:
            return True

    if not org_map:
        return False

    lineage = snap.org_lineage.get(org_node, (org_node,))
    for node_id in lineage:
        effs = org_map.get(node_id)
        if effs:
            if "DENY" in effs:
                return True
            if "ALLOW" in effs:
                return False
    return False


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    snap = get_acl_snapshot(db_path, tenant_id)
    chain = snap.org_lineage.get(start_node_id)
    if chain is not None:
        return list(chain)
    return [start_node_id] if start_node_id else []


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    snap = get_acl_snapshot(db_path, tenant_id)
    return is_doc_blocked_with_snapshot(snap, user_id, doc_id)


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
    """配置或停用文档利益冲突隔离墙规则（仅递增 acl_epoch，绝不触发文档倒排索引重建）。"""
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")
    if not doc_id or not subject_id:
        raise ValueError("doc_id and subject_id are required")

    now_ts = int(time.time())
    with write_transaction(db_path) as conn:
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
                (tenant_id, doc_id, norm_type, subject_id, norm_effect, now_ts),
            )
        else:
            conn.execute(
                "UPDATE doc_acl_rules SET active = 0, updated_at = ? "
                "WHERE tenant_id = ? AND doc_id = ? AND subject_type = ? AND subject_id = ? AND effect = ?",
                (now_ts, tenant_id, doc_id, norm_type, subject_id, norm_effect),
            )

    tstate = get_runtime(db_path).get_tenant(tenant_id)
    with tstate.acl_lock:
        tstate.acl_epoch += 1

    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
