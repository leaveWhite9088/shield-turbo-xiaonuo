# -*- coding: utf-8 -*-
"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎。

裁决优先级规则（从高到低）：
1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。
"""
from __future__ import annotations

import pathlib
import threading
import time
from typing import Any

from .db import bump_domain_epoch, get_domain_epoch, open_connection


class _AclWallCache:
    __slots__ = ("epoch", "user_lineage", "rules_by_doc")

    def __init__(
        self,
        epoch: int,
        user_lineage: dict[str, tuple[str, ...]],
        rules_by_doc: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]],
    ) -> None:
        self.epoch = epoch
        self.user_lineage = user_lineage
        self.rules_by_doc = rules_by_doc


_ACL_CACHE_LOCK = threading.Lock()
_ACL_CACHES: dict[str, _AclWallCache] = {}


def _get_acl_cache(db_path: str, tenant_id: str) -> _AclWallCache:
    db_key = str(pathlib.Path(db_path).resolve())
    cache_key = f"{db_key}::{tenant_id}"
    cur_epoch = get_domain_epoch(db_key, tenant_id, "acl")
    with _ACL_CACHE_LOCK:
        cached = _ACL_CACHES.get(cache_key)
        if cached is not None and cached.epoch == cur_epoch:
            return cached

    conn = open_connection(db_key)
    try:
        u_rows = conn.execute(
            "SELECT user_id, org_node_id FROM users WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        n_rows = conn.execute(
            "SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        acl_rows = conn.execute(
            "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()

    parent_map: dict[str, str | None] = {}
    for r in n_rows:
        parent_map[str(r["node_id"])] = str(r["parent_node_id"]) if r["parent_node_id"] else None

    lineage_by_node: dict[str, tuple[str, ...]] = {}
    for nid in parent_map:
        chain: list[str] = []
        curr: str | None = nid
        seen: set[str] = set()
        while curr and curr not in seen:
            seen.add(curr)
            chain.append(curr)
            curr = parent_map.get(curr)
        lineage_by_node[nid] = tuple(chain)

    user_lineage: dict[str, tuple[str, ...]] = {}
    for r in u_rows:
        uid = str(r["user_id"])
        oid = str(r["org_node_id"])
        if oid in lineage_by_node:
            user_lineage[uid] = lineage_by_node[oid]
        else:
            user_lineage[uid] = (oid,) if oid else ()

    rules_by_doc: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]] = {}
    for r in acl_rows:
        did = str(r["doc_id"])
        stype = str(r["subject_type"])
        sid = str(r["subject_id"])
        eff = str(r["effect"]).upper()
        entry = rules_by_doc.get(did)
        if entry is None:
            entry = ({}, {})
            rules_by_doc[did] = entry
        if stype == "USER":
            entry[0].setdefault(sid, set()).add(eff)
        elif stype == "ORG_NODE":
            entry[1].setdefault(sid, set()).add(eff)

    state = _AclWallCache(epoch=cur_epoch, user_lineage=user_lineage, rules_by_doc=rules_by_doc)
    with _ACL_CACHE_LOCK:
        if len(_ACL_CACHES) > 256:
            _ACL_CACHES.pop(next(iter(_ACL_CACHES)), None)
        _ACL_CACHES[cache_key] = state
    return state


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
    conn = open_connection(db_path)
    try:
        n_rows = conn.execute(
            "SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()
    parent_map = {str(r["node_id"]): (str(r["parent_node_id"]) if r["parent_node_id"] else None) for r in n_rows}
    lineage: list[str] = []
    curr: str | None = start_node_id
    visited: set[str] = set()
    while curr and curr not in visited:
        visited.add(curr)
        lineage.append(curr)
        curr = parent_map.get(curr)
    return lineage


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
    state = _get_acl_cache(db_path, tenant_id)
    lineage = state.user_lineage.get(user_id)
    if lineage is None:
        return True

    doc_rules = state.rules_by_doc.get(doc_id)
    if not doc_rules:
        return False

    user_map, org_map = doc_rules
    user_effects = user_map.get(user_id)
    if user_effects:
        if "ALLOW" in user_effects:
            return False
        if "DENY" in user_effects:
            return True

    if org_map:
        for node_id in lineage:
            effs = org_map.get(node_id)
            if effs:
                if "DENY" in effs:
                    return True
                if "ALLOW" in effs:
                    return False

    return False


def get_blocked_doc_ids_for_user(db_path: str, tenant_id: str, user_id: str) -> set[str]:
    """批量预计算当前用户在租户下被隔离墙封禁的文档集合。"""
    state = _get_acl_cache(db_path, tenant_id)
    lineage = state.user_lineage.get(user_id)
    if lineage is None:
        return set(state.rules_by_doc.keys())
    blocked: set[str] = set()
    for doc_id, (user_map, org_map) in state.rules_by_doc.items():
        u_eff = user_map.get(user_id)
        if u_eff:
            if "ALLOW" in u_eff:
                continue
            if "DENY" in u_eff:
                blocked.add(doc_id)
                continue
        if org_map:
            for node_id in lineage:
                effs = org_map.get(node_id)
                if effs:
                    if "DENY" in effs:
                        blocked.add(doc_id)
                    break
    return blocked


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
    """配置或停用文档利益冲突隔离墙规则（支持 USER / ORG_NODE 与 DENY / ALLOW）。"""
    norm_type = str(subject_type or "").upper()
    norm_effect = str(effect or "DENY").upper()
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")
    if not doc_id or not subject_id:
        raise ValueError("doc_id and subject_id are required")

    now_ts = int(time.time())
    conn = open_connection(db_path)
    try:
        doc_row = conn.execute(
            "SELECT doc_id FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
            (tenant_id, doc_id),
        ).fetchone()
        if not doc_row:
            raise LookupError(f"Document not found in tenant: {doc_id}")

        conn.execute("BEGIN IMMEDIATE")
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
        conn.commit()
    finally:
        conn.close()

    bump_domain_epoch(db_path, tenant_id, "acl")
    return {
        "tenant_id": tenant_id,
        "doc_id": doc_id,
        "subject_type": norm_type,
        "subject_id": subject_id,
        "effect": norm_effect,
        "active": bool(active),
    }
