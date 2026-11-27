# -*- coding: utf-8 -*-
"""三级利益冲突墙与独立 ACL 纪元快照缓存。"""
from __future__ import annotations

import threading
import time
from typing import Any

from .db import open_connection
from .runtime import bounded_text


class WallSnapshot:
    __slots__ = ("rules", "parents", "epoch")

    def __init__(self, rules: dict[str, tuple[tuple[str, str, str], ...]], parents: dict[str, str | None], epoch: int) -> None:
        self.rules = rules
        self.parents = parents
        self.epoch = epoch

    def lineage(self, start_node_id: str) -> list[str]:
        result: list[str] = []
        current: str | None = start_node_id
        visited: set[str] = set()
        while current and current not in visited:
            visited.add(current)
            result.append(current)
            current = self.parents.get(current)
        return result

    def blocked(self, user_id: str, org_node_id: str, doc_id: str) -> bool:
        acl_rows = self.rules.get(doc_id)
        if not acl_rows:
            return False
        user_effects = {
            effect for subject_type, subject_id, effect in acl_rows
            if subject_type == "USER" and subject_id == user_id
        }
        if "ALLOW" in user_effects:
            return False
        if "DENY" in user_effects:
            return True
        org_effects: dict[str, set[str]] = {}
        for subject_type, subject_id, effect in acl_rows:
            if subject_type == "ORG_NODE":
                org_effects.setdefault(subject_id, set()).add(effect)
        for node_id in self.lineage(org_node_id):
            effects = org_effects.get(node_id)
            if effects:
                if "DENY" in effects:
                    return True
                if "ALLOW" in effects:
                    return False
        return False


class _WallCacheEntry:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.epoch = 0
        self.snapshot: WallSnapshot | None = None


_CACHES: dict[tuple[str, str], _WallCacheEntry] = {}
_CACHES_GUARD = threading.Lock()


def _cache(db_path: str, tenant_id: str) -> _WallCacheEntry:
    key = (str(db_path), tenant_id)
    with _CACHES_GUARD:
        entry = _CACHES.get(key)
        if entry is None:
            entry = _WallCacheEntry()
            _CACHES[key] = entry
        return entry


def get_wall_snapshot(db_path: str, tenant_id: str) -> WallSnapshot:
    entry = _cache(db_path, tenant_id)
    with entry.lock:
        if entry.snapshot is not None:
            return entry.snapshot
        conn = open_connection(db_path)
        try:
            acl_cursor = conn.execute(
                "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
                "WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            )
            mutable: dict[str, list[tuple[str, str, str]]] = {}
            for row in acl_cursor:
                mutable.setdefault(str(row["doc_id"]), []).append(
                    (str(row["subject_type"]), str(row["subject_id"]), str(row["effect"]).upper())
                )
            parents = {
                str(row["node_id"]): row["parent_node_id"]
                for row in conn.execute("SELECT node_id, parent_node_id FROM org_nodes WHERE tenant_id = ?", (tenant_id,))
            }
        finally:
            conn.close()
        entry.epoch += 1
        entry.snapshot = WallSnapshot(
            {doc_id: tuple(rows) for doc_id, rows in mutable.items()}, parents, entry.epoch
        )
        return entry.snapshot


def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
    return get_wall_snapshot(db_path, tenant_id).lineage(start_node_id)


def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
    conn = open_connection(db_path)
    try:
        row = conn.execute(
            "SELECT org_node_id FROM users WHERE tenant_id = ? AND user_id = ? AND active = 1",
            (tenant_id, user_id),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return True
    return get_wall_snapshot(db_path, tenant_id).blocked(user_id, str(row["org_node_id"]), doc_id)


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
    norm_type = bounded_text(subject_type, "subject_type", 16).upper()
    norm_effect = bounded_text(effect or "DENY", "effect", 16).upper()
    subject_id = bounded_text(subject_id, "subject_id", 128)
    doc_id = bounded_text(doc_id, "doc_id", 128)
    if norm_type not in ("USER", "ORG_NODE"):
        raise ValueError("subject_type must be USER or ORG_NODE")
    if norm_effect not in ("DENY", "ALLOW"):
        raise ValueError("effect must be DENY or ALLOW")
    if not isinstance(active, bool):
        raise ValueError("active must be boolean")

    now_ts = int(time.time())
    entry = _cache(db_path, tenant_id)
    with entry.lock:
        conn = open_connection(db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not conn.execute(
                "SELECT 1 FROM compliance_docs WHERE tenant_id = ? AND doc_id = ?",
                (tenant_id, doc_id),
            ).fetchone():
                raise LookupError("Document not found")
            if active:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (tenant_id, doc_id, norm_type, subject_id, norm_effect, now_ts),
                )
            else:
                conn.execute(
                    "UPDATE doc_acl_rules SET active = 0, updated_at = ? WHERE tenant_id = ? AND doc_id = ? "
                    "AND subject_type = ? AND subject_id = ? AND effect = ?",
                    (now_ts, tenant_id, doc_id, norm_type, subject_id, norm_effect),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        # 只推进 ACL 纪元；文档倒排与词项位置完全保留。
        entry.epoch += 1
        entry.snapshot = None

    return {
        "tenant_id": tenant_id, "doc_id": doc_id, "subject_type": norm_type,
        "subject_id": subject_id, "effect": norm_effect, "active": active,
    }
