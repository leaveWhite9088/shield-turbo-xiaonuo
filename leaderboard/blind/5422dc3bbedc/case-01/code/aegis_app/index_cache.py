# -*- coding: utf-8 -*-
"""进程内多维缓存与紧凑增量倒排索引（AegisGate 高频读路径加速层）。

设计要点：
1. **纪元解耦**：文档倒排索引（doc epoch）、利益冲突墙规则（acl epoch）、
   角色授予（grants epoch）、借调委托（delegation epoch）、租户策略（policy epoch）、
   制裁名单（sanctions epoch）各自独立纪元计数——修改单条 doc-acl 规则绝不会
   连带清空整租户文档倒排索引，反之亦然。
2. **紧凑常驻内存**：索引仅保留派生结构（倒排位置表、词集合、标题词频、140 字
   摘要），绝不无界常驻原始大正文 body；文档对象使用 ``__slots__`` 压缩。
3. **双向引用增量传播**：citations 正向唯一引用集 + reverse_dependents 反向依赖图；
   引用源状态翻转时仅对 O(deg) 个被引用方脏标记，检索时惰性重算精确有效引用数，
   无需全库重建。
4. **全局统一锁序**：跨租户使用独立租户锁；所有写路径的数据库串行化统一交给
   SQLite ``BEGIN IMMEDIATE`` 单写者锁（见 db.immediate_transaction），进程内
   缓存锁绝不与数据库锁交叉持有，结构性无死锁。
"""
from __future__ import annotations

import pathlib
import threading
from typing import Any, Iterable

from .db import open_connection
from .doc_indexer import tokenize_text


class DocEntry:
    """单篇文档的紧凑索引条目（不含原始 body 全文）。"""

    __slots__ = (
        "doc_id",
        "tenant_id",
        "category",
        "regulation_code",
        "canon_reg",
        "clearance_level",
        "risk_weight",
        "custom_tag",
        "title",
        "snippet",
        "updated_at",
        "status",
        "quarantined",
        "title_tf",
        "body_positions",
        "uniq_tokens",
    )

    def __init__(
        self,
        doc_id: str,
        tenant_id: str,
        category: str,
        regulation_code: str,
        canon_reg: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        snippet: str,
        updated_at: int,
        status: str,
        quarantined: int,
    ) -> None:
        self.doc_id = doc_id
        self.tenant_id = tenant_id
        self.category = category
        self.regulation_code = regulation_code
        self.canon_reg = canon_reg
        self.clearance_level = clearance_level
        self.risk_weight = risk_weight
        self.custom_tag = custom_tag
        self.title = title
        self.snippet = snippet
        self.updated_at = updated_at
        self.status = status
        self.quarantined = quarantined
        self.title_tf: dict[str, int] = {}
        self.body_positions: dict[str, list[int]] = {}
        self.uniq_tokens: frozenset[str] = frozenset()

    def build_text_index(self, title: str, body: str) -> None:
        """（增量）重建该文档的标题词频、正文倒排位置表与全词集合。"""
        title_tokens = tokenize_text(title)
        self.title_tf = {}
        for tok in title_tokens:
            self.title_tf[tok] = self.title_tf.get(tok, 0) + 1
        positions: dict[str, list[int]] = {}
        body_tokens = tokenize_text(body)
        for i, tok in enumerate(body_tokens):
            plist = positions.get(tok)
            if plist is None:
                positions[tok] = [i]
            else:
                plist.append(i)
        self.body_positions = positions
        self.uniq_tokens = frozenset(title_tokens) | frozenset(body_tokens)

    @property
    def searchable(self) -> bool:
        return self.status == "ACTIVE" and self.quarantined == 0

    @property
    def citable(self) -> bool:
        """作为其他文档有效内部引用源的条件：本租户 ACTIVE 且未被隔离。"""
        return self.status == "ACTIVE" and self.quarantined == 0


class TenantState:
    """单租户进程内状态（文档索引 + 各维纪元缓存），独立租户锁。"""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.lock = threading.RLock()
        # 文档纪元
        self.docs: dict[str, DocEntry] = {}
        self.refs: dict[str, tuple[str, ...]] = {}
        self.reverse_dependents: dict[str, set[str]] = {}
        self._cite_counts: dict[str, int] = {}
        self._cite_dirty: set[str] = set()
        self._docs_built = False
        # 各维纪元（与文档索引互相解耦）
        self.acl_epoch = 0
        self._acl_rules: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]] | None = None
        self._acl_built_epoch = -1
        self.grants_epoch = 0
        self._role_grants: dict[str, set[str]] | None = None
        self._grants_built_epoch = -1
        self.delegation_epoch = 0
        self._delegations: list[tuple[str, str, str, int, int]] | None = None
        self._deleg_built_epoch = -1
        self.policy_epoch = 0
        self._policy: dict[str, Any] | None = None
        self._policy_built_epoch = -1
        self.sanctions_epoch = 0
        self._sanctions: dict[str, int] | None = None
        self._sanctions_built_epoch = -1
        # 静态结构（运行期只读）
        self._org_tree: dict[str, tuple[str | None, str | None]] | None = None
        self._users: dict[str, dict[str, Any]] | None = None

    # ---------------- 文档倒排索引（惰性全量构建一次，之后单篇增量） ----------------
    def ensure_docs(self, db_path: str) -> None:
        with self.lock:
            if self._docs_built:
                return
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
                    "risk_weight, custom_tag, title, body, status, quarantined, updated_at "
                    "FROM compliance_docs WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchall()
                cit_rows = conn.execute(
                    "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            docs: dict[str, DocEntry] = {}
            from .legacy_compat import canonicalize_regulation_code

            for r in rows:
                entry = DocEntry(
                    r["doc_id"], self.tenant_id, r["category"], r["regulation_code"],
                    canonicalize_regulation_code(r["regulation_code"]),
                    int(r["clearance_level"]), int(r["risk_weight"]), r["custom_tag"],
                    r["title"], r["body"][:140], int(r["updated_at"]),
                    r["status"], int(r["quarantined"]),
                )
                entry.build_text_index(r["title"], r["body"])
                docs[entry.doc_id] = entry
            refs_map: dict[str, list[str]] = {}
            reverse: dict[str, set[str]] = {}
            for cr in cit_rows:
                doc_id = cr["doc_id"]
                ref = str(cr["cited_by_ref"] or "").strip()
                if not ref:
                    continue
                bucket = refs_map.setdefault(doc_id, [])
                if ref not in bucket:
                    bucket.append(ref)
                reverse.setdefault(ref, set()).add(doc_id)
            self.docs = docs
            self.refs = {k: tuple(v) for k, v in refs_map.items()}
            self.reverse_dependents = reverse
            self._cite_counts = {}
            self._cite_dirty = set(self.refs.keys())
            self._docs_built = True

    def citation_count(self, doc_id: str) -> int:
        """文档当前有效唯一引用源计数（内部 doc_ 引用须本租户 ACTIVE 且未隔离）。

        状态翻转仅脏标记 O(deg) 反向依赖方，此处惰性精确重算。
        """
        with self.lock:
            cached = self._cite_counts.get(doc_id)
            if cached is not None and doc_id not in self._cite_dirty:
                return cached
            refs = self.refs.get(doc_id)
            valid = 0
            seen: set[str] = set()
            for ref in refs or ():
                if not ref or ref == doc_id or ref in seen:
                    continue
                seen.add(ref)
                if ref.startswith("doc_"):
                    ref_entry = self.docs.get(ref)
                    # 修复原版跨租户侧信道：内部引用仅当引用源同租户、ACTIVE 且未隔离时计入
                    if (
                        ref_entry is not None
                        and ref_entry.tenant_id == self.tenant_id
                        and ref_entry.citable
                    ):
                        valid += 1
                else:
                    valid += 1
            self._cite_counts[doc_id] = valid
            self._cite_dirty.discard(doc_id)
            return valid

    def apply_upsert(self, fields: dict[str, Any], added_refs: Iterable[str]) -> None:
        """单篇增量：更新/新建文档条目并增量登记引用（绝不重建整租户索引）。"""
        with self.lock:
            entry = self.docs.get(fields["doc_id"])
            if entry is None:
                from .legacy_compat import canonicalize_regulation_code

                entry = DocEntry(
                    fields["doc_id"], self.tenant_id, fields["category"],
                    fields["regulation_code"],
                    canonicalize_regulation_code(fields["regulation_code"]),
                    fields["clearance_level"], fields["risk_weight"], fields["custom_tag"],
                    fields["title"], fields["body"][:140], fields["updated_at"],
                    fields["status"], fields["quarantined"],
                )
                self.docs[entry.doc_id] = entry
            else:
                entry.category = fields["category"]
                entry.regulation_code = fields["regulation_code"]
                from .legacy_compat import canonicalize_regulation_code

                entry.canon_reg = canonicalize_regulation_code(fields["regulation_code"])
                entry.clearance_level = fields["clearance_level"]
                entry.risk_weight = fields["risk_weight"]
                entry.custom_tag = fields["custom_tag"]
                entry.updated_at = fields["updated_at"]
                entry.status = fields["status"]
                entry.quarantined = fields["quarantined"]
            entry.build_text_index(fields["title"], fields["body"])
            # 增量引用登记（引用集为并集，与原版累积插入 + 计数去重语义一致）
            doc_id = entry.doc_id
            current = list(self.refs.get(doc_id, ()))
            changed = False
            for ref in added_refs:
                ref = str(ref).strip()
                if not ref or ref in current:
                    continue
                current.append(ref)
                self.reverse_dependents.setdefault(ref, set()).add(doc_id)
                changed = True
            if changed:
                self.refs[doc_id] = tuple(current)
            self._cite_dirty.add(doc_id)
            self._cite_counts.pop(doc_id, None)

    def _mark_ref_status_dirty(self, doc_id: str) -> None:
        """引用源状态翻转：仅对引用了它的文档（反向依赖）做 O(deg) 脏标记。"""
        self._cite_dirty.update(self.reverse_dependents.get(doc_id, ()))

    def apply_status(self, doc_id: str, status: str) -> None:
        with self.lock:
            entry = self.docs.get(doc_id)
            if entry is None:
                return
            entry.status = status
            self._mark_ref_status_dirty(doc_id)

    def apply_quarantine(self, doc_id: str, quarantined: int) -> None:
        with self.lock:
            entry = self.docs.get(doc_id)
            if entry is None:
                return
            entry.quarantined = quarantined
            self._mark_ref_status_dirty(doc_id)

    # ---------------- 利益冲突墙（acl 纪元，与文档纪元解耦） ----------------
    def wall_rules(self, db_path: str) -> dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]]:
        with self.lock:
            if self._acl_rules is not None and self._acl_built_epoch == self.acl_epoch:
                return self._acl_rules
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
                    "WHERE tenant_id = ? AND active = 1",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            rules: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]] = {}
            for r in rows:
                user_map, org_map = rules.get(r["doc_id"], ({}, {}))
                user_map = dict(user_map)
                org_map = dict(org_map)
                effect = str(r["effect"]).upper()
                if r["subject_type"] == "USER":
                    user_map.setdefault(r["subject_id"], set()).add(effect)
                elif r["subject_type"] == "ORG_NODE":
                    org_map.setdefault(r["subject_id"], set()).add(effect)
                rules[r["doc_id"]] = (user_map, org_map)
            self._acl_rules = rules
            self._acl_built_epoch = self.acl_epoch
            return rules

    def bump_acl(self) -> None:
        with self.lock:
            self.acl_epoch += 1

    # ---------------- 静态组织树 / 用户（运行期只读） ----------------
    def org_tree(self, db_path: str) -> dict[str, tuple[str | None, str | None]]:
        with self.lock:
            if self._org_tree is not None:
                return self._org_tree
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            self._org_tree = {
                r["node_id"]: (r["parent_node_id"], r["inherited_role"]) for r in rows
            }
            return self._org_tree

    def users(self, db_path: str) -> dict[str, dict[str, Any]]:
        with self.lock:
            if self._users is not None:
                return self._users
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT user_id, username, org_node_id, base_role, api_token_hash, active "
                    "FROM users WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            self._users = {
                r["user_id"]: {
                    "username": r["username"],
                    "org_node_id": r["org_node_id"],
                    "base_role": r["base_role"],
                    "api_token_hash": r["api_token_hash"],
                    "active": int(r["active"]) == 1,
                }
                for r in rows
            }
            return self._users

    # ---------------- 角色授予纪元 ----------------
    def role_grants(self, db_path: str) -> dict[str, set[str]]:
        with self.lock:
            if self._role_grants is not None and self._grants_built_epoch == self.grants_epoch:
                return self._role_grants
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            grants: dict[str, set[str]] = {}
            for r in rows:
                grants.setdefault(r["user_id"], set()).add(r["granted_role"])
            self._role_grants = grants
            self._grants_built_epoch = self.grants_epoch
            return grants

    def bump_grants(self) -> None:
        with self.lock:
            self.grants_epoch += 1

    # ---------------- 借调委托纪元 ----------------
    def delegations(self, db_path: str) -> list[tuple[str, str, str, int, int]]:
        """返回 (grantor, grantee, delegated_role, starts_at, expires_at) 活跃委托列表。"""
        with self.lock:
            if self._delegations is not None and self._deleg_built_epoch == self.delegation_epoch:
                return self._delegations
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
                    "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            self._delegations = [
                (r["grantor_user_id"], r["grantee_user_id"], r["delegated_role"],
                 int(r["starts_at"]), int(r["expires_at"]))
                for r in rows
            ]
            self._deleg_built_epoch = self.delegation_epoch
            return self._delegations

    def bump_delegations(self) -> None:
        with self.lock:
            self.delegation_epoch += 1

    # ---------------- 租户策略纪元 ----------------
    def policy(self, db_path: str) -> dict[str, Any] | None:
        with self.lock:
            if self._policy is not None and self._policy_built_epoch == self.policy_epoch:
                return self._policy
            conn = open_connection(db_path)
            try:
                row = conn.execute(
                    "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, "
                    "velocity_amount_cents, counterparty_fanout_limit, review_threshold, "
                    "reject_threshold, custom_rules_json, updated_at "
                    "FROM tenant_policies WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchone()
            finally:
                conn.close()
            if not row:
                self._policy = None
                self._policy_built_epoch = self.policy_epoch
                return None
            import json as _json

            policy = dict(row)
            policy["custom_rules"] = _json.loads(policy["custom_rules_json"])
            self._policy = policy
            self._policy_built_epoch = self.policy_epoch
            return policy

    def bump_policy(self) -> None:
        with self.lock:
            self.policy_epoch += 1

    # ---------------- 制裁名单纪元 ----------------
    def sanctions(self, db_path: str) -> dict[str, int]:
        with self.lock:
            if self._sanctions is not None and self._sanctions_built_epoch == self.sanctions_epoch:
                return self._sanctions
            conn = open_connection(db_path)
            try:
                rows = conn.execute(
                    "SELECT entity_id, active FROM sanctioned_entities WHERE tenant_id = ?",
                    (self.tenant_id,),
                ).fetchall()
            finally:
                conn.close()
            self._sanctions = {r["entity_id"]: int(r["active"]) for r in rows}
            self._sanctions_built_epoch = self.sanctions_epoch
            return self._sanctions

    def bump_sanctions(self) -> None:
        with self.lock:
            self.sanctions_epoch += 1


class CacheState:
    """按数据库文件为键的全局缓存状态（含租户表静态缓存）。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.lock = threading.RLock()
        self.tenants: dict[str, TenantState] = {}
        self._tenant_rows: dict[str, dict[str, str]] | None = None

    def tenant(self, tenant_id: str) -> TenantState:
        with self.lock:
            st = self.tenants.get(tenant_id)
            if st is None:
                st = TenantState(tenant_id)
                self.tenants[tenant_id] = st
            return st

    def tenant_rows(self) -> dict[str, dict[str, str]]:
        with self.lock:
            if self._tenant_rows is not None:
                return self._tenant_rows
            conn = open_connection(self.db_path)
            try:
                rows = conn.execute("SELECT tenant_id, status, webhook_secret FROM tenants").fetchall()
            finally:
                conn.close()
            self._tenant_rows = {
                r["tenant_id"]: {"status": r["status"], "webhook_secret": r["webhook_secret"]}
                for r in rows
            }
            return self._tenant_rows


_STATES: dict[str, CacheState] = {}
_STATES_LOCK = threading.RLock()


def get_state(db_path: str) -> CacheState:
    key = str(pathlib.Path(db_path).resolve())
    with _STATES_LOCK:
        state = _STATES.get(key)
        if state is None:
            state = CacheState(key)
            _STATES[key] = state
        return state
