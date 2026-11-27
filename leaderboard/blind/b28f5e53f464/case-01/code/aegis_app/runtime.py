# -*- coding: utf-8 -*-
"""AegisGate 共享运行时引擎：连接池、全局锁偏序、多维解耦纪元缓存、紧凑倒排索引与风险图谱状态管理。"""
from __future__ import annotations

from array import array
from bisect import bisect_left, insort
from collections import OrderedDict, defaultdict, deque
import contextlib
import json
import pathlib
import sqlite3
import sys
import threading
from typing import Any, Iterator

from .config import MAX_DELEGATION_HOPS, ROLE_DEFAULT_CLEARANCE, SLIDING_WINDOW_SECONDS
from .db import open_connection
from .doc_indexer import tokenize_text
from .legacy_compat import canonicalize_regulation_code
from .window_stats import AccountWindowState

MAX_POOL_SIZE = 32
MAX_BODY_LRU_DOCS = 512
MAX_BODY_LRU_TOKENS = 262144  # ~1 MB (array('I') 4 bytes/token)


class CompactDocNode:
    """紧凑常驻文档索引节点（不保留原始大正文 body，仅保留 140 字符摘要与紧凑元数据）。"""

    __slots__ = (
        "doc_int_id",
        "doc_id",
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
        "uniq_token_ids",
        "ext_refs",
        "int_refs",
        "valid_citation_count",
    )

    def __init__(
        self,
        *,
        doc_int_id: int,
        doc_id: str,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        snippet: str,
        updated_at: int,
        status: str,
        quarantined: int,
        uniq_token_ids: array,
        ext_refs: set[str],
        int_refs: set[str],
        valid_citation_count: int = 0,
    ) -> None:
        self.doc_int_id = doc_int_id
        self.doc_id = doc_id
        self.category = category
        self.regulation_code = regulation_code
        self.canon_reg = canonicalize_regulation_code(regulation_code)
        self.clearance_level = clearance_level
        self.risk_weight = risk_weight
        self.custom_tag = custom_tag
        self.title = title
        self.snippet = snippet
        self.updated_at = updated_at
        self.status = status
        self.quarantined = quarantined
        self.uniq_token_ids = uniq_token_ids
        self.ext_refs = ext_refs
        self.int_refs = int_refs
        self.valid_citation_count = valid_citation_count

    def is_active_unquarantined(self) -> bool:
        return self.status == "ACTIVE" and self.quarantined == 0


class TenantDocIndex:
    """单租户增量倒排索引、反向引用传播图与有界词序列 LRU 缓存。"""

    def __init__(self) -> None:
        self.loaded: bool = False
        self.doc_epoch: int = 0
        self.vocab: dict[str, int] = {}
        self.next_doc_int: int = 1
        self.docs_by_id: dict[str, CompactDocNode] = {}
        self.docs_by_int: dict[int, CompactDocNode] = {}
        # term_id -> {doc_int_id: (min(title_tf, 5) << 4) | min(body_tf, 12)}
        self.postings: dict[int, dict[int, int]] = {}
        # source_doc_id -> set of citing target doc_ids
        self.reverse_dependents: dict[str, set[str]] = defaultdict(set)
        # doc_id -> array('I') of body token IDs (hard-capped at 512 docs / ~1MB)
        self.body_token_lru: OrderedDict[str, array] = OrderedDict()
        self.body_lru_tokens: int = 0

    def _intern_term(self, term: str) -> int:
        tid = self.vocab.get(term)
        if tid is None:
            tid = len(self.vocab)
            self.vocab[term] = tid
        return tid

    def _put_body_lru(self, doc_id: str, tok_ids: array) -> None:
        n_toks = len(tok_ids)
        if n_toks > MAX_BODY_LRU_TOKENS // 4:
            return
        old = self.body_token_lru.pop(doc_id, None)
        if old is not None:
            self.body_lru_tokens -= len(old)
        self.body_token_lru[doc_id] = tok_ids
        self.body_lru_tokens += n_toks
        while (
            len(self.body_token_lru) > MAX_BODY_LRU_DOCS
            or self.body_lru_tokens > MAX_BODY_LRU_TOKENS
        ):
            _, evicted = self.body_token_lru.popitem(last=False)
            self.body_lru_tokens -= len(evicted)

    def _invalidate_body_lru(self, doc_id: str) -> None:
        old = self.body_token_lru.pop(doc_id, None)
        if old is not None:
            self.body_lru_tokens -= len(old)

    def _remove_postings(self, node: CompactDocNode) -> None:
        d_int = node.doc_int_id
        for tid in node.uniq_token_ids:
            plist = self.postings.get(tid)
            if plist is not None:
                plist.pop(d_int, None)
                if not plist:
                    del self.postings[tid]

    def _index_doc_tokens(
        self,
        doc_int_id: int,
        title: str,
        body: str,
        *,
        cache_body_id: str | None = None,
    ) -> array:
        title_tf: dict[int, int] = {}
        for tok in tokenize_text(title):
            tid = self._intern_term(tok)
            title_tf[tid] = title_tf.get(tid, 0) + 1

        body_toks = tokenize_text(body)
        body_tf: dict[int, int] = {}
        body_arr = array("I")
        for tok in body_toks:
            tid = self._intern_term(tok)
            body_tf[tid] = body_tf.get(tid, 0) + 1
            body_arr.append(tid)

        if cache_body_id is not None:
            self._put_body_lru(cache_body_id, body_arr)

        all_tids = sorted(set(title_tf.keys()) | set(body_tf.keys()))
        for tid in all_tids:
            t_cnt = title_tf.get(tid, 0)
            b_cnt = body_tf.get(tid, 0)
            if t_cnt > 5:
                t_cnt = 5
            if b_cnt > 12:
                b_cnt = 12
            packed = (t_cnt << 4) | b_cnt
            plist = self.postings.get(tid)
            if plist is None:
                self.postings[tid] = {doc_int_id: packed}
            else:
                plist[doc_int_id] = packed

        return array("I", all_tids)

    def load_from_db(self, conn: sqlite3.Connection, tenant_id: str) -> None:
        self.vocab.clear()
        self.next_doc_int = 1
        self.docs_by_id.clear()
        self.docs_by_int.clear()
        self.postings.clear()
        self.reverse_dependents.clear()
        self.body_token_lru.clear()
        self.body_lru_tokens = 0

        doc_rows = conn.execute(
            "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, body, status, quarantined, updated_at "
            "FROM compliance_docs WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()

        cite_rows = conn.execute(
            "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()

        cites_by_doc: dict[str, tuple[set[str], set[str]]] = {}
        for cr in cite_rows:
            did = str(cr["doc_id"])
            ref = str(cr["cited_by_ref"] or "").strip()
            if not ref or ref == did:
                continue
            pair = cites_by_doc.get(did)
            if pair is None:
                pair = (set(), set())
                cites_by_doc[did] = pair
            if ref.startswith("doc_"):
                pair[1].add(ref)
            else:
                pair[0].add(ref)

        for r in doc_rows:
            did = str(r["doc_id"])
            d_int = self.next_doc_int
            self.next_doc_int += 1
            title = str(r["title"])
            body = str(r["body"])
            uniq_ids = self._index_doc_tokens(d_int, title, body, cache_body_id=did)
            ext_refs, int_refs = cites_by_doc.get(did, (set(), set()))
            node = CompactDocNode(
                doc_int_id=d_int,
                doc_id=did,
                category=sys.intern(str(r["category"])),
                regulation_code=str(r["regulation_code"]),
                clearance_level=int(r["clearance_level"]),
                risk_weight=int(r["risk_weight"]),
                custom_tag=str(r["custom_tag"]),
                title=title,
                snippet=body[:140],
                updated_at=int(r["updated_at"]),
                status=sys.intern(str(r["status"])),
                quarantined=int(r["quarantined"]),
                uniq_token_ids=uniq_ids,
                ext_refs=set(ext_refs),
                int_refs=set(int_refs),
                valid_citation_count=len(ext_refs),
            )
            self.docs_by_id[did] = node
            self.docs_by_int[d_int] = node
            for src_ref in int_refs:
                self.reverse_dependents[src_ref].add(did)

        # 解析所有有效内部引用计数（O(总引用边数)）
        for node in self.docs_by_id.values():
            valid_int = 0
            for src_ref in node.int_refs:
                src_node = self.docs_by_id.get(src_ref)
                if src_node is not None and src_node.is_active_unquarantined():
                    valid_int += 1
            node.valid_citation_count = len(node.ext_refs) + valid_int

        self.doc_epoch += 1
        self.loaded = True

    def apply_upsert(
        self,
        *,
        doc_id: str,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        body: str,
        updated_at: int,
        new_citations: list[str],
    ) -> None:
        if not self.loaded:
            return
        self._invalidate_body_lru(doc_id)
        existing = self.docs_by_id.get(doc_id)
        if existing is not None:
            was_valid_src = existing.is_active_unquarantined()
            self._remove_postings(existing)
            uniq_ids = self._index_doc_tokens(
                existing.doc_int_id, title, body, cache_body_id=doc_id
            )
            existing.category = sys.intern(category)
            existing.regulation_code = regulation_code
            existing.canon_reg = canonicalize_regulation_code(regulation_code)
            existing.clearance_level = clearance_level
            existing.risk_weight = risk_weight
            existing.custom_tag = custom_tag
            existing.title = title
            existing.snippet = body[:140]
            existing.updated_at = updated_at
            existing.status = sys.intern("ACTIVE")
            existing.uniq_token_ids = uniq_ids
            node = existing
        else:
            was_valid_src = False
            d_int = self.next_doc_int
            self.next_doc_int += 1
            uniq_ids = self._index_doc_tokens(d_int, title, body, cache_body_id=doc_id)
            node = CompactDocNode(
                doc_int_id=d_int,
                doc_id=doc_id,
                category=sys.intern(category),
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                snippet=body[:140],
                updated_at=updated_at,
                status=sys.intern("ACTIVE"),
                quarantined=0,
                uniq_token_ids=uniq_ids,
                ext_refs=set(),
                int_refs=set(),
                valid_citation_count=0,
            )
            self.docs_by_id[doc_id] = node
            self.docs_by_int[d_int] = node

        for raw_ref in new_citations:
            ref = str(raw_ref or "").strip()
            if not ref or ref == doc_id:
                continue
            if ref.startswith("doc_"):
                if ref not in node.int_refs:
                    node.int_refs.add(ref)
                    self.reverse_dependents[ref].add(doc_id)
                    src_node = self.docs_by_id.get(ref)
                    if src_node is not None and src_node.is_active_unquarantined():
                        node.valid_citation_count += 1
            else:
                if ref not in node.ext_refs:
                    node.ext_refs.add(ref)
                    node.valid_citation_count += 1

        is_valid_src = node.is_active_unquarantined()
        if was_valid_src != is_valid_src:
            delta = 1 if is_valid_src else -1
            for dep_id in self.reverse_dependents.get(doc_id, ()):
                dep_node = self.docs_by_id.get(dep_id)
                if dep_node is not None:
                    dep_node.valid_citation_count += delta

        self.doc_epoch += 1

    def apply_status_change(
        self,
        doc_id: str,
        *,
        status: str | None = None,
        quarantined: int | None = None,
        updated_at: int | None = None,
    ) -> None:
        if not self.loaded:
            return
        node = self.docs_by_id.get(doc_id)
        if node is None:
            return
        was_valid = node.is_active_unquarantined()
        if status is not None:
            node.status = sys.intern(status)
        if quarantined is not None:
            node.quarantined = quarantined
        if updated_at is not None:
            node.updated_at = updated_at
        is_valid = node.is_active_unquarantined()
        if was_valid != is_valid:
            delta = 1 if is_valid else -1
            for dep_id in self.reverse_dependents.get(doc_id, ()):
                dep_node = self.docs_by_id.get(dep_id)
                if dep_node is not None:
                    dep_node.valid_citation_count += delta
        self.doc_epoch += 1


class TenantAclState:
    """单租户独立隔离墙规则缓存（与文档纪元完全解耦）。"""

    def __init__(self) -> None:
        self.loaded: bool = False
        self.acl_epoch: int = 0
        # doc_id -> (user_id -> set[effect], org_node_id -> set[effect])
        self.rules_by_doc: dict[str, tuple[dict[str, set[str]], dict[str, set[str]]]] = {}

    def load_from_db(self, conn: sqlite3.Connection, tenant_id: str) -> None:
        self.rules_by_doc.clear()
        rows = conn.execute(
            "SELECT doc_id, subject_type, subject_id, effect FROM doc_acl_rules "
            "WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        for r in rows:
            did = str(r["doc_id"])
            pair = self.rules_by_doc.get(did)
            if pair is None:
                pair = ({}, {})
                self.rules_by_doc[did] = pair
            target_map = pair[0] if r["subject_type"] == "USER" else pair[1]
            sid = str(r["subject_id"])
            effs = target_map.get(sid)
            if effs is None:
                effs = set()
                target_map[sid] = effs
            effs.add(str(r["effect"]).upper())
        self.acl_epoch += 1
        self.loaded = True

    def apply_rule_change(
        self,
        doc_id: str,
        subject_type: str,
        subject_id: str,
        effect: str,
        active: bool,
    ) -> None:
        if not self.loaded:
            return
        pair = self.rules_by_doc.get(doc_id)
        if active:
            if pair is None:
                pair = ({}, {})
                self.rules_by_doc[doc_id] = pair
            target_map = pair[0] if subject_type == "USER" else pair[1]
            effs = target_map.get(subject_id)
            if effs is None:
                effs = set()
                target_map[subject_id] = effs
            effs.add(effect)
        elif pair is not None:
            target_map = pair[0] if subject_type == "USER" else pair[1]
            effs = target_map.get(subject_id)
            if effs is not None:
                effs.discard(effect)
                if not effs:
                    del target_map[subject_id]
            if not pair[0] and not pair[1]:
                del self.rules_by_doc[doc_id]
        self.acl_epoch += 1


class TenantPermState:
    """单租户组织树、原生角色与 1~2 跳受控借调委托内存视图（支持零写窗口过期降级）。"""

    def __init__(self) -> None:
        self.loaded: bool = False
        self.perm_epoch: int = 0
        self.tenant_status: str = ""
        # user_id -> (username, org_node_id, base_role, active, api_token_hash)
        self.users: dict[str, tuple[str, str, str, int, str]] = {}
        # node_id -> (parent_node_id, inherited_role)
        self.org_nodes: dict[str, tuple[str | None, str | None]] = {}
        self.org_lineages: dict[str, list[str]] = {}
        self.org_inherited_roles: dict[str, frozenset[str]] = {}
        self.role_grants: dict[str, set[str]] = defaultdict(set)
        self.native_roles: dict[str, frozenset[str]] = {}
        # grantee_user_id -> list[(grantor_user_id, delegated_role, starts_at, expires_at)]
        self.delegations_by_grantee: dict[str, list[tuple[str, str, int, int]]] = defaultdict(list)

    def _compute_lineage(self, start_node_id: str) -> list[str]:
        cached = self.org_lineages.get(start_node_id)
        if cached is not None:
            return cached
        lineage: list[str] = []
        curr: str | None = start_node_id
        visited: set[str] = set()
        while curr and curr not in visited:
            visited.add(curr)
            lineage.append(curr)
            info = self.org_nodes.get(curr)
            curr = info[0] if info else None
        self.org_lineages[start_node_id] = lineage
        return lineage

    def _recompute_user_native(self, user_id: str) -> frozenset[str]:
        u_info = self.users.get(user_id)
        if not u_info or u_info[3] != 1:
            self.native_roles[user_id] = frozenset()
            return frozenset()
        _, org_node_id, base_role, _, _ = u_info
        roles: set[str] = {base_role}
        inh = self.org_inherited_roles.get(org_node_id)
        if inh is None:
            inh_set: set[str] = set()
            for nid in self._compute_lineage(org_node_id):
                n_info = self.org_nodes.get(nid)
                if n_info and n_info[1]:
                    inh_set.add(n_info[1])
            inh = frozenset(inh_set)
            self.org_inherited_roles[org_node_id] = inh
        roles.update(inh)
        roles.update(self.role_grants.get(user_id, ()))
        frozen = frozenset(roles)
        self.native_roles[user_id] = frozen
        return frozen

    def load_from_db(self, conn: sqlite3.Connection, tenant_id: str) -> None:
        self.users.clear()
        self.org_nodes.clear()
        self.org_lineages.clear()
        self.org_inherited_roles.clear()
        self.role_grants.clear()
        self.native_roles.clear()
        self.delegations_by_grantee.clear()

        t_row = conn.execute(
            "SELECT status FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        self.tenant_status = str(t_row["status"]) if t_row else ""

        for nr in conn.execute(
            "SELECT node_id, parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall():
            self.org_nodes[str(nr["node_id"])] = (
                str(nr["parent_node_id"]) if nr["parent_node_id"] else None,
                str(nr["inherited_role"]) if nr["inherited_role"] else None,
            )

        for ur in conn.execute(
            "SELECT user_id, username, org_node_id, base_role, active, api_token_hash "
            "FROM users WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall():
            self.users[str(ur["user_id"])] = (
                str(ur["username"]),
                str(ur["org_node_id"]),
                str(ur["base_role"]),
                int(ur["active"]),
                str(ur["api_token_hash"]),
            )

        for gr in conn.execute(
            "SELECT user_id, granted_role FROM role_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall():
            self.role_grants[str(gr["user_id"])].add(str(gr["granted_role"]))

        for dr in conn.execute(
            "SELECT grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at "
            "FROM delegation_grants WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall():
            self.delegations_by_grantee[str(dr["grantee_user_id"])].append(
                (
                    str(dr["grantor_user_id"]),
                    str(dr["delegated_role"]),
                    int(dr["starts_at"]),
                    int(dr["expires_at"]),
                )
            )

        for nid in list(self.org_nodes.keys()):
            self._compute_lineage(nid)
        for uid in list(self.users.keys()):
            self._recompute_user_native(uid)

        self.perm_epoch += 1
        self.loaded = True

    def get_org_lineage(self, start_node_id: str) -> list[str]:
        return list(self._compute_lineage(start_node_id))

    def get_native_roles(self, user_id: str) -> set[str]:
        return set(self.native_roles.get(user_id, ()))

    def resolve_active_delegated_roles(self, grantee_user_id: str, at_ts: int) -> set[str]:
        """在任意时刻 at_ts 精确核验 1~2 跳有效借调链（免疫有向环路、上游过期自动降级）。"""
        u_info = self.users.get(grantee_user_id)
        if not u_info or u_info[3] != 1:
            return set()

        edges = self.delegations_by_grantee.get(grantee_user_id)
        if not edges:
            return set()

        effective: set[str] = set()
        # 分别按角色做最多 2 跳有向无环回溯
        candidate_roles = {
            role for _, role, s_ts, e_ts in edges if s_ts <= at_ts < e_ts
        }
        for role_name in candidate_roles:
            # BFS: (current_user_id, hop_dist), visited 防环
            visited = {grantee_user_id}
            queue: deque[tuple[str, int]] = deque([(grantee_user_id, 0)])
            found = False
            while queue and not found:
                curr_uid, hop = queue.popleft()
                if hop >= MAX_DELEGATION_HOPS:
                    continue
                for grantor_uid, e_role, s_ts, e_ts in self.delegations_by_grantee.get(curr_uid, ()):
                    if e_role != role_name or not (s_ts <= at_ts < e_ts):
                        continue
                    g_info = self.users.get(grantor_uid)
                    if not g_info or g_info[3] != 1:
                        continue
                    if role_name in self.native_roles.get(grantor_uid, ()):
                        effective.add(role_name)
                        found = True
                        break
                    if grantor_uid not in visited and hop + 1 < MAX_DELEGATION_HOPS:
                        visited.add(grantor_uid)
                        queue.append((grantor_uid, hop + 1))
        return effective

    def resolve_effective_permissions(self, user_id: str, at_ts: int) -> tuple[set[str], int]:
        native = self.native_roles.get(user_id)
        if not native:
            return set(), 0
        delegated = self.resolve_active_delegated_roles(user_id, at_ts)
        all_roles = set(native) | delegated
        max_cl = max((ROLE_DEFAULT_CLEARANCE.get(r, 1) for r in all_roles), default=1)
        return all_roles, max_cl

    def has_delegation_path(self, src_user_id: str, dst_user_id: str, role_name: str) -> bool:
        """检查当前激活委托边中是否存在 src_user_id -> ... -> dst_user_id 的有向路径（用于拒接成环）。"""
        # 沿着反向边从 dst_user_id 向上回溯至 src_user_id
        visited = {dst_user_id}
        queue: deque[str] = deque([dst_user_id])
        while queue:
            curr = queue.popleft()
            for grantor_uid, e_role, _, _ in self.delegations_by_grantee.get(curr, ()):
                if e_role != role_name:
                    continue
                if grantor_uid == src_user_id:
                    return True
                if grantor_uid not in visited:
                    visited.add(grantor_uid)
                    queue.append(grantor_uid)
        return False


class TenantRiskState:
    """单租户风控策略、受制裁实体、账户滑动窗口与 3-Hop 资金传染图状态。"""

    def __init__(self) -> None:
        self.policy_loaded: bool = False
        self.policy_epoch: int = 0
        self.policy: dict[str, Any] = {}

        self.sanctions_loaded: bool = False
        self.sanction_epoch: int = 0
        self.sanctioned_set: set[str] = set()

        self.graph_loaded: bool = False
        # node -> {neighbor: sorted list of tx timestamps}
        self.adj: dict[str, dict[str, list[int]]] = {}

        self.window_accounts: dict[str, AccountWindowState] = {}

    def load_policy(self, conn: sqlite3.Connection, tenant_id: str) -> dict[str, Any]:
        row = conn.execute(
            "SELECT tenant_id, policy_version, high_amount_cents, velocity_tx_limit, "
            "velocity_amount_cents, counterparty_fanout_limit, review_threshold, "
            "reject_threshold, custom_rules_json, updated_at "
            "FROM tenant_policies WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if not row:
            raise LookupError(f"Policy configuration missing for {tenant_id}")
        policy = dict(row)
        policy["custom_rules"] = json.loads(policy["custom_rules_json"])
        self.policy = policy
        self.policy_epoch += 1
        self.policy_loaded = True
        return dict(policy)

    def load_sanctions(self, conn: sqlite3.Connection, tenant_id: str) -> set[str]:
        rows = conn.execute(
            "SELECT entity_id FROM sanctioned_entities WHERE tenant_id = ? AND active = 1",
            (tenant_id,),
        ).fetchall()
        self.sanctioned_set = {str(r["entity_id"]) for r in rows}
        self.sanction_epoch += 1
        self.sanctions_loaded = True
        return self.sanctioned_set

    def load_graph(self, conn: sqlite3.Connection, tenant_id: str) -> None:
        self.adj.clear()
        rows = conn.execute(
            "SELECT account_id, counterparty_id, ts FROM transactions "
            "WHERE tenant_id = ? ORDER BY ts ASC",
            (tenant_id,),
        ).fetchall()
        for r in rows:
            self.add_edge(str(r["account_id"]), str(r["counterparty_id"]), int(r["ts"]))
        self.graph_loaded = True

    def add_edge(self, u: str, v: str, ts: int) -> None:
        u_map = self.adj.get(u)
        if u_map is None:
            self.adj[u] = {v: [ts]}
        else:
            lst = u_map.get(v)
            if lst is None:
                u_map[v] = [ts]
            elif not lst or ts >= lst[-1]:
                lst.append(ts)
            else:
                insort(lst, ts)
        if u != v:
            v_map = self.adj.get(v)
            if v_map is None:
                self.adj[v] = {u: [ts]}
            else:
                lst2 = v_map.get(u)
                if lst2 is None:
                    v_map[u] = [ts]
                elif not lst2 or ts >= lst2[-1]:
                    lst2.append(ts)
                else:
                    insort(lst2, ts)

    @staticmethod
    def has_edge_in_window(ts_list: list[int], win_start: int, ts: int) -> bool:
        if not ts_list:
            return False
        if len(ts_list) == 1:
            t0 = ts_list[0]
            return win_start <= t0 <= ts
        idx = bisect_left(ts_list, win_start)
        return idx < len(ts_list) and ts_list[idx] <= ts


class GatewayRuntime:
    """单数据库实例的完整线程安全运行时（连接池 + 分层无死锁锁表 + 隔离缓存）。"""

    def __init__(self, db_path: str | pathlib.Path) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self._pool: deque[sqlite3.Connection] = deque()
        self._pool_lock = threading.Lock()
        self._db_write_lock = threading.Lock()
        self._locks_guard = threading.Lock()

        self._doc_locks: dict[str, threading.RLock] = {}
        self._acl_locks: dict[str, threading.RLock] = {}
        self._perm_locks: dict[str, threading.RLock] = {}
        self._risk_locks: dict[str, threading.RLock] = {}
        self._quota_locks: dict[tuple[str, str], threading.Lock] = {}
        self._token_locks: dict[tuple[str, str], threading.Lock] = {}

        self._doc_indexes: dict[str, TenantDocIndex] = {}
        self._acl_states: dict[str, TenantAclState] = {}
        self._perm_states: dict[str, TenantPermState] = {}
        self._risk_states: dict[str, TenantRiskState] = {}

    def _get_lock(self, table: dict[Any, Any], key: Any, rlock: bool = False) -> Any:
        lk = table.get(key)
        if lk is not None:
            return lk
        with self._locks_guard:
            lk = table.get(key)
            if lk is None:
                lk = threading.RLock() if rlock else threading.Lock()
                table[key] = lk
            return lk

    def doc_lock(self, tenant_id: str) -> threading.RLock:
        return self._get_lock(self._doc_locks, tenant_id, rlock=True)

    def acl_lock(self, tenant_id: str) -> threading.RLock:
        return self._get_lock(self._acl_locks, tenant_id, rlock=True)

    def perm_lock(self, tenant_id: str) -> threading.RLock:
        return self._get_lock(self._perm_locks, tenant_id, rlock=True)

    def risk_lock(self, tenant_id: str) -> threading.RLock:
        return self._get_lock(self._risk_locks, tenant_id, rlock=True)

    def quota_lock(self, tenant_id: str, quota_type: str) -> threading.Lock:
        return self._get_lock(self._quota_locks, (tenant_id, quota_type), rlock=False)

    @contextlib.contextmanager
    def quota_pair_locks(self, tenant_id: str, q_a: str, q_b: str) -> Iterator[None]:
        """严格按字典序加锁双配额池，从根源消除跨池双向并发调拨死锁。"""
        first, second = (q_a, q_b) if q_a <= q_b else (q_b, q_a)
        lk1 = self.quota_lock(tenant_id, first)
        lk2 = self.quota_lock(tenant_id, second)
        with lk1:
            if second == first:
                yield
            else:
                with lk2:
                    yield

    def token_lock(self, tenant_id: str, token_id: str) -> threading.Lock:
        return self._get_lock(self._token_locks, (tenant_id, token_id), rlock=False)

    def acquire_conn(self) -> sqlite3.Connection:
        with self._pool_lock:
            if self._pool:
                conn = self._pool.pop()
                if conn.in_transaction:
                    conn.rollback()
                return conn
        return open_connection(self.db_path)

    def release_conn(self, conn: sqlite3.Connection) -> None:
        try:
            if conn.in_transaction:
                conn.rollback()
        except sqlite3.Error:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            return
        with self._pool_lock:
            if len(self._pool) < MAX_POOL_SIZE:
                self._pool.append(conn)
                return
        try:
            conn.close()
        except sqlite3.Error:
            pass

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.acquire_conn()
        try:
            yield conn
        finally:
            self.release_conn(conn)

    @contextlib.contextmanager
    def write_tx(self) -> Iterator[sqlite3.Connection]:
        """全局串行化 SQLite BEGIN IMMEDIATE 写事务，杜绝 SQLITE_BUSY 锁冲突。"""
        with self._db_write_lock:
            conn = self.acquire_conn()
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except BaseException:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                raise
            finally:
                self.release_conn(conn)

    def close_pool(self) -> None:
        with self._pool_lock:
            while self._pool:
                conn = self._pool.popleft()
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

    def get_doc_index(self, tenant_id: str) -> TenantDocIndex:
        idx = self._doc_indexes.get(tenant_id)
        if idx is None:
            with self._locks_guard:
                idx = self._doc_indexes.get(tenant_id)
                if idx is None:
                    idx = TenantDocIndex()
                    self._doc_indexes[tenant_id] = idx
        if not idx.loaded:
            with self.doc_lock(tenant_id):
                if not idx.loaded:
                    with self.connection() as conn:
                        idx.load_from_db(conn, tenant_id)
        return idx

    def get_acl_state(self, tenant_id: str) -> TenantAclState:
        st = self._acl_states.get(tenant_id)
        if st is None:
            with self._locks_guard:
                st = self._acl_states.get(tenant_id)
                if st is None:
                    st = TenantAclState()
                    self._acl_states[tenant_id] = st
        if not st.loaded:
            with self.acl_lock(tenant_id):
                if not st.loaded:
                    with self.connection() as conn:
                        st.load_from_db(conn, tenant_id)
        return st

    def get_perm_state(self, tenant_id: str) -> TenantPermState:
        st = self._perm_states.get(tenant_id)
        if st is None:
            with self._locks_guard:
                st = self._perm_states.get(tenant_id)
                if st is None:
                    st = TenantPermState()
                    self._perm_states[tenant_id] = st
        if not st.loaded:
            with self.perm_lock(tenant_id):
                if not st.loaded:
                    with self.connection() as conn:
                        st.load_from_db(conn, tenant_id)
        return st

    def get_risk_state(self, tenant_id: str) -> TenantRiskState:
        st = self._risk_states.get(tenant_id)
        if st is None:
            with self._locks_guard:
                st = self._risk_states.get(tenant_id)
                if st is None:
                    st = TenantRiskState()
                    self._risk_states[tenant_id] = st
        return st


_REGISTRY_LOCK = threading.Lock()
_RUNTIMES: dict[str, GatewayRuntime] = {}


def _norm_db_key(db_path: str | pathlib.Path) -> str:
    return str(pathlib.Path(db_path).resolve())


def get_runtime(db_path: str | pathlib.Path) -> GatewayRuntime:
    key = _norm_db_key(db_path)
    rt = _RUNTIMES.get(key)
    if rt is not None:
        return rt
    with _REGISTRY_LOCK:
        rt = _RUNTIMES.get(key)
        if rt is None:
            rt = GatewayRuntime(key)
            _RUNTIMES[key] = rt
        return rt


def create_gateway_runtime(db_path: str | pathlib.Path) -> GatewayRuntime:
    key = _norm_db_key(db_path)
    with _REGISTRY_LOCK:
        old = _RUNTIMES.pop(key, None)
        if old is not None:
            old.close_pool()
        rt = GatewayRuntime(key)
        _RUNTIMES[key] = rt
        return rt


def reset_runtime(db_path: str | pathlib.Path) -> None:
    key = _norm_db_key(db_path)
    with _REGISTRY_LOCK:
        old = _RUNTIMES.pop(key, None)
        if old is not None:
            old.close_pool()
