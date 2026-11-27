# -*- coding: utf-8 -*-
"""租户级合规文档增量索引、双向引用传播图与紧凑常驻内存预算控制。

设计要点（与原版「每次变动全量重建」的根本差异）：

1. **紧凑常驻结构**：索引节点 ``DocNode`` 使用 ``__slots__``，仅保留元数据、
   分词后的紧凑 token 元组（``sys.intern`` 共享字符串池）与引用集合，
   **绝不常驻整库原始大正文 ``body``**；正文仅在真正需要输出片段时按页取回。

2. **单篇增量更新**：文档新增/修订只重新分词该文档（O(该文档词数)），
   绝不因单篇写入而推倒重建整租户倒排结构。

3. **双向引用传播图**：``cite_refs``（文档 -> 唯一引用源）与
   ``reverse_dependents``（被引用文档 -> 引用它的文档）双向维护。
   当内部 ``doc_`` 引用源发生 ``RETIRED``/``quarantined`` 状态翻转时，
   仅沿 ``reverse_dependents`` 做 **O(deg) 局部更新**，被引用方的有效
   ``citation_count`` 立即精确联动，无需全量重算。

4. **缓存有界**：索引按租户分片，节点数/token 总数超过硬预算时自动降级为
   「不缓存 + 直接流式扫描」模式，杜绝常驻堆内存无界膨胀。
"""
from __future__ import annotations

import sqlite3
import sys
from typing import Any, Iterable

from .doc_indexer import tokenize_text
from .legacy_compat import canonicalize_regulation_code

# 常驻堆内存硬预算：单租户索引最多缓存的 token 总数上限。
MAX_INDEX_TOKENS = 400_000
# 单租户索引最多缓存的文档节点数上限。
MAX_INDEX_DOCS = 20_000


def _intern_tokens(text: str) -> tuple[str, ...]:
    """分词并 intern 化：相同词元在全库共享同一字符串对象，极大压缩常驻堆。"""
    return tuple(sys.intern(tok) for tok in tokenize_text(text))


class DocNode:
    """单篇文档的紧凑索引节点（``__slots__`` 杜绝 __dict__ 常驻开销）。"""

    __slots__ = (
        "doc_id",
        "category",
        "regulation_code",
        "canon_reg",
        "clearance_level",
        "risk_weight",
        "custom_tag",
        "title",
        "updated_at",
        "status",
        "quarantined",
        "title_tokens",
        "body_tokens",
        "cite_refs",
    )

    def __init__(
        self,
        *,
        doc_id: str,
        category: str,
        regulation_code: str,
        clearance_level: int,
        risk_weight: int,
        custom_tag: str,
        title: str,
        updated_at: int,
        status: str,
        quarantined: bool,
        title_tokens: tuple[str, ...],
        body_tokens: tuple[str, ...],
    ) -> None:
        self.doc_id = doc_id
        self.category = category
        self.regulation_code = regulation_code
        self.canon_reg = canonicalize_regulation_code(regulation_code)
        self.clearance_level = int(clearance_level)
        self.risk_weight = int(risk_weight)
        self.custom_tag = custom_tag
        self.title = title
        self.updated_at = int(updated_at)
        self.status = status
        self.quarantined = bool(quarantined)
        self.title_tokens = title_tokens
        self.body_tokens = body_tokens
        self.cite_refs: set[str] = set()


class TenantDocIndex:
    """单租户文档索引：元数据 + 引用传播图 + 有效引用计数缓存。"""

    __slots__ = (
        "tenant_id",
        "nodes",
        "reverse_dependents",
        "cite_count",
        "token_budget_used",
        "usable",
    )

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self.nodes: dict[str, DocNode] = {}
        self.reverse_dependents: dict[str, set[str]] = {}
        self.cite_count: dict[str, int] = {}
        self.token_budget_used = 0
        self.usable = True

    # -- 构建 -------------------------------------------------------------
    def build(self, conn: sqlite3.Connection) -> None:
        """全量构建（仅在首次访问或缓存失效时执行）。"""
        self.nodes.clear()
        self.reverse_dependents.clear()
        self.cite_count.clear()
        self.token_budget_used = 0

        rows = conn.execute(
            "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, "
            "custom_tag, title, body, status, quarantined, updated_at "
            "FROM compliance_docs WHERE tenant_id = ?",
            (self.tenant_id,),
        ).fetchall()
        for row in rows:
            node = self._make_node(row)
            if node is None:
                continue
            self.nodes[node.doc_id] = node
            self.token_budget_used += len(node.title_tokens) + len(node.body_tokens)

        cite_rows = conn.execute(
            "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
            (self.tenant_id,),
        ).fetchall()
        for row in cite_rows:
            self._register_ref(str(row["doc_id"]), str(row["cited_by_ref"] or ""))

        for doc_id in self.nodes:
            self._recompute_citation_count(doc_id)

        if len(self.nodes) > MAX_INDEX_DOCS or self.token_budget_used > MAX_INDEX_TOKENS:
            # 超预算：主动降级（清空常驻结构），改走流式扫描模式。
            self.degrade()

    def _make_node(self, row: sqlite3.Row) -> DocNode | None:
        node = DocNode(
            doc_id=str(row["doc_id"]),
            category=str(row["category"]),
            regulation_code=str(row["regulation_code"]),
            clearance_level=int(row["clearance_level"]),
            risk_weight=int(row["risk_weight"]),
            custom_tag=str(row["custom_tag"]),
            title=str(row["title"]),
            updated_at=int(row["updated_at"]),
            status=str(row["status"]),
            quarantined=bool(int(row["quarantined"])),
            title_tokens=_intern_tokens(str(row["title"])),
            body_tokens=_intern_tokens(str(row["body"])),
        )
        return node

    def degrade(self) -> None:
        """降级：释放常驻结构，后续请求走数据库流式扫描（正确性不受影响）。"""
        self.nodes.clear()
        self.reverse_dependents.clear()
        self.cite_count.clear()
        self.token_budget_used = 0
        self.usable = False

    # -- 引用传播 ---------------------------------------------------------
    def _register_ref(self, doc_id: str, ref: str) -> bool:
        ref = ref.strip()
        node = self.nodes.get(doc_id)
        if not node or not ref or ref == doc_id:
            return False
        if ref in node.cite_refs:
            return False
        node.cite_refs.add(ref)
        self.reverse_dependents.setdefault(ref, set()).add(doc_id)
        return True

    def _recompute_citation_count(self, doc_id: str) -> int:
        node = self.nodes.get(doc_id)
        if node is None:
            return 0
        count = 0
        for ref in node.cite_refs:
            if ref.startswith("doc_"):
                target = self.nodes.get(ref)
                if (
                    target is not None
                    and target.status == "ACTIVE"
                    and not target.quarantined
                ):
                    count += 1
            else:
                count += 1
        self.cite_count[doc_id] = count
        return count

    def effective_citation_count(self, doc_id: str) -> int:
        cached = self.cite_count.get(doc_id)
        if cached is not None:
            return cached
        return self._recompute_citation_count(doc_id)

    def apply_status_change(self, doc_id: str, *, status: str | None = None, quarantined: bool | None = None) -> None:
        """文档状态/隔离翻转：沿反向引用图做 O(deg) 局部联动更新。"""
        node = self.nodes.get(doc_id)
        if node is None:
            return
        if status is not None:
            node.status = status
        if quarantined is not None:
            node.quarantined = bool(quarantined)
        # 被引用方的有效引用计数立即联动（仅遍历引用了本文档的文档）。
        for dependent in self.reverse_dependents.get(doc_id, ()):  # O(deg)
            self._recompute_citation_count(dependent)
        self._recompute_citation_count(doc_id)

    # -- 增量写入 ---------------------------------------------------------
    def upsert_doc(
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
        status: str,
        quarantined: bool,
        updated_at: int,
    ) -> None:
        """单篇增量写入：仅重新分词该文档。"""
        node = self.nodes.get(doc_id)
        new_title_tokens = _intern_tokens(title)
        new_body_tokens = _intern_tokens(body)
        if node is None:
            if len(self.nodes) >= MAX_INDEX_DOCS:
                self.degrade()
                return
            node = DocNode(
                doc_id=doc_id,
                category=category,
                regulation_code=regulation_code,
                clearance_level=clearance_level,
                risk_weight=risk_weight,
                custom_tag=custom_tag,
                title=title,
                updated_at=updated_at,
                status=status,
                quarantined=quarantined,
                title_tokens=new_title_tokens,
                body_tokens=new_body_tokens,
            )
            self.nodes[doc_id] = node
            self.token_budget_used += len(new_title_tokens) + len(new_body_tokens)
        else:
            self.token_budget_used -= len(node.title_tokens) + len(node.body_tokens)
            node.category = category
            node.regulation_code = regulation_code
            node.canon_reg = canonicalize_regulation_code(regulation_code)
            node.clearance_level = int(clearance_level)
            node.risk_weight = int(risk_weight)
            node.custom_tag = custom_tag
            node.title = title
            node.updated_at = int(updated_at)
            node.status = status
            node.quarantined = bool(quarantined)
            node.title_tokens = new_title_tokens
            node.body_tokens = new_body_tokens
            self.token_budget_used += len(new_title_tokens) + len(new_body_tokens)

        if self.token_budget_used > MAX_INDEX_TOKENS:
            self.degrade()
            return
        self._recompute_citation_count(doc_id)

    def add_citations(self, doc_id: str, refs: Iterable[str]) -> None:
        """新增引用记录：更新引用集合与反向引用图，并即时刷新受影响计数。"""
        added = False
        for ref in refs:
            if self._register_ref(doc_id, str(ref)):
                added = True
        if added:
            self._recompute_citation_count(doc_id)
            for dependent in self.reverse_dependents.get(doc_id, ()):  # O(deg)
                self._recompute_citation_count(dependent)

    # -- 查询辅助 ---------------------------------------------------------
    def doc_ids(self) -> list[str]:
        return list(self.nodes.keys())

    def snapshot_meta(self, doc_id: str) -> dict[str, Any] | None:
        node = self.nodes.get(doc_id)
        if node is None:
            return None
        return {
            "doc_id": node.doc_id,
            "category": node.category,
            "regulation_code": node.regulation_code,
            "_canon_reg": node.canon_reg,
            "clearance_level": node.clearance_level,
            "risk_weight": node.risk_weight,
            "custom_tag": node.custom_tag,
            "title": node.title,
            "updated_at": node.updated_at,
        }
