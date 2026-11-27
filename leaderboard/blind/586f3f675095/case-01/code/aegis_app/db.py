# -*- coding: utf-8 -*-
"""SQLite 存储模型定义、确定性多租户业务种子初始化器与线程安全连接/增量索引/纪元总线。

相对 v3.0 初始版本的架构级改动（三个层面）：

1. **连接与事务层**：按线程复用 WAL 连接（``DB.conn()``），写事务统一
   ``BEGIN IMMEDIATE`` + 有界重试（``DB.write``），并为高频读写补齐复合索引
   （``INDEX_SQL``，挂载既有库时幂等补建）；
2. **常驻加工视图**：合规文档的“标题/正文词频、去重词集、引用计数”由
   ``DocumentIndex`` 以 ``__slots__`` 紧凑节点增量维护；原始大正文 ``body`` 不常驻堆
   （命中文档按需回源数据库取 140 字符摘要）；
3. **多维纪元总线**：``EpochBus`` 为权限/隔离墙/策略/黑名单/配额各设独立纪元，
   任一类变更只让自身缓存代际失效，文档倒排索引只由文档自身增删驱动。
"""
from __future__ import annotations

import bisect
import hashlib
import json
import pathlib
import random
import sqlite3
import threading
import time
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Schema（核心表结构保持向后兼容）
# ---------------------------------------------------------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    tier TEXT NOT NULL,
    webhook_secret TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS org_nodes (
    node_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    parent_node_id TEXT,
    node_name TEXT NOT NULL,
    inherited_role TEXT
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    username TEXT NOT NULL,
    org_node_id TEXT NOT NULL,
    base_role TEXT NOT NULL,
    api_token_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS role_grants (
    grant_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    granted_role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS delegation_grants (
    delegation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    grantor_user_id TEXT NOT NULL,
    grantee_user_id TEXT NOT NULL,
    delegated_role TEXT NOT NULL,
    starts_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS doc_acl_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    effect TEXT NOT NULL DEFAULT 'DENY',
    active INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id TEXT PRIMARY KEY,
    policy_version INTEGER NOT NULL,
    high_amount_cents INTEGER NOT NULL,
    velocity_tx_limit INTEGER NOT NULL,
    velocity_amount_cents INTEGER NOT NULL,
    counterparty_fanout_limit INTEGER NOT NULL,
    review_threshold INTEGER NOT NULL,
    reject_threshold INTEGER NOT NULL,
    custom_rules_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sanctioned_entities (
    tenant_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    list_source TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, entity_id)
);

CREATE TABLE IF NOT EXISTS compliance_docs (
    doc_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    category TEXT NOT NULL,
    regulation_code TEXT NOT NULL,
    clearance_level INTEGER NOT NULL,
    risk_weight INTEGER NOT NULL,
    custom_tag TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    quarantined INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS doc_citations (
    citation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    doc_id TEXT NOT NULL,
    cited_by_ref TEXT NOT NULL,
    cited_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    tx_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    counterparty_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT NOT NULL,
    channel TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    ts INTEGER NOT NULL,
    metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_decisions (
    decision_id TEXT PRIMARY KEY,
    tx_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    decision TEXT NOT NULL,
    win_tx_count INTEGER NOT NULL,
    win_amount_cents INTEGER NOT NULL,
    win_unique_counterparties INTEGER NOT NULL,
    win_median_cents INTEGER NOT NULL,
    sanction_hop INTEGER NOT NULL,
    reasons_json TEXT NOT NULL,
    evaluated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id TEXT NOT NULL,
    quota_type TEXT NOT NULL,
    remaining_quota INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, quota_type)
);

CREATE TABLE IF NOT EXISTS quota_transfers (
    transfer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    from_quota TEXT NOT NULL,
    to_quota TEXT NOT NULL,
    amount INTEGER NOT NULL,
    ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS override_tokens (
    token_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_by TEXT,
    used_at INTEGER
);

CREATE TABLE IF NOT EXISTS webhook_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    callback_ts INTEGER NOT NULL,
    settlement_ref TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    raw_payload TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS report_templates (
    tenant_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    title_format TEXT NOT NULL,
    extra_event_filter TEXT NOT NULL DEFAULT '',
    sample_limit INTEGER NOT NULL DEFAULT 10,
    created_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, template_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    masked_account TEXT NOT NULL,
    ts INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_secrets (
    secret_key TEXT PRIMARY KEY,
    secret_value TEXT NOT NULL,
    classification TEXT NOT NULL
);
"""

# 追加式复合索引：用户/组织/委托/权限/隔离墙/文档/引用/交易/决策/审计/回调/配额
INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_users_tenant_user ON users(tenant_id, user_id, active);
CREATE INDEX IF NOT EXISTS idx_org_nodes_tenant ON org_nodes(tenant_id, node_id);
CREATE INDEX IF NOT EXISTS idx_grants_user ON role_grants(tenant_id, user_id, active);
CREATE INDEX IF NOT EXISTS idx_deleg_grantee ON delegation_grants(tenant_id, grantee_user_id, delegated_role, active);
CREATE INDEX IF NOT EXISTS idx_deleg_grantor ON delegation_grants(tenant_id, grantor_user_id, active);
CREATE INDEX IF NOT EXISTS idx_acl_doc ON doc_acl_rules(tenant_id, doc_id, active);
CREATE INDEX IF NOT EXISTS idx_docs_tenant_status ON compliance_docs(tenant_id, status, quarantined);
CREATE INDEX IF NOT EXISTS idx_docs_tenant_tag ON compliance_docs(tenant_id, custom_tag, status);
CREATE INDEX IF NOT EXISTS idx_cite_doc ON doc_citations(tenant_id, doc_id);
CREATE INDEX IF NOT EXISTS idx_tx_tenant_ts ON transactions(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_tx_tenant_acct_ts ON transactions(tenant_id, account_id, ts);
CREATE INDEX IF NOT EXISTS idx_dec_tenant ON risk_decisions(tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_log ON audit_logs(tenant_id, log_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_logs(tenant_id, ts);
CREATE UNIQUE INDEX IF NOT EXISTS uq_webhook_nonce ON webhook_events(tenant_id, nonce);
CREATE INDEX IF NOT EXISTS idx_quota_tenant ON tenant_quotas(tenant_id);
"""


def hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def open_connection(db_path: str | pathlib.Path) -> sqlite3.Connection:
    """新建独立连接（保留给外部脚本与兼容调用方；网关热路径统一走 ``DB.conn()``）。"""
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(db_path: str | pathlib.Path) -> None:
    path = pathlib.Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = open_connection(path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(INDEX_SQL)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 线程本地连接 + 统一写事务
# ---------------------------------------------------------------------------
class GatewayDB:
    """线程复用连接 + ``BEGIN IMMEDIATE`` 写事务（有界退避重试）。

    每个 ``SharedResources`` 绑定一个独立的 ``GatewayDB``，因此同一进程内挂载多个
    网关实例（不同数据库）时互不串线；线程本地缓存以实例对象为键。
    """

    __slots__ = ("path", "shared")

    def __init__(self, path: str) -> None:
        self.path = path
        self.shared = None
        self._bind_global()

    def _bind_global(self) -> None:
        """首个默认实例即进程级默认库，供按 db_path 隐式寻址的辅助模块使用。"""
        default = globals().get("_DEFAULT_DB")
        if default is not None and default is not self and default.path == "":
            default.path = self.path

    def bind(self, path: str) -> None:
        self.path = path

    def conn(self) -> sqlite3.Connection:
        cache = getattr(_TLS, "conns", None)
        if cache is None:
            cache = {}
            _TLS.conns = cache
        c = cache.get(id(self))
        if c is None:
            c = open_connection(self.path)
            c.execute("PRAGMA busy_timeout=60000")
            c.execute("PRAGMA synchronous=NORMAL")
            if len(cache) >= 32:
                try:
                    cache.pop(next(iter(cache))).close()
                except sqlite3.Error:
                    pass
            cache[id(self)] = c
        return c

    def attach(self, conn: sqlite3.Connection) -> None:
        """把一条外部连接登记为当前线程的连接（独立调用方复用同一事务）。"""
        cache = getattr(_TLS, "conns", None)
        if cache is None:
            cache = {}
            _TLS.conns = cache
        cache[id(self)] = conn

    def close_thread(self) -> None:
        cache = getattr(_TLS, "conns", None)
        if not cache:
            return
        c = cache.pop(id(self), None)
        if c is not None:
            try:
                c.close()
            except sqlite3.Error:
                pass

    def begin_write(self, conn: sqlite3.Connection) -> None:
        """开启 IMMEDIATE 写事务：整个进程内所有跨表/跨池原子更新共用同一串行化点。"""
        deadline = time.monotonic() + 5.0
        delay = 0.0005
        while True:
            if conn.in_transaction:
                conn.rollback()
            try:
                conn.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                msg = str(exc).lower()
                if ("busy" not in msg and "locked" not in msg) or time.monotonic() > deadline:
                    raise
                time.sleep(delay)
                delay = min(delay * 2.0, 0.05)

    def write(self, fn):
        """``fn(conn)`` 在单条 IMMEDIATE 事务中执行；成功提交，任何异常整体回滚。"""
        conn = self.conn()
        self.begin_write(conn)
        try:
            result = fn(conn)
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        conn.commit()
        return result

    def rows(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return self.conn().execute(sql, tuple(params)).fetchall()

    def cursor(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self.conn().execute(sql, tuple(params))

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.conn().execute(sql, tuple(params)).fetchone()


_TLS = threading.local()
_DEFAULT_DB = GatewayDB("")
DB = _DEFAULT_DB


# ---------------------------------------------------------------------------
# 多维纪元总线
# ---------------------------------------------------------------------------
class EpochBus:
    """维度纪元：``doc`` 为文档倒排纪元，其余维度（acl/perm/policy/sanction/quota）懒创建。"""

    __slots__ = ("doc", "dims")

    def __init__(self) -> None:
        self.doc = 0
        self.dims: dict[str, int] = {}

    def bump(self, dim: str) -> None:
        self.dims[dim] = self.dims.get(dim, 0) + 1

    def get(self, dim: str) -> int:
        return self.dims.get(dim, 0)

    def touch(self, dim: str) -> None:
        self.dims[dim] = self.dims.get(dim, 0) + 1


# ---------------------------------------------------------------------------
# 二维有序桶索引（去重集合规模剪枝用）
# ---------------------------------------------------------------------------
class BucketedIndex:
    """``{键: 降序有序数组}``；支持 O(log n) 计数与 O(缓冲) 增量写入。"""

    __slots__ = ("data", "_buf", "_dirty", "_buf_limit")

    def __init__(self, buf_limit: int = 512) -> None:
        self.data: dict[Any, list[int]] = {}
        self._buf: dict[Any, list[int]] = {}
        self._dirty = False
        self._buf_limit = buf_limit

    def add(self, key: Any, value: int) -> None:
        buf = self._buf.get(key)
        if buf is None:
            self._buf[key] = [value]
        else:
            buf.append(value)
        self._dirty = True
        if len(self._buf) > self._buf_limit:
            self.flush()

    def flush(self) -> None:
        if not self._dirty:
            return
        data = self.data
        for key, extra in self._buf.items():
            base = data.get(key)
            if base is None:
                data[key] = sorted(extra, reverse=True)
            else:
                merged = base + extra
                merged.sort(reverse=True)
                data[key] = merged
        self._buf.clear()
        self._dirty = False

    def count_ge(self, key: Any, value: int) -> int:
        """降序数组中 >= value 的元素个数。"""
        if self._dirty:
            self.flush()
        arr = self.data.get(key)
        if not arr:
            return 0
        return bisect.bisect_left(arr, -value, key=lambda v: -v)


# ---------------------------------------------------------------------------
# 文档索引：紧凑节点 + 增量倒排 + 双向引用图
# ---------------------------------------------------------------------------
class DocNode:
    """紧凑文档节点：不保存原始 ``body``，只保存至多 256 字符标题与检索加工量。

    * ``postings``：正文词 -> 截断词频（>= 12 记 12；未出现即为 0，与“首次出现”语义等价）；
    * ``title_counts``：标题词 -> 出现次数（仅含出现 >= 2 次的词，输出时再按 5 次上限截断，省内存）；
    * ``uniq``：标题 ∪ 正文的去重词集（Jaccard 集合）；
    * ``max_cap`` / ``lower_cap``：近似去重的活性规模上/下界。有效内部引用源被撤回/隔离/退役时，
      其贡献只从 ``lower_cap`` 扣除；``max_cap`` 始终 >= 真实交集，所以下界判定不出假阴性。
    """

    __slots__ = ("doc_id", "status", "quarantined", "clearance", "risk_weight", "category",
                 "tag", "updated_at", "title", "raw_reg_code", "postings", "title_counts", "uniq",
                 "title_uniq", "n_uniq", "canon_reg", "max_cap", "lower_cap", "ext_cites",
                 "self_cites")

    def __init__(self, doc_id, status, quarantined, clearance, risk_weight, category, tag,
                 updated_at, title, raw_reg_code, postings, title_counts, uniq, title_uniq, n_uniq,
                 canon_reg, max_cap, lower_cap, ext_cites) -> None:
        self.doc_id = doc_id
        self.status = status
        self.quarantined = quarantined
        self.clearance = clearance
        self.risk_weight = risk_weight
        self.category = category
        self.tag = tag
        self.updated_at = updated_at
        self.title = title
        self.raw_reg_code = raw_reg_code
        self.postings = postings
        self.title_counts = title_counts
        self.uniq = uniq
        self.title_uniq = title_uniq
        self.n_uniq = n_uniq
        self.canon_reg = canon_reg
        self.max_cap = max_cap
        self.lower_cap = lower_cap
        self.ext_cites = ext_cites
        self.self_cites = 0
    def live(self) -> bool:
        return self.status == "ACTIVE" and not self.quarantined


class DocTenantView:
    """单租户检索视图：节点表、词->存活文档倒排、全租户去重词桶、双向引用图。"""

    __slots__ = ("nodes", "postings", "citers", "ref_citers", "category_docs", "tags", "title_postings")

    def __init__(self) -> None:
        self.nodes: dict[str, DocNode] = {}
        self.postings: dict[str, dict[str, DocNode]] = {}
        self.title_postings: dict[str, dict[str, DocNode]] = {}
        self.citers: dict[str, dict[str, int]] = {}
        self.ref_citers: dict[str, set[str]] = {}
        # 原版 ``custom_tag = '<值>'``（值同时被当作表名）与分类过滤的等价增量倒排；
        # 随单篇写入/状态翻转 O(1)~O(出度) 维护。
        self.category_docs: dict[str, set[str]] = {}
        self.tags: dict[str, set[str]] = {}


class DocumentIndex:
    """跨租户文档索引：单篇增量 O(词数 + 出度)，状态翻转 O(出度)，从不整库重建。"""

    __slots__ = ("views", "epoch")

    def __init__(self) -> None:
        self.views: dict[str, DocTenantView] = {}
        self.epoch = EpochBus()

    # -- 装载 --------------------------------------------------------------
    def view(self, tenant_id: str) -> DocTenantView:
        v = self.views.get(tenant_id)
        if v is None:
            v = DocTenantView()
            self.views[tenant_id] = v
            self._load_tenant(v, tenant_id)
        return v

    def _load_tenant(self, v: DocTenantView, tenant_id: str) -> None:
        from .doc_indexer import TokenProfile
        cur = DB.cursor(
            "SELECT doc_id, clearance_level, risk_weight, category, custom_tag, title, body, updated_at "
            "FROM compliance_docs WHERE tenant_id = ? AND status = 'ACTIVE' AND quarantined = 0",
            (tenant_id,),
        )
        while True:
            batch = cur.fetchmany(256)
            if not batch:
                break
            for r in batch:
                self._index_node(v, {
                    "doc_id": r["doc_id"],
                    "clearance": int(r["clearance_level"]),
                    "risk_weight": int(r["risk_weight"]),
                    "category": r["category"],
                    "custom_tag": r["custom_tag"],
                    "title": r["title"] or "",
                    "body": r["body"] or "",
                    "updated_at": int(r["updated_at"]),
                }, TokenProfile)
        cur.close()
        for r in DB.rows("SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?", (tenant_id,)):
            self.apply_citation(v, r["doc_id"], r["cited_by_ref"])

    @staticmethod
    def apply_citation(v: DocTenantView, target: Any, ref_raw: Any) -> None:
        """登记一条已落库引用 ``(被引用方 target, 引用源 ref_raw)``（装载与增量写入共用同一语义）。"""
        target = str(target or "")
        ref = str(ref_raw or "").strip()
        if not target or not ref:
            return
        if ref == target:
            # 自引用：不构成有效内部引用（不触发联动传播），但原版按“其他引用”计入被引用次数
            tnode = v.nodes.get(target)
            if tnode is not None:
                tnode.self_cites += 1
            return
        v.ref_citers.setdefault(ref, set()).add(target)
        if ref.startswith("doc_"):
            src = v.nodes.get(ref)
            if src is not None and src.live():
                d = v.citers.setdefault(target, {})
                d[ref] = d.get(ref, 0) + 1
        else:
            node = v.nodes.get(target)
            if node is not None:
                node.ext_cites += 1

    @staticmethod
    def _index_node(v: DocTenantView, rec: dict[str, Any], token_profile_cls) -> DocNode:
        from .doc_indexer import TokenProfile
        from .legacy_compat import canonicalize_regulation_code
        prof = token_profile_cls.build(rec["title"], rec["body"])
        body_tf = prof.body_tf
        postings = {t: (c if c < 12 else 12) for t, c in body_tf.items()}
        title_repeat = {t: c for t, c in prof.title_tf.items() if c > 1}
        title_uniq = set(prof.title_tf)
        node = DocNode(
            rec["doc_id"], "ACTIVE", 0, rec["clearance"], rec["risk_weight"], rec["category"],
            rec["custom_tag"], rec["updated_at"], rec["title"][:256],
            rec.get("regulation_code") or "", postings, title_repeat,
            frozenset(set(body_tf) | title_uniq), title_uniq, len(title_uniq) + len(body_tf),
            canonicalize_regulation_code(rec.get("regulation_code") or ""),
            len(title_uniq) + len(body_tf), len(title_uniq) + 1, rec.get("ext_cites", 0),
        )
        _ = TokenProfile
        v.nodes[node.doc_id] = node
        for tok in postings:
            v.postings.setdefault(tok, {})[node.doc_id] = node
        # 标题词单独成桶：标题命中而正文未命中的文档同样可被检索到
        for tok in title_uniq:
            v.title_postings.setdefault(tok, {})[node.doc_id] = node
        cat = rec.get("category")
        if cat:
            v.category_docs.setdefault(cat, set()).add(node.doc_id)
        tag = rec.get("custom_tag")
        if tag:
            v.tags.setdefault(tag, set()).add(node.doc_id)
        return node
    # -- 写入 --------------------------------------------------------------
    def put_document(self, tenant_id: str, rec: dict[str, Any]) -> None:
        """按单篇文档最新完整记录增量更新索引（O(出度 + 词数)）。"""
        from .doc_indexer import TokenProfile
        v = self.view(tenant_id)
        doc_id = rec["doc_id"]
        live = rec["status"] == "ACTIVE" and rec["quarantined"] == 0
        self._detach_as_source(v, doc_id)
        old = v.nodes.get(doc_id)
        if old is not None:
            old.self_cites = 0     # 引用明细整体替换语义：自引用计数随本次重挂重建
            v.nodes.pop(doc_id, None)
            self._remove_postings(v, old)
        if live:
            self._index_node(v, rec, TokenProfile)
            self._attach_as_source(v, doc_id)
        self.epoch.touch("doc")

    def change_status(self, tenant_id: str, doc_id: str, *, status: str | None = None,
                      quarantined: int | None = None) -> None:
        """状态翻转：引用联动 O(出度)，倒排移除 O(词数)；不重建整租户索引。"""
        v = self.views.get(tenant_id)
        if v is None:
            return
        node = v.nodes.get(doc_id)
        if node is None:
            return
        was_live = node.live()
        self._detach_as_source(v, doc_id)
        if status is not None:
            node.status = status
        if quarantined is not None:
            node.quarantined = quarantined
        if node.live():
            self._attach_as_source(v, doc_id)
        elif was_live:
            self._remove_postings(v, node)
            v.nodes.pop(doc_id, None)
        self.epoch.touch("doc")

    def add_citations(self, tenant_id: str, refs: Iterable[tuple[str, str]]) -> None:
        """登记已落库引用关系 ``(引用源 doc_id, 被引用 ref)``，O(度数) 传播。"""
        v = self.view(tenant_id)
        for src, ref in refs:
            ref = str(ref or "").strip()
            if not ref:
                continue
            self.apply_citation(v, src, ref)
        self.epoch.touch("doc")

    def citation_count(self, tenant_id: str, doc_id: str) -> int:
        v = self.view(tenant_id)
        node = v.nodes.get(doc_id)
        if node is None:
            return 0
        return node.ext_cites + len(v.citers.get(doc_id, ()))

    # -- 内部 --------------------------------------------------------------
    @staticmethod
    def _remove_postings(v: DocTenantView, node: DocNode) -> None:
        for table, keys in ((v.postings, node.postings), (v.title_postings, node.title_uniq)):
            for tok in keys:
                m = table.get(tok)
                if m is not None:
                    m.pop(node.doc_id, None)
                    if not m:
                        table.pop(tok, None)
        for table, key in (
            (v.category_docs, node.category),
            (v.tags, node.tag),
        ):
            if not key:
                continue
            bucket = table.get(key)
            if bucket is not None:
                bucket.discard(node.doc_id)
                if not bucket:
                    table.pop(key, None)

    def _detach_as_source(self, v: DocTenantView, doc_id: str) -> None:
        """若 doc_id 当前是有效内部引用源，撤销其对下游被引用方的计数贡献（O(出度)）。"""
        src = v.nodes.get(doc_id)
        if src is None or not src.live():
            return
        for target in v.ref_citers.get(doc_id, ()):
            d = v.citers.get(target)
            if d is not None:
                d.pop(doc_id, None)
                if not d:
                    v.citers.pop(target, None)
            tnode = v.nodes.get(target)
            if tnode is not None:
                tnode.lower_cap -= 1

    def _attach_as_source(self, v: DocTenantView, doc_id: str) -> None:
        """doc_id 变为有效源后恢复其对下游被引用方的计数贡献（O(出度)）。"""
        for target in v.ref_citers.get(doc_id, ()):
            node = v.nodes.get(target)
            if node is None:
                continue
            d = v.citers.setdefault(target, {})
            d[doc_id] = d.get(doc_id, 0) + 1
            node.lower_cap += 1


# ---------------------------------------------------------------------------
# 网关级共享资源
# ---------------------------------------------------------------------------
class SharedResources:
    """单网关实例的共享加工层：增量索引、纪元总线、各维度有界缓存与单一全局消息锁。

    并发模型（性能—安全平衡）：
    * ``lock`` 只在 Python 内存结构（索引、缓存、分层比率计、黑名单集合）的读写临界区
      持有，**绝不在其中执行任何 SQLite 语句**；写数据库先后固定为
      “先 ``BEGIN IMMEDIATE`` 完成全部 SQL → 再持锁做内存增量提交 → 最后 ``COMMIT``”，
      从而与所有跨表/跨池原子更新共享同一全局偏序，不存在锁环；
    * 各缓存均有容量上限并做 LRU 淘汰，常驻堆不会随租户数或文档数无界增长。
    """

    __slots__ = ("db", "storage_dir", "index", "epoch", "lock", "policy_cache", "token_cache",
                 "org_cache", "acl_cache", "realtime", "cred_cache", "diag_cache", "stamp",
                 "windows", "contagion")

    def __init__(self, path: str, storage_dir: str) -> None:
        from .acl_wall import WindowAclCache
        from .contagion_graph import ContagionStore
        from .window_stats import WindowRegistry
        self.db = GatewayDB(path)
        self.storage_dir = storage_dir
        self.index = DocumentIndex()
        self.epoch = EpochBus()
        self.lock = threading.Lock()
        self.stamp = 0
        self.policy_cache: dict[str, tuple[int, dict[str, Any]]] = {}
        self.token_cache: dict[str, str] = {}
        self.org_cache: dict[tuple[str, str], tuple[bytes, list[str]]] = {}
        self.acl_cache = WindowAclCache()
        self.cred_cache: dict[tuple[str, str, str], tuple[int, Any]] = {}
        self.realtime: dict[str, Any] = {}
        self.diag_cache: dict[str, Any] = {}
        self.windows = WindowRegistry()
        self.contagion = ContagionStore()

    def view(self, tenant_id: str) -> DocTenantView:
        return self.index.view(tenant_id)


# ---------------------------------------------------------------------------
# 确定性种子数据（与 v3.0 初始版本逐字一致，保证评测数据集不变）
# ---------------------------------------------------------------------------
_REGULATION_TOPICS = [
    ("AML", "FATF-R16", "wire transfer originator beneficiary travel rule verification thresholds"),
    ("AML", "FATF-REC-16", "wire transfer originator beneficiary travel rule legacy cross border"),
    ("AML", "FINCEN-314A", "suspicious activity structuring cross border correspondent banking monitoring"),
    ("SANCTIONS", "OFAC-50PCT", "blocked entity ownership aggregation screening vessel flag embargo"),
    ("SANCTIONS", "OFAC-RULE-50", "blocked entity ownership aggregation legacy maritime screening embargo"),
    ("SANCTIONS", "EU-269", "asset freeze designated person indirect control economic resources restriction"),
    ("PRIVACY", "GDPR-ART32", "encryption pseudonymisation confidentiality integrity resilience processing"),
    ("PRIVACY", "PIPL-CROSS", "standard contract security assessment outbound personal financial data"),
    ("LIQUIDITY", "BASEL-LCR", "high quality liquid assets net cash outflows thirty day stress scenario"),
    ("CARD", "PCI-DSS4", "primary account number masking strong cryptography key rotation audit trail"),
]

_EXTRA_VOCAB = [
    "settlement", "clearing", "nostro", "vostro", "escrow", "chargeback", "velocity",
    "beneficiary", "remittance", "jurisdiction", "threshold", "escalation", "quorum",
    "attestation", "ledger", "reconciliation", "counterparty", "custody", "derivative",
    "collateral", "underwriting", "kyc", "onboarding", "pep", "adverse", "screening",
]


def seed_dataset(
    db_path: str | pathlib.Path,
    storage_dir: str | pathlib.Path,
    *,
    seed: int = 20261122,
    num_tenants: int = 2,
    docs_per_tenant: int = 28,
    tx_per_tenant: int = 72,
    audit_rows_per_tenant: int = 80,
    base_ts: int = 1760000000,
) -> dict[str, Any]:
    """按确定性种子初始化多租户业务数据、多级组织树、借调委托、制裁图谱边与快照文件。"""
    from .config import MASTER_SIGNING_PEPPER

    init_schema(db_path)
    storage_root = pathlib.Path(storage_dir)
    storage_root.mkdir(parents=True, exist_ok=True)

    secret_canary = f"CANARY-ROOT-VAULT-{hashlib.sha256(f'{seed}:{MASTER_SIGNING_PEPPER}'.encode()).hexdigest()[:16]}"
    (storage_root / "system_vault.json").write_text(
        json.dumps(
            {
                "vault_canary": secret_canary,
                "master_pepper": MASTER_SIGNING_PEPPER,
                "db_file": str(pathlib.Path(db_path).resolve()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    rng = random.Random(seed)
    conn = open_connection(db_path)
    manifest: dict[str, Any] = {
        "seed": seed,
        "base_ts": base_ts,
        "secret_canary": secret_canary,
        "tenants": {},
    }

    try:
        conn.execute(
            "INSERT OR REPLACE INTO system_secrets(secret_key, secret_value, classification) VALUES (?, ?, ?)",
            ("VAULT_CANARY", secret_canary, "RESTRICTED_ROOT"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO system_secrets(secret_key, secret_value, classification) VALUES (?, ?, ?)",
            ("MASTER_SIGNING_PEPPER", MASTER_SIGNING_PEPPER, "RESTRICTED_ROOT"),
        )

        tenant_names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
        for t_idx in range(num_tenants):
            t_slug = tenant_names[t_idx] if t_idx < len(tenant_names) else f"t{t_idx + 1:02d}"
            tenant_id = f"tenant_{t_slug}"
            webhook_secret = f"whsec_{t_slug}_{hashlib.sha256(f'wh:{seed}:{tenant_id}'.encode()).hexdigest()[:20]}"

            conn.execute(
                "INSERT OR REPLACE INTO tenants(tenant_id, name, tier, webhook_secret, status) VALUES (?, ?, ?, ?, 'ACTIVE')",
                (tenant_id, f"Aegis {t_slug.title()} Financial", "ENTERPRISE", webhook_secret),
            )

            # 5 层组织架构树（含 ops_team 下的特殊子团队 ops_special_unit 用于检验最近祖先覆盖规则）
            nodes = [
                (f"{tenant_id}_root", tenant_id, None, "Executive HQ", "VIEWER"),
                (f"{tenant_id}_risk_div", tenant_id, f"{tenant_id}_root", "Risk Division", "ANALYST"),
                (f"{tenant_id}_audit_dept", tenant_id, f"{tenant_id}_risk_div", "Audit Department", "SENIOR_AUDITOR"),
                (f"{tenant_id}_ops_team", tenant_id, f"{tenant_id}_root", "Operations Team", "VIEWER"),
                (f"{tenant_id}_ops_special", tenant_id, f"{tenant_id}_ops_team", "Special Clearance Desk", "ANALYST"),
                (f"{tenant_id}_research_desk", tenant_id, f"{tenant_id}_root", "Advisory Research Desk", "ANALYST"),
            ]
            conn.executemany(
                "INSERT OR REPLACE INTO org_nodes(node_id, tenant_id, parent_node_id, node_name, inherited_role) VALUES (?, ?, ?, ?, ?)",
                nodes,
            )

            users_spec = [
                ("admin", f"{tenant_id}_root", "COMPLIANCE_ADMIN"),
                ("auditor", f"{tenant_id}_audit_dept", "ANALYST"),
                ("analyst", f"{tenant_id}_ops_team", "ANALYST"),
                ("specialist", f"{tenant_id}_ops_special", "ANALYST"),
                ("researcher", f"{tenant_id}_research_desk", "ANALYST"),
                ("viewer", f"{tenant_id}_ops_team", "VIEWER"),
            ]
            user_tokens: dict[str, dict[str, str]] = {}
            for role_key, node_id, base_role in users_spec:
                uid = f"usr_{t_slug}_{role_key}"
                raw_tok = f"tok_{t_slug}_{role_key}_{hashlib.md5(f'{seed}:{uid}'.encode()).hexdigest()[:12]}"
                conn.execute(
                    "INSERT OR REPLACE INTO users(user_id, tenant_id, username, org_node_id, base_role, api_token_hash, active) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (uid, tenant_id, f"{role_key}@{t_slug}.example.com", node_id, base_role, hash_api_token(raw_tok)),
                )
                user_tokens[role_key] = {"user_id": uid, "token": raw_tok, "base_role": base_role}

            conn.execute(
                "INSERT INTO role_grants(tenant_id, user_id, granted_role, active, updated_at) VALUES (?, ?, ?, 1, ?)",
                (tenant_id, user_tokens["auditor"]["user_id"], "SENIOR_AUDITOR", base_ts),
            )

            # 预置一级借调委托（auditor -> researcher: [base_ts - 3600, base_ts + 7200)）
            # 及二级转借调委托（researcher -> specialist: [base_ts + 200, base_ts + 9000)）
            conn.execute(
                "INSERT INTO delegation_grants(tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at) "
                "VALUES (?, ?, ?, 'SENIOR_AUDITOR', ?, ?, 1, ?)",
                (
                    tenant_id,
                    user_tokens["auditor"]["user_id"],
                    user_tokens["researcher"]["user_id"],
                    base_ts - 3600,
                    base_ts + 7200,
                    base_ts - 3600,
                ),
            )
            conn.execute(
                "INSERT INTO delegation_grants(tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at) "
                "VALUES (?, ?, ?, 'SENIOR_AUDITOR', ?, ?, 1, ?)",
                (
                    tenant_id,
                    user_tokens["researcher"]["user_id"],
                    user_tokens["specialist"]["user_id"],
                    base_ts + 200,
                    base_ts + 9000,
                    base_ts - 1800,
                ),
            )

            custom_rules = {
                "op": "OR",
                "children": [
                    {
                        "op": "AND",
                        "children": [
                            {"field": "channel", "op": "EQ", "value": "CRYPTO_BRIDGE"},
                            {"field": "amount_cents", "op": "GTE", "value": 250000},
                        ],
                        "bonus_score": 22,
                        "reason": "CRYPTO_HIGH_VALUE",
                    },
                    {
                        "op": "AND",
                        "children": [
                            {"field": "channel", "op": "EQ", "value": "WIRE_INTL"},
                            {"field": "amount_cents", "op": "GTE", "value": 800000},
                        ],
                        "bonus_score": 16,
                        "reason": "WIRE_INTL_LARGE",
                    },
                ],
            }
            conn.execute(
                "INSERT OR REPLACE INTO tenant_policies("
                "tenant_id, policy_version, high_amount_cents, velocity_tx_limit, velocity_amount_cents, "
                "counterparty_fanout_limit, review_threshold, reject_threshold, custom_rules_json, updated_at"
                ") VALUES (?, 1, ?, ?, ?, ?, 45, 75, ?, ?)",
                (
                    tenant_id,
                    500000 + t_idx * 50000,
                    5,
                    1200000,
                    4,
                    json.dumps(custom_rules),
                    base_ts,
                ),
            )

            # 初始化受制裁黑名单实体与多层资金链路（sanctioned_entity -> bridge_cp -> mule_acct -> ...）
            sanc_entity = f"ent_{t_slug}_sanctioned_01"
            conn.execute(
                "INSERT OR REPLACE INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
                "VALUES (?, ?, 'OFAC_SDN', 1, ?)",
                (tenant_id, sanc_entity, base_ts),
            )

            doc_rows = []
            citation_rows = []
            secret_doc_marker = f"TOPSECRET-{tenant_id.upper()}-MARKER-{hashlib.md5(tenant_id.encode()).hexdigest()[:8]}"
            wall_doc_id = f"doc_{t_slug}_0003"
            wall_doc_marker = f"CHINESEWALL-{tenant_id.upper()}-DEAL-{hashlib.md5((tenant_id + ':wall').encode()).hexdigest()[:8]}"

            for d_idx in range(docs_per_tenant):
                cat, reg_code, core_phrase = _REGULATION_TOPICS[d_idx % len(_REGULATION_TOPICS)]
                doc_id = f"doc_{t_slug}_{d_idx + 1:04d}"
                if d_idx == 0:
                    clearance = 4
                    extra_words = f"{secret_doc_marker} classified board resolution liquidity contingency wire screening"
                elif d_idx == 2:
                    clearance = 2
                    extra_words = f"{wall_doc_marker} merger acquisition target valuation advisory embargo screening"
                elif d_idx % 7 == 0:
                    clearance = 4
                    extra_words = "executive restricted supervisory enforcement escalation protocol"
                elif d_idx % 4 == 0:
                    clearance = 3
                    extra_words = "confidential internal audit exception remediation action plan"
                elif d_idx % 2 == 0:
                    clearance = 2
                    extra_words = "standard operational compliance checklist verification procedure"
                else:
                    clearance = 1
                    extra_words = "public regulatory guidance summary obligations overview"

                cluster_variant = (d_idx // len(_REGULATION_TOPICS)) % 3
                picked_vocab = [
                    _EXTRA_VOCAB[(d_idx + k * 3 + t_idx) % len(_EXTRA_VOCAB)]
                    for k in range(6)
                ]
                appendix_clause = (
                    f" Regulatory archival schedule for {tenant_id} section {d_idx + 1}: "
                    + " ".join(picked_vocab)
                    + " "
                    + ("supervisory compliance record retention governance attestation " * 6).strip()
                    + "."
                )
                if cluster_variant in (0, 1) and d_idx >= len(_REGULATION_TOPICS):
                    shared_anchor = [
                        _EXTRA_VOCAB[((d_idx % len(_REGULATION_TOPICS)) + k * 3 + t_idx) % len(_EXTRA_VOCAB)]
                        for k in range(8)
                    ]
                    shared_tail = (
                        " ".join(shared_anchor)
                        + " "
                        + ("supervisory compliance record retention governance attestation " * 6).strip()
                    )
                    body_text = (
                        f"{extra_words}. Tenant {t_slug} policy directive for {reg_code}. "
                        f"Core mandate: {core_phrase}. "
                        f"Operational scope: {shared_tail} {' '.join(picked_vocab[:2])}."
                    )
                else:
                    body_text = (
                        f"{extra_words}. Tenant {t_slug} reference manual {d_idx + 1} under {reg_code}. "
                        f"Mandate: {core_phrase}. "
                        f"Specific controls: {' '.join(picked_vocab)}.{appendix_clause}"
                    )

                title_text = f"[{reg_code}] {cat} Control Standard Rev-{d_idx + 1}"
                tag_val = f"tag_{cat.lower()}_{(d_idx % 5) + 1}"
                risk_w = 10 + ((d_idx * 7 + t_idx * 3) % 40)
                upd_ts = base_ts - (docs_per_tenant - d_idx) * 600
                doc_rows.append(
                    (
                        doc_id,
                        tenant_id,
                        cat,
                        reg_code,
                        clearance,
                        risk_w,
                        tag_val,
                        title_text,
                        body_text,
                        "ACTIVE",
                        0,
                        upd_ts,
                    )
                )
                num_cites = (d_idx + t_idx) % 5
                for c_i in range(num_cites):
                    citation_rows.append((tenant_id, doc_id, f"ref_{t_slug}_{d_idx}_{c_i}", upd_ts + c_i * 10))
                if d_idx >= 3 and (d_idx % 3 == 0):
                    peer_idx = ((d_idx - 2) % docs_per_tenant) + 1
                    peer_doc_id = f"doc_{t_slug}_{peer_idx:04d}"
                    if peer_doc_id != doc_id:
                        citation_rows.append((tenant_id, doc_id, peer_doc_id, upd_ts + 55))

            if docs_per_tenant >= 6:
                citation_rows.append((tenant_id, f"doc_{t_slug}_0006", f"doc_{t_slug}_0002", base_ts - 120))
                citation_rows.append((tenant_id, f"doc_{t_slug}_0002", f"doc_{t_slug}_0005", base_ts - 110))

            conn.executemany(
                "INSERT OR REPLACE INTO compliance_docs("
                "doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
                "custom_tag, title, body, status, quarantined, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                doc_rows,
            )
            conn.executemany(
                "INSERT INTO doc_citations(tenant_id, doc_id, cited_by_ref, cited_at) VALUES (?, ?, ?, ?)",
                citation_rows,
            )

            # 多层级利益冲突墙：父部门 ops_team 设为 DENY，但子部门 ops_special 显式设为 ALLOW（检验最近组织节点优先级覆盖！）
            if docs_per_tenant >= 3:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, 'ORG_NODE', ?, 'DENY', 1, ?)",
                    (tenant_id, wall_doc_id, f"{tenant_id}_ops_team", base_ts),
                )
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, 'ORG_NODE', ?, 'ALLOW', 1, ?)",
                    (tenant_id, wall_doc_id, f"{tenant_id}_ops_special", base_ts + 1),
                )

            channels = ["WIRE_INTL", "CRYPTO_BRIDGE", "CARD_CNP", "ACH_BATCH", "POS_CHIP"]
            num_accounts = max(6, tx_per_tenant // 12)
            tx_rows = []
            dec_rows = []

            # 构造确定性的 2 跳 / 3 跳制裁传染边：
            # sanc_entity <--(tx1)--> bridge_hop1 <--(tx2)--> acct_{slug}_002
            hop_edges = [
                (f"tx_{t_slug}_sanc_e1", f"bridge_{t_slug}_h1", sanc_entity, 95000, base_ts - 3600),
                (f"tx_{t_slug}_sanc_e2", f"acct_{t_slug}_002", f"bridge_{t_slug}_h1", 88000, base_ts - 1800),
            ]
            for h_tx_id, h_acct, h_cp, h_amt, h_ts in hop_edges:
                tx_rows.append(
                    (
                        h_tx_id,
                        tenant_id,
                        "batch_hist_sanc",
                        h_acct,
                        h_cp,
                        h_amt,
                        "USD",
                        "WIRE_INTL",
                        f"sanc.monitor@{t_slug}-partner.org",
                        h_ts,
                        json.dumps({"region": "EU", "tag": "chain"}),
                    )
                )

            for x_idx in range(tx_per_tenant):
                tx_id = f"tx_{t_slug}_hist_{x_idx + 1:05d}"
                dec_id = f"dec_{t_slug}_hist_{x_idx + 1:05d}"
                acct_id = f"acct_{t_slug}_{(x_idx % num_accounts) + 1:03d}"
                cp_id = f"cp_{(x_idx * 5 + t_idx) % 25 + 1:03d}"
                amt = 15000 + rng.randint(1, 90) * 10000
                ch = channels[(x_idx + t_idx) % len(channels)]
                tx_ts = base_ts - 120000 + int((x_idx / max(1, tx_per_tenant)) * 115000)
                email = f"billing.{acct_id}@{t_slug}-partner.org"
                tx_rows.append(
                    (
                        tx_id,
                        tenant_id,
                        "batch_hist_init",
                        acct_id,
                        cp_id,
                        amt,
                        "USD",
                        ch,
                        email,
                        tx_ts,
                        json.dumps({"region": "APAC" if x_idx % 2 == 0 else "EU", "device": f"dev_{x_idx % 10}"}),
                    )
                )
                dec_rows.append(
                    (
                        dec_id,
                        tx_id,
                        tenant_id,
                        acct_id,
                        25 + (x_idx % 50),
                        "ALLOW" if (x_idx % 5 != 0) else "REVIEW",
                        1 + (x_idx % 4),
                        amt,
                        1 + (x_idx % 3),
                        amt,
                        0,
                        json.dumps(["HISTORICAL_BASELINE"]),
                        tx_ts,
                    )
                )
            conn.executemany(
                "INSERT OR REPLACE INTO transactions("
                "tx_id, tenant_id, batch_id, account_id, counterparty_id, amount_cents, "
                "currency, channel, contact_email, ts, metadata_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tx_rows,
            )
            conn.executemany(
                "INSERT OR REPLACE INTO risk_decisions("
                "decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
                "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
                "sanction_hop, reasons_json, evaluated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                dec_rows,
            )

            # 多配额池（支撑单池扣减与跨池原子调拨）
            conn.execute(
                "INSERT OR REPLACE INTO tenant_quotas(tenant_id, quota_type, remaining_quota, updated_at) VALUES (?, 'EMERGENCY_EXPORT', 5, ?)",
                (tenant_id, base_ts),
            )
            conn.execute(
                "INSERT OR REPLACE INTO tenant_quotas(tenant_id, quota_type, remaining_quota, updated_at) VALUES (?, 'RESERVE_BUFFER_POOL', 50, ?)",
                (tenant_id, base_ts),
            )
            conn.execute(
                "INSERT OR REPLACE INTO tenant_quotas(tenant_id, quota_type, remaining_quota, updated_at) VALUES (?, 'REALTIME_ALERT_POOL', 50, ?)",
                (tenant_id, base_ts),
            )
            conn.execute(
                "INSERT OR REPLACE INTO tenant_quotas(tenant_id, quota_type, remaining_quota, updated_at) VALUES (?, 'SCARCE_REVIEW_SLOT', 1, ?)",
                (tenant_id, base_ts),
            )
            override_tok = f"ovt_{t_slug}_single_use_01"
            conn.execute(
                "INSERT OR REPLACE INTO override_tokens(token_id, tenant_id, purpose, used) VALUES (?, ?, 'CRITICAL_WIRE_RELEASE', 0)",
                (override_tok, tenant_id),
            )

            # 默认审计报表模板
            conn.execute(
                "INSERT OR REPLACE INTO report_templates(tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at) "
                "VALUES (?, 'tpl_default_q4', '[{tenant_id}] Compliance Summary ({total_records} events)', '', 5, ?, ?)",
                (tenant_id, user_tokens["admin"]["user_id"], base_ts),
            )

            severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            event_types = ["RISK_EVAL", "DOC_ACCESS", "POLICY_CHECK", "SETTLEMENT_ACK"]
            audit_rows = []
            padding_note = "compliance-audit-verification-record-" * 8
            for a_idx in range(audit_rows_per_tenant):
                sev = severities[(a_idx * 3 + t_idx) % len(severities)]
                evt = event_types[a_idx % len(event_types)]
                amt = ((a_idx * 137 + t_idx * 50) % 400) * 1000
                a_ts = base_ts - 80000 + a_idx * 30
                masked_acc = f"****{(1000 + (a_idx % 9000)):04d}"
                payload = json.dumps(
                    {
                        "seq": a_idx + 1,
                        "trace_ref": f"tr_{t_slug}_{a_idx:06d}",
                        "summary_note": padding_note,
                        "verified": True,
                    }
                )
                audit_rows.append(
                    (
                        tenant_id,
                        user_tokens["analyst"]["user_id"],
                        evt,
                        sev,
                        amt,
                        masked_acc,
                        a_ts,
                        payload,
                    )
                )
            conn.executemany(
                "INSERT INTO audit_logs("
                "tenant_id, actor_id, event_type, severity, amount_cents, masked_account, ts, payload_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                audit_rows,
            )

            snap_dir = storage_root / tenant_id / "snapshots"
            snap_dir.mkdir(parents=True, exist_ok=True)
            (snap_dir / "2026-Q3.json").write_text(
                json.dumps(
                    {
                        "tenant_id": tenant_id,
                        "period": "2026-Q3",
                        "archived_docs": docs_per_tenant,
                        "integrity_tag": hashlib.sha256(f"snap:{tenant_id}:2026-Q3".encode()).hexdigest()[:16],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (snap_dir / "2026-Q4.json").write_text(
                json.dumps(
                    {
                        "tenant_id": tenant_id,
                        "period": "2026-Q4",
                        "archived_docs": docs_per_tenant,
                        "integrity_tag": hashlib.sha256(f"snap:{tenant_id}:2026-Q4".encode()).hexdigest()[:16],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            manifest["tenants"][tenant_id] = {
                "tenant_id": tenant_id,
                "slug": t_slug,
                "webhook_secret": webhook_secret,
                "secret_doc_id": f"doc_{t_slug}_0001",
                "secret_doc_marker": secret_doc_marker,
                "wall_doc_id": wall_doc_id,
                "wall_doc_marker": wall_doc_marker,
                "sanctioned_entity": sanc_entity,
                "sample_decision_id": f"dec_{t_slug}_hist_00001",
                "sample_tx_id": f"tx_{t_slug}_hist_00001",
                "override_token": override_tok,
                "users": user_tokens,
            }

        conn.commit()
    finally:
        conn.close()

    return manifest


