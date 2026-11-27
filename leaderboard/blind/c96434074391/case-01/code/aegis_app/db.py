# -*- coding: utf-8 -*-
"""SQLite 存储模型、有界连接池、全局统一锁偏序协调器与确定性多租户种子初始化器。"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
import hashlib
import json
import os
import pathlib
import random
import sqlite3
import threading
import zlib
from typing import Any, Iterator

from .config import (
    DB_POOL_MAX_SIZE,
    DB_RUNTIME_CACHE_MAX,
    MASTER_SIGNING_PEPPER,
    TENANT_STATE_CACHE_MAX,
)


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

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_users_tenant_uid ON users(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_org_nodes_tenant_node ON org_nodes(tenant_id, node_id);
CREATE INDEX IF NOT EXISTS idx_role_grants_tenant_user_active ON role_grants(tenant_id, user_id, active);
CREATE INDEX IF NOT EXISTS idx_delegations_tenant_grantee_active ON delegation_grants(tenant_id, grantee_user_id, active);
CREATE INDEX IF NOT EXISTS idx_delegations_tenant_grantor_active ON delegation_grants(tenant_id, grantor_user_id, active);
CREATE INDEX IF NOT EXISTS idx_doc_acl_tenant_doc_active ON doc_acl_rules(tenant_id, doc_id, active);
CREATE INDEX IF NOT EXISTS idx_docs_tenant_status_q ON compliance_docs(tenant_id, status, quarantined);
CREATE INDEX IF NOT EXISTS idx_citations_tenant_doc ON doc_citations(tenant_id, doc_id);
CREATE INDEX IF NOT EXISTS idx_tx_tenant_acct_ts ON transactions(tenant_id, account_id, ts);
CREATE INDEX IF NOT EXISTS idx_tx_tenant_ts ON transactions(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_id_tenant ON risk_decisions(decision_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_sanctions_tenant_active ON sanctioned_entities(tenant_id, active);
CREATE INDEX IF NOT EXISTS idx_override_tok_tenant ON override_tokens(token_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_covering_scan ON audit_logs(tenant_id, log_id, event_type, severity, amount_cents, masked_account, ts);
CREATE INDEX IF NOT EXISTS idx_audit_evt_covering ON audit_logs(tenant_id, event_type, log_id, severity, amount_cents, masked_account, ts);
CREATE INDEX IF NOT EXISTS idx_audit_sev_covering ON audit_logs(tenant_id, severity, log_id, event_type, amount_cents, masked_account, ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_tenant_nonce_uniq ON webhook_events(tenant_id, nonce);
"""


def hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -8000")
        conn.execute("PRAGMA busy_timeout = 30000")
    except sqlite3.Error:
        pass
    return conn


def open_connection(db_path: str | pathlib.Path) -> sqlite3.Connection:
    conn = sqlite3.connect(
        str(db_path),
        timeout=30.0,
        isolation_level=None,
        check_same_thread=False,
    )
    return _configure_connection(conn)


class BoundedConnectionPool:
    """严格有界 SQLite 连接池（支持多线程借还与自动回滚异常未决事务）。"""

    __slots__ = ("db_path", "max_size", "_lock", "_idle", "_closed")

    def __init__(self, db_path: str, max_size: int = DB_POOL_MAX_SIZE) -> None:
        self.db_path = db_path
        self.max_size = max_size
        self._lock = threading.Lock()
        self._idle: list[sqlite3.Connection] = []
        self._closed = False

    def acquire(self) -> sqlite3.Connection:
        with self._lock:
            if not self._closed and self._idle:
                return self._idle.pop()
        return open_connection(self.db_path)

    def release(self, conn: sqlite3.Connection) -> None:
        try:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            return

        with self._lock:
            if self._closed or len(self._idle) >= self.max_size:
                should_close = True
            else:
                self._idle.append(conn)
                should_close = False
        if should_close:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    def close_all(self) -> None:
        with self._lock:
            self._closed = True
            conns = list(self._idle)
            self._idle.clear()
        for c in conns:
            try:
                c.close()
            except sqlite3.Error:
                pass


class BoundedLRUMap:
    """线程安全有界 LRU 容器，防止恶意或海量租户键导致常驻堆内存无界膨胀。"""

    __slots__ = ("max_entries", "_lock", "_data")

    def __init__(self, max_entries: int = TENANT_STATE_CACHE_MAX) -> None:
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._data: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str) -> Any | None:
        with self._lock:
            val = self._data.get(key)
            if val is not None:
                self._data.move_to_end(key)
            return val

    def set(self, key: str, value: Any) -> Any:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)
            return value

    def get_or_create(self, key: str, factory: Any) -> Any:
        with self._lock:
            val = self._data.get(key)
            if val is not None:
                self._data.move_to_end(key)
                return val
        created = factory()
        with self._lock:
            existing = self._data.get(key)
            if existing is not None:
                self._data.move_to_end(key)
                return existing
            self._data[key] = created
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)
            return created

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class DatabaseRuntime:
    """单数据库实例的并发锁偏序协调器、连接池与多维正交状态注册表。

    全局锁严格单向偏序（Layer 1 -> Layer 2 -> Layer 3）：
      Layer 1: 租户风控评估条带锁 (_risk_stripes, 128 固定槽位)
      Layer 2: 租户配额桶字典序条带锁 (_quota_stripes, 256 固定槽位，多桶按升序槽位号获取)
      Layer 3: SQLite BEGIN IMMEDIATE 写事务锁 (在持有 Layer 3 期间严禁反向请求 Layer 1/2)
    """

    __slots__ = (
        "db_path",
        "file_ctime_ns",
        "pool",
        "_risk_stripes",
        "_quota_stripes",
        "_tenant_meta_stripes",
        "auth_cache",
        "acl_cache",
        "doc_index_cache",
        "window_cache",
        "contagion_cache",
        "policy_cache",
        "_indexes_ensured",
        "_init_lock",
    )

    def __init__(self, db_path: str, file_ctime_ns: int) -> None:
        self.db_path = db_path
        self.file_ctime_ns = file_ctime_ns
        self.pool = BoundedConnectionPool(db_path, DB_POOL_MAX_SIZE)
        self._risk_stripes = tuple(threading.Lock() for _ in range(128))
        self._quota_stripes = tuple(threading.Lock() for _ in range(256))
        self._tenant_meta_stripes = tuple(threading.RLock() for _ in range(128))
        self.auth_cache = BoundedLRUMap(TENANT_STATE_CACHE_MAX)
        self.acl_cache = BoundedLRUMap(TENANT_STATE_CACHE_MAX)
        self.doc_index_cache = BoundedLRUMap(TENANT_STATE_CACHE_MAX)
        self.window_cache = BoundedLRUMap(TENANT_STATE_CACHE_MAX)
        self.contagion_cache = BoundedLRUMap(TENANT_STATE_CACHE_MAX)
        self.policy_cache = BoundedLRUMap(TENANT_STATE_CACHE_MAX)
        self._indexes_ensured = False
        self._init_lock = threading.Lock()

    def ensure_indexes(self) -> None:
        if self._indexes_ensured:
            return
        with self._init_lock:
            if self._indexes_ensured:
                return
            conn = self.pool.acquire()
            try:
                for stmt in INDEX_SQL.strip().split(";"):
                    s = stmt.strip()
                    if s:
                        try:
                            conn.execute(s)
                        except sqlite3.Error:
                            pass
                self._indexes_ensured = True
            finally:
                self.pool.release(conn)

    def tenant_meta_lock(self, tenant_id: str) -> threading.RLock:
        idx = zlib.crc32(tenant_id.encode("utf-8")) & 0x7F
        return self._tenant_meta_stripes[idx]

    @contextmanager
    def acquire_risk_lock(self, tenant_id: str) -> Iterator[None]:
        idx = zlib.crc32(f"risk:{tenant_id}".encode("utf-8")) & 0x7F
        lk = self._risk_stripes[idx]
        lk.acquire()
        try:
            yield
        finally:
            lk.release()

    @contextmanager
    def acquire_quota_locks(self, tenant_id: str, *bucket_names: str) -> Iterator[None]:
        slot_indices = sorted(
            {
                zlib.crc32(f"quota:{tenant_id}:{b}".encode("utf-8")) & 0xFF
                for b in bucket_names
            }
        )
        acquired: list[threading.Lock] = []
        try:
            for idx in slot_indices:
                lk = self._quota_stripes[idx]
                lk.acquire()
                acquired.append(lk)
            yield
        finally:
            for lk in reversed(acquired):
                lk.release()

    @contextmanager
    def read_conn(self) -> Iterator[sqlite3.Connection]:
        self.ensure_indexes()
        conn = self.pool.acquire()
        try:
            yield conn
        finally:
            self.pool.release(conn)

    @contextmanager
    def write_tx(self) -> Iterator[sqlite3.Connection]:
        self.ensure_indexes()
        conn = self.pool.acquire()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        finally:
            self.pool.release(conn)

    def clear_caches(self) -> None:
        self.auth_cache.clear()
        self.acl_cache.clear()
        self.doc_index_cache.clear()
        self.window_cache.clear()
        self.contagion_cache.clear()
        self.policy_cache.clear()

    def close(self) -> None:
        self.clear_caches()
        self.pool.close_all()


_RUNTIMES_LOCK = threading.Lock()
_RUNTIMES: OrderedDict[str, DatabaseRuntime] = OrderedDict()


def _stat_ctime_ns(norm_path: str) -> int:
    try:
        return os.stat(norm_path).st_ctime_ns
    except OSError:
        return 0


def get_db_runtime(db_path: str | pathlib.Path) -> DatabaseRuntime:
    norm = str(pathlib.Path(db_path).resolve())
    cur_ctime = _stat_ctime_ns(norm)
    evicted: list[DatabaseRuntime] = []
    with _RUNTIMES_LOCK:
        rt = _RUNTIMES.get(norm)
        if rt is not None:
            if cur_ctime and rt.file_ctime_ns and cur_ctime != rt.file_ctime_ns:
                # 同路径数据库已被外部删除重建，销毁旧运行时
                evicted.append(rt)
                del _RUNTIMES[norm]
                rt = None
            else:
                if cur_ctime and not rt.file_ctime_ns:
                    rt.file_ctime_ns = cur_ctime
                _RUNTIMES.move_to_end(norm)
        if rt is None:
            rt = DatabaseRuntime(norm, cur_ctime)
            _RUNTIMES[norm] = rt
            while len(_RUNTIMES) > DB_RUNTIME_CACHE_MAX:
                _, old_rt = _RUNTIMES.popitem(last=False)
                evicted.append(old_rt)
    for old in evicted:
        old.close()
    return rt


def reset_db_runtime(db_path: str | pathlib.Path, *, close_pool: bool = False) -> None:
    norm = str(pathlib.Path(db_path).resolve())
    removed: DatabaseRuntime | None = None
    with _RUNTIMES_LOCK:
        rt = _RUNTIMES.get(norm)
        if rt is not None:
            if close_pool:
                removed = _RUNTIMES.pop(norm)
            else:
                rt.clear_caches()
                rt.file_ctime_ns = _stat_ctime_ns(norm)
    if removed is not None:
        removed.close()


def init_schema(db_path: str | pathlib.Path) -> None:
    path = pathlib.Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = open_connection(path)
    try:
        conn.executescript(SCHEMA_SQL)
        for stmt in INDEX_SQL.strip().split(";"):
            s = stmt.strip()
            if s:
                try:
                    conn.execute(s)
                except sqlite3.Error:
                    pass
    finally:
        conn.close()


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
    reset_db_runtime(db_path, close_pool=True)
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
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
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
