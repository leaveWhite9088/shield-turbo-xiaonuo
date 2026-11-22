# -*- coding: utf-8 -*-
"""SQLite 存储层与确定性业务数据初始化模块。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import random
import sqlite3
import threading
from typing import Any

from .config import MASTER_SIGNING_PEPPER


class ConflictError(Exception):
    """业务冲突异常（主键冲突、配额不足、一次性令牌或 Webhook 重放等，映射为 HTTP 409）。"""

    def __init__(self, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.status_code = status_code


INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_org_nodes_tenant_node
    ON org_nodes(tenant_id, node_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_user
    ON users(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_role_grants_tenant_user_active
    ON role_grants(tenant_id, user_id, active);
CREATE INDEX IF NOT EXISTS idx_doc_acl_tenant_doc_active
    ON doc_acl_rules(tenant_id, doc_id, active);
CREATE INDEX IF NOT EXISTS idx_doc_acl_tenant_active
    ON doc_acl_rules(tenant_id, active);
CREATE INDEX IF NOT EXISTS idx_docs_tenant_active_q
    ON compliance_docs(tenant_id, status, quarantined, clearance_level);
CREATE INDEX IF NOT EXISTS idx_docs_tenant_cat
    ON compliance_docs(tenant_id, status, quarantined, category);
CREATE INDEX IF NOT EXISTS idx_docs_tenant_tag
    ON compliance_docs(tenant_id, status, quarantined, custom_tag);
CREATE INDEX IF NOT EXISTS idx_citations_doc
    ON doc_citations(doc_id);
CREATE INDEX IF NOT EXISTS idx_citations_tenant_doc
    ON doc_citations(tenant_id, doc_id);
CREATE INDEX IF NOT EXISTS idx_tx_tenant_acct_ts
    ON transactions(tenant_id, account_id, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_tenant_id
    ON risk_decisions(tenant_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_log
    ON audit_logs(tenant_id, log_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts_log
    ON audit_logs(tenant_id, ts, log_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_sev_ts_log
    ON audit_logs(tenant_id, severity, ts, log_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_tenant_nonce
    ON webhook_events(tenant_id, nonce);
"""


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


_THREAD_LOCAL = threading.local()
_INIT_LOCK = threading.Lock()
_INITIALIZED_DBS: set[str] = set()


def _normalize_db_path(db_path: str | pathlib.Path) -> str:
    return str(pathlib.Path(db_path).resolve())


def hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _configure_pragmas(conn: sqlite3.Connection, *, set_wal: bool = False) -> None:
    if set_wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-32000")
    conn.execute("PRAGMA mmap_size=67108864")


def open_connection(db_path: str | pathlib.Path) -> sqlite3.Connection:
    """打开指向网关数据库的连接。"""
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    _configure_pragmas(conn, set_wal=False)
    return conn


def get_thread_connection(db_path: str | pathlib.Path) -> sqlite3.Connection:
    """获取当前线程针对目标数据库的复用连接（autocommit 模式，配合显式 BEGIN IMMEDIATE 控制写事务）。"""
    norm = _normalize_db_path(db_path)
    conns: dict[str, sqlite3.Connection] | None = getattr(_THREAD_LOCAL, "conns", None)
    if conns is None:
        conns = {}
        _THREAD_LOCAL.conns = conns
    conn = conns.get(norm)
    if conn is not None:
        return conn
    ensure_db_optimized(norm)
    conn = sqlite3.connect(norm, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    _configure_pragmas(conn, set_wal=False)
    conns[norm] = conn
    return conn


def ensure_db_optimized(db_path: str | pathlib.Path) -> None:
    """对存量或新建数据库幂等开启 WAL 模式并补齐缺失二级索引（绝不清空已有数据）。"""
    norm = _normalize_db_path(db_path)
    if norm in _INITIALIZED_DBS:
        return
    with _INIT_LOCK:
        if norm in _INITIALIZED_DBS:
            return
        path = pathlib.Path(norm)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(norm, timeout=30.0)
        try:
            _configure_pragmas(conn, set_wal=True)
            conn.executescript(SCHEMA_SQL)
            conn.executescript(INDEX_SQL)
            conn.commit()
        finally:
            conn.close()
        _INITIALIZED_DBS.add(norm)


def init_schema(db_path: str | pathlib.Path) -> None:
    """幂等初始化核心业务表结构、WAL 模式与二级索引。"""
    norm = _normalize_db_path(db_path)
    with _INIT_LOCK:
        _INITIALIZED_DBS.discard(norm)
    ensure_db_optimized(norm)


_REGULATION_TOPICS = [
    ("AML", "FATF-R16", "wire transfer originator beneficiary travel rule verification thresholds"),
    ("AML", "FINCEN-314A", "suspicious activity structuring cross border correspondent banking monitoring"),
    ("SANCTIONS", "OFAC-50PCT", "blocked entity ownership aggregation screening vessel flag embargo"),
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
    docs_per_tenant: int = 24,
    tx_per_tenant: int = 60,
    audit_rows_per_tenant: int = 80,
    base_ts: int = 1760000000,
) -> dict[str, Any]:
    """按给定确定性种子生成多租户数据集（含利益冲突隔离墙规则与归档快照）。"""
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

            # 组织层级树（含两个同密级但处于利益冲突墙两侧的平行团队：research_desk vs ops_team）
            nodes = [
                (f"{tenant_id}_root", tenant_id, None, "Executive HQ", "VIEWER"),
                (f"{tenant_id}_risk_div", tenant_id, f"{tenant_id}_root", "Risk Division", "ANALYST"),
                (f"{tenant_id}_audit_dept", tenant_id, f"{tenant_id}_risk_div", "Audit Department", "SENIOR_AUDITOR"),
                (f"{tenant_id}_ops_team", tenant_id, f"{tenant_id}_root", "Operations Team", "VIEWER"),
                (f"{tenant_id}_research_desk", tenant_id, f"{tenant_id}_root", "Advisory Research Desk", "ANALYST"),
            ]
            conn.executemany(
                "INSERT OR REPLACE INTO org_nodes(node_id, tenant_id, parent_node_id, node_name, inherited_role) VALUES (?, ?, ?, ?, ?)",
                nodes,
            )

            # 增加 researcher（与 analyst 同样是最高密级 2 ANALYST，但归属 research_desk，不受 ops_team 利益冲突墙限制！）
            users_spec = [
                ("admin", f"{tenant_id}_root", "COMPLIANCE_ADMIN"),
                ("auditor", f"{tenant_id}_audit_dept", "ANALYST"),
                ("analyst", f"{tenant_id}_ops_team", "ANALYST"),
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
                    # 第 3 篇为 INTERNAL(2) 密级，但受利益冲突隔离墙保护（禁止 ops_team 部门及所属员工访问）
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
                if cluster_variant in (0, 1) and d_idx >= len(_REGULATION_TOPICS):
                    shared_anchor = [
                        _EXTRA_VOCAB[((d_idx % len(_REGULATION_TOPICS)) + k * 3 + t_idx) % len(_EXTRA_VOCAB)]
                        for k in range(8)
                    ]
                    body_text = (
                        f"{extra_words}. Tenant {t_slug} policy directive for {reg_code}. "
                        f"Core mandate: {core_phrase}. "
                        f"Operational scope: {' '.join(shared_anchor)} {' '.join(picked_vocab[:2])}."
                    )
                else:
                    body_text = (
                        f"{extra_words}. Tenant {t_slug} reference manual {d_idx + 1} under {reg_code}. "
                        f"Mandate: {core_phrase}. "
                        f"Specific controls: {' '.join(picked_vocab)}."
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

            # 利益冲突隔离墙规则：对 ops_team 组织节点封禁 wall_doc_id（researcher 同为密级2可看，analyst 在 ops_team 不可看！）
            if docs_per_tenant >= 3:
                conn.execute(
                    "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
                    "VALUES (?, ?, 'ORG_NODE', ?, 'DENY', 1, ?)",
                    (tenant_id, wall_doc_id, f"{tenant_id}_ops_team", base_ts),
                )

            channels = ["WIRE_INTL", "CRYPTO_BRIDGE", "CARD_CNP", "ACH_BATCH", "POS_CHIP"]
            num_accounts = max(6, tx_per_tenant // 12)
            tx_rows = []
            dec_rows = []
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
                "win_tx_count, win_amount_cents, win_unique_counterparties, reasons_json, evaluated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                dec_rows,
            )

            conn.execute(
                "INSERT OR REPLACE INTO tenant_quotas(tenant_id, quota_type, remaining_quota, updated_at) VALUES (?, 'EMERGENCY_EXPORT', 5, ?)",
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
                "sample_decision_id": f"dec_{t_slug}_hist_00001",
                "sample_tx_id": f"tx_{t_slug}_hist_00001",
                "override_token": override_tok,
                "users": user_tokens,
            }

        conn.commit()
    finally:
        conn.close()

    from .runtime import reset_db_runtime

    reset_db_runtime(db_path)
    return manifest
