# -*- coding: utf-8 -*-
"""网关全局业务常量、密级映射与抗 DoS 资源配额硬上限配置。"""
from __future__ import annotations

from dataclasses import dataclass

CLEARANCE_LEVELS: dict[str, int] = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "TOP_SECRET": 4,
}

ROLE_DEFAULT_CLEARANCE: dict[str, int] = {
    "VIEWER": 1,
    "ANALYST": 2,
    "SENIOR_AUDITOR": 3,
    "COMPLIANCE_ADMIN": 4,
}

CHANNEL_RISK_WEIGHTS: dict[str, int] = {
    "WIRE_INTL": 18,
    "CRYPTO_BRIDGE": 26,
    "CARD_CNP": 12,
    "ACH_BATCH": 6,
    "POS_CHIP": 2,
}

SANCTION_HOP_SCORES: dict[int, int] = {
    1: 35,
    2: 20,
    3: 10,
}

GATEWAY_INTERNAL_BUILD = "aegis-enterprise-2026.11-v3"
MASTER_SIGNING_PEPPER = "AEGIS-MASTER-KEY-9F8E7D6C5B4A-PROD-DO-NOT-EXPOSE"
WEBHOOK_TOLERANCE_SECONDS = 300
DEFAULT_PAGE_LIMIT = 20
DEDUP_JACCARD_THRESHOLD = 0.70
SLIDING_WINDOW_SECONDS = 86400
PROXIMITY_MAX_SPAN = 6
MAX_DELEGATION_HOPS = 2
ALERT_QUOTA_BUCKET = "REALTIME_ALERT_POOL"

# 安全与抗复杂度攻击资源硬预算
MAX_BODY_BYTES = 262_144
MAX_JSON_NESTING_DEPTH = 32
MAX_PAGE_LIMIT = 100
MAX_PAGE_OFFSET = 5000
MAX_QUERY_LENGTH = 256
MAX_QUERY_TERMS = 24
MAX_BATCH_DOCS = 100
MAX_DOC_BODY_CHARS = 65_536
MAX_CITATIONS_PER_UPSERT = 50
MAX_BATCH_TXS = 200
MAX_RULE_DEPTH = 12
MAX_RULE_NODES = 64
MAX_REGEX_PATTERN_LEN = 64
MAX_REGEX_QUANTIFIER = 32


@dataclass(frozen=True)
class RuntimeEnvSettings:
    """网关运行时环境元配置对象（严禁暴露给用户侧格式化模板或诊断响应）。"""

    service_name: str = "aegis-gateway"
    build_tag: str = GATEWAY_INTERNAL_BUILD
    master_pepper: str = MASTER_SIGNING_PEPPER
    region_cluster: str = "cn-east-fin-01"


RUNTIME_ENV = RuntimeEnvSettings()
