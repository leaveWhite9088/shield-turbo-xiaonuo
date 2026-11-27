# -*- coding: utf-8 -*-
"""网关全局业务常量、密级映射、安全边界与默认风控参数配置。"""
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

# 严格数值边界与抗 DoS 硬熔断预算
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
MAX_SAFE_TS = 1 << 60
MAX_TX_AMOUNT_CENTS = 10**15
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_CONTAINER_NODES = 50_000
MAX_RULE_DEPTH = 16
MAX_RULE_NODES = 256
MAX_RULE_IN_LIST = 256
MAX_REGEX_LEN = 256
MAX_REGEX_REPEAT_BOUND = 64
MAX_CITATIONS_PER_DOC = 256
MAX_DOC_BODY_CHARS = 262_144
MAX_BATCH_TX_COUNT = 500
MAX_BATCH_GET_IDS = 200
MAX_QUERY_CHARS = 2048
MAX_QUERY_TERMS = 64


@dataclass(frozen=True)
class RuntimeEnvSettings:
    """网关运行时环境元配置对象。"""

    service_name: str = "aegis-gateway"
    build_tag: str = GATEWAY_INTERNAL_BUILD
    master_pepper: str = MASTER_SIGNING_PEPPER
    region_cluster: str = "cn-east-fin-01"


RUNTIME_ENV = RuntimeEnvSettings()
