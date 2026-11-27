# -*- coding: utf-8 -*-
"""网关全局业务常量、密级映射与默认风控参数配置。"""
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

MAX_JSON_PAYLOAD_BYTES = 524288
MAX_JSON_NESTING_DEPTH = 24
MAX_BATCH_TX_COUNT = 256
MAX_DOC_BODY_CHARS = 65536
MAX_CITATIONS_PER_DOC = 64
MAX_BATCH_GET_DOC_IDS = 100
MAX_RULE_TREE_NODES = 64
MAX_RULE_TREE_DEPTH = 12
MAX_QUERY_TERMS = 16
MAX_QUERY_CHARS = 512
MAX_SAFE_INT64 = (1 << 62) - 1
MIN_SAFE_INT64 = -((1 << 62) - 1)


def parse_strict_int(
    val: object,
    name: str = "integer",
    *,
    min_val: int | None = MIN_SAFE_INT64,
    max_val: int | None = MAX_SAFE_INT64,
) -> int:
    if isinstance(val, bool) or val is None:
        raise ValueError(f"Invalid {name}: boolean or null not allowed")
    if isinstance(val, float):
        raise ValueError(f"Invalid {name}: float not allowed")
    if isinstance(val, int):
        res = val
    elif isinstance(val, str):
        s = val.strip()
        if not s or len(s) > 22:
            raise ValueError(f"Invalid {name} string")
        try:
            res = int(s, 10)
        except ValueError as exc:
            raise ValueError(f"Invalid {name} string") from exc
    else:
        raise ValueError(f"Invalid {name} type")
    if min_val is not None and res < min_val:
        raise ValueError(f"{name} below minimum {min_val}")
    if max_val is not None and res > max_val:
        raise ValueError(f"{name} exceeds maximum {max_val}")
    return res


@dataclass(frozen=True)
class RuntimeEnvSettings:
    """网关运行时环境元配置对象（供内部诊断与报表头格式化组件读取）。"""

    service_name: str = "aegis-gateway"
    build_tag: str = GATEWAY_INTERNAL_BUILD
    master_pepper: str = MASTER_SIGNING_PEPPER
    region_cluster: str = "cn-east-fin-01"


RUNTIME_ENV = RuntimeEnvSettings()
