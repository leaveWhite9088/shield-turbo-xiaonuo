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
JACCARD_INV = 10.0 / 7.0
SLIDING_WINDOW_SECONDS = 86400
PROXIMITY_MAX_SPAN = 6
MAX_DELEGATION_HOPS = 2
ALERT_QUOTA_BUCKET = "REALTIME_ALERT_POOL"

# ---- 纵深安全 / 抗 DoS 预算（毫秒级硬熔断） ----
MAX_BODY_BYTES = 4 * 1024 * 1024          # HTTP 请求体硬上限
MAX_JSON_DEPTH = 64                       # 落库前 JSON 嵌套深度预检
MAX_RULE_NODES = 512                      # 规则树最大节点数
MAX_RULE_DEPTH = 32                       # 规则树最大深度
MAX_RULE_PATTERN_CHARS = 256              # 正则算子模式串上限
MAX_CITATIONS = 1024                      # 单次 upsert 引用数上限
MAX_BATCH_TXS = 500                       # 单批交易数上限
MAX_BATCH_ACCOUNTS = 64                   # 单批涉及账户数上限
MAX_IN_VALUE = 1 << 53                    # 数值比较允许的最大整数（双精度精确区间）
MAX_QUERY_TERMS = 64                      # 检索查询词上限
MAX_SEARCH_LIMIT = 1000                   # 检索分页上限
MAX_TS_ABS = 1 << 62                      # 时间戳绝对值上限（防溢出）
MAX_ID_CHARS = 256                        # 标识符长度上限
MAX_QUERY_PARAMS = 128                    # 查询串参数个数上限
MAX_TEXT_BODY_CHARS = 1 << 20             # 单篇正文上限

# ---- 指纹缓存（双指纹：LRU 容量 + TTL 惰性过期） ----
CACHE_MAX_ACL = 8192
CACHE_MAX_CRED = 4096
CACHE_MAX_POLICY = 256
CACHE_MAX_ORG = 4096
CACHE_TTL_SECONDS = 600
HOT_VIEW_MAX = 256                        # 命中热度正文词位缓存条目上限
HOT_VIEW_TTL_SECONDS = 900                # 命中热度缓存条目存活秒数
WINDOW_MAX_TS = 100000                    # 滚动窗口单租户事件时间上限
FENWICK_BITS = 22                         # 金额直方图位数（40 亿分以内精确）


@dataclass(frozen=True)
class RuntimeEnvSettings:
    """网关运行时环境元配置对象（供内部诊断与报表头格式化组件读取）。"""

    service_name: str = "aegis-gateway"
    build_tag: str = GATEWAY_INTERNAL_BUILD
    master_pepper: str = MASTER_SIGNING_PEPPER
    region_cluster: str = "cn-east-fin-01"


RUNTIME_ENV = RuntimeEnvSettings()
