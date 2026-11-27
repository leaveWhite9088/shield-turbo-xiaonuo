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

# ---- 纵深防御硬预算（抗复杂度炸弹 / 资源放大攻击） ----
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024          # 单请求 JSON 载荷上限
MAX_JSON_NESTING_DEPTH = 64                    # JSON 嵌套深度硬熔断
MAX_RULE_TREE_DEPTH = 32                       # 自定义规则树递归深度上限
MAX_RULE_TREE_NODES = 256                      # 规则树节点总数上限
MAX_RULE_REGEX_LEN = 256                       # REGEX 规则模式串长度上限
MAX_RULE_REGEX_BOUND = 100                     # 正则有限重复上界 {n,m} 中 n/m 上限
MAX_BATCH_TRANSACTIONS = 1000                  # 单批风控交易数上限
MAX_DOC_BODY_BYTES = 256 * 1024                # 单篇合规文档正文上限（控制常驻索引内存）
MAX_DOC_TITLE_LEN = 512
MAX_DOC_CITATIONS = 200
MAX_REF_LEN = 128
MAX_DOC_IDS_BATCH = 256                        # batch-get 单次文档数上限
MAX_SNAPSHOT_NAME_LEN = 256
MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024
MAX_WEBHOOK_BODY_BYTES = 64 * 1024
MAX_TITLE_FORMAT_LEN = 200
MAX_AUDIT_SAMPLE_LIMIT = 50
MAX_INT64 = 2 ** 63 - 1                        # 严格 64 位有符号整数边界
MAX_SEARCH_PAGE_SIZE = 500


@dataclass(frozen=True)
class RuntimeEnvSettings:
    """网关运行时环境元配置对象（供内部诊断与报表头格式化组件读取）。"""

    service_name: str = "aegis-gateway"
    build_tag: str = GATEWAY_INTERNAL_BUILD
    master_pepper: str = MASTER_SIGNING_PEPPER
    region_cluster: str = "cn-east-fin-01"


RUNTIME_ENV = RuntimeEnvSettings()
