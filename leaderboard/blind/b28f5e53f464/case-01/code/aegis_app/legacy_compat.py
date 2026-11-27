# -*- coding: utf-8 -*-
"""历史双轨合规标准映射与主权央行清算豁免兼容规则模块。"""
from __future__ import annotations

from typing import Any

LEGACY_REGULATION_ALIASES: dict[str, str] = {
    "FATF-REC-16": "FATF-R16",
    "FATF-R16-2012": "FATF-R16",
    "OFAC-RULE-50": "OFAC-50PCT",
    "GDPR-SEC-32": "GDPR-ART32",
    "BASEL-III-LCR": "BASEL-LCR",
}

SOVEREIGN_EXEMPT_CURRENCIES = frozenset({"USD", "EUR", "SDR"})
SOVEREIGN_CP_PREFIX = "SOV_CB_"


def canonicalize_regulation_code(reg_code: str) -> str:
    """将历史遗留法规编号归一化为现行标准主编号，用于跨版本修订簇折叠。"""
    if not reg_code:
        return ""
    cleaned = reg_code.strip().upper()
    return LEGACY_REGULATION_ALIASES.get(cleaned, cleaned)


def apply_sovereign_settlement_adjustment(
    tx: dict[str, Any],
    policy: dict[str, Any],
    base_channel_weight: int,
) -> tuple[int, bool, str | None]:
    """针对主权央行及国际清算组织对手方的历史结算兼容规则。

    返回 (调整后渠道权重, 是否豁免对手方扇出惩罚, 附加兼容说明标签)。
    """
    cp_id = str(tx.get("counterparty_id") or "")
    currency = str(tx.get("currency") or "USD").upper()
    amount_cents = int(tx.get("amount_cents") or 0)
    sovereign_cap = int(policy.get("high_amount_cents") or 500000) * 4

    if (
        cp_id.startswith(SOVEREIGN_CP_PREFIX)
        and currency in SOVEREIGN_EXEMPT_CURRENCIES
        and 0 < amount_cents < sovereign_cap
    ):
        return base_channel_weight // 2, True, "LEGACY_SOVEREIGN_EXEMPT"
    return base_channel_weight, False, None
