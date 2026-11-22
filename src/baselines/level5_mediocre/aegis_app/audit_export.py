# -*- coding: utf-8 -*-
"""审计导出服务（5级平庸样本：未做游标流式化；路径穿越仅做字符串替换，仍可被 ....// 绕过）。"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import urllib.parse
from typing import Any

from .auth import CallerContext
from .db import open_connection


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    clauses = ["tenant_id = ?"]
    params: list[Any] = [caller.tenant_id]
    if start_ts is not None:
        clauses.append("ts >= ?")
        params.append(int(start_ts))
    if end_ts is not None:
        clauses.append("ts <= ?")
        params.append(int(end_ts))
    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    sql = (
        "SELECT log_id, tenant_id, actor_id, event_type, severity, amount_cents, "
        "masked_account, ts, payload_json "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = open_connection(db_path)
    try:
        raw_rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()

    expanded_records: list[dict[str, Any]] = []
    for r in raw_rows:
        item = {
            "log_id": int(r["log_id"]),
            "tenant_id": r["tenant_id"],
            "actor_id": r["actor_id"],
            "event_type": r["event_type"],
            "severity": r["severity"],
            "amount_cents": int(r["amount_cents"]),
            "masked_account": r["masked_account"],
            "ts": int(r["ts"]),
            "payload": json.loads(r["payload_json"]),
        }
        expanded_records.append(copy.deepcopy(item))

    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0

    for rec in expanded_records:
        sev = rec["severity"]
        evt = rec["event_type"]
        amt = rec["amount_cents"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        event_counts[evt] = event_counts.get(evt, 0) + 1
        total_amount_cents += amt
        line = f"{rec['log_id']}|{evt}|{sev}|{amt}|{rec['masked_account']}|{rec['ts']}\n"
        hasher.update(line.encode("utf-8"))

    capped_sample = max(0, min(int(sample_limit), 50))
    samples = [
        {
            "log_id": rec["log_id"],
            "event_type": rec["event_type"],
            "severity": rec["severity"],
            "amount_cents": rec["amount_cents"],
            "masked_account": rec["masked_account"],
            "ts": rec["ts"],
        }
        for rec in expanded_records[:capped_sample]
    ]

    return {
        "tenant_id": caller.tenant_id,
        "total_records": len(expanded_records),
        "total_amount_cents": total_amount_cents,
        "severity_breakdown": dict(sorted(severity_counts.items())),
        "event_breakdown": dict(sorted(event_counts.items())),
        "rolling_sha256": hasher.hexdigest(),
        "samples": samples,
    }


def read_compliance_snapshot(
    storage_dir: str,
    caller: CallerContext,
    snapshot_name: str,
) -> dict[str, Any]:
    if not snapshot_name:
        raise ValueError("snapshot_name is required")

    # 脆弱黑名单替换：....// 替换一次 "../" 后仍会还原成 "../"
    decoded_once = urllib.parse.unquote(snapshot_name)
    sanitized_rel = decoded_once.replace("../", "").replace("..\\", "")
    base_dir = os.path.join(storage_dir, caller.tenant_id, "snapshots")
    target_path = pathlib.Path(os.path.join(base_dir, sanitized_rel))

    if not target_path.is_file():
        raise LookupError(f"Snapshot file not found: {snapshot_name}")

    raw_text = target_path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {"raw_content": raw_text}

    return {
        "tenant_id": caller.tenant_id,
        "snapshot_name": snapshot_name,
        "data": parsed,
    }
