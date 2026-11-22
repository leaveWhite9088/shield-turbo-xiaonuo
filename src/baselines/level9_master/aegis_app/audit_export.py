# -*- coding: utf-8 -*-
"""高性能安全审计导出服务：游标分块流式迭代（极低恒定内存峰值）与规范化路径边界锚定防穿越。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.parse
from typing import Any

from .auth import CallerContext
from .db import get_thread_connection

SAFE_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\.json$")
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """仅投影计算所需轻量列，使用游标 fetchmany 流式迭代计算统计与滚动哈希，避免加载大体积 payload_json。"""
    if severity and severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"Invalid severity filter: {severity}")
    if not isinstance(sample_limit, int) or sample_limit < 0 or sample_limit > 50:
        if isinstance(sample_limit, int) and sample_limit > 50:
            sample_limit = 50
        elif isinstance(sample_limit, int) and sample_limit < 0:
            raise ValueError("sample_limit must be non-negative")

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
        "SELECT log_id, event_type, severity, amount_cents, masked_account, ts "
        f"FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY log_id ASC"
    )

    conn = get_thread_connection(db_path)
    cur = conn.execute(sql, tuple(params))

    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_records = 0
    total_amount_cents = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    try:
        while True:
            batch = cur.fetchmany(256)
            if not batch:
                break
            for r in batch:
                log_id = int(r[0])
                evt = r[1]
                sev = r[2]
                amt = int(r[3])
                masked_acc = r[4]
                ts = int(r[5])

                total_records += 1
                total_amount_cents += amt
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                event_counts[evt] = event_counts.get(evt, 0) + 1
                hasher.update(f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts}\n".encode("utf-8"))

                if len(samples) < capped_sample:
                    samples.append(
                        {
                            "log_id": log_id,
                            "event_type": evt,
                            "severity": sev,
                            "amount_cents": amt,
                            "masked_account": masked_acc,
                            "ts": ts,
                        }
                    )
    finally:
        cur.close()

    return {
        "tenant_id": caller.tenant_id,
        "total_records": total_records,
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
    """双重防线防路径穿越：严格文件名白名单 + resolve().is_relative_to() 物理边界锚定。"""
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")

    # 拒绝任何编码残留、路径分隔符、控制字符或相对跳转符号
    unquoted_once = urllib.parse.unquote(snapshot_name)
    unquoted_twice = urllib.parse.unquote(unquoted_once)
    if (
        unquoted_once != snapshot_name
        or unquoted_twice != snapshot_name
        or "/" in snapshot_name
        or "\\" in snapshot_name
        or ".." in snapshot_name
        or "\x00" in snapshot_name
        or not SAFE_SNAPSHOT_NAME_RE.match(snapshot_name)
    ):
        raise ValueError("Illegal snapshot_name format")

    base_dir = (pathlib.Path(storage_dir).resolve() / caller.tenant_id / "snapshots").resolve()
    target_path = (base_dir / snapshot_name).resolve()

    if not target_path.is_relative_to(base_dir) or target_path.parent != base_dir:
        raise ValueError("Path traversal attempt blocked")

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
