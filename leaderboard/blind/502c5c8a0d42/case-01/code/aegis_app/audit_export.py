# -*- coding: utf-8 -*-
"""合规审计流水流式汇总摘要导出与租户季度归档快照安全读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.parse
from typing import Any

from .auth import AuthError, CallerContext
from .runtime import get_runtime


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """流式统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。

    滚动摘要规则：按 log_id 升序遍历匹配记录，依次向 SHA-256 更新
    f"{log_id}|{event_type}|{severity}|{amount_cents}|{masked_account}|{ts}\\n"。
    """
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

    rt = get_runtime(db_path)
    conn = rt.get_connection()

    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    total_amount_cents = 0
    total_records = 0
    capped_sample = max(0, min(int(sample_limit), 50))
    samples: list[dict[str, Any]] = []

    cur = conn.execute(sql, tuple(params))
    while True:
        batch = cur.fetchmany(1000)
        if not batch:
            break
        for r in batch:
            log_id = int(r["log_id"])
            evt = r["event_type"]
            sev = r["severity"]
            amt = int(r["amount_cents"])
            masked_acc = r["masked_account"]
            ts = int(r["ts"])

            total_records += 1
            total_amount_cents += amt
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            event_counts[evt] = event_counts.get(evt, 0) + 1

            line = f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts}\n"
            hasher.update(line.encode("utf-8"))

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
    """安全读取当前租户归档目录下的合规季度快照文件（严格封堵路径穿越与符号链接逃逸）。"""
    if not snapshot_name or not isinstance(snapshot_name, str):
        raise ValueError("snapshot_name is required")

    # 拒绝控制字符、空字节、反斜杠及多轮编码隐藏跳转
    decoded = urllib.parse.unquote(snapshot_name)
    for candidate in (snapshot_name, decoded, urllib.parse.unquote(decoded)):
        if "\x00" in candidate or "\\" in candidate or ":" in candidate:
            raise AuthError("Invalid snapshot path", 403)
        if candidate.startswith("/"):
            raise AuthError("Absolute snapshot path not allowed", 403)
        parts = [p for p in candidate.split("/") if p]
        if any(p in (".", "..") for p in parts):
            raise AuthError("Path traversal in snapshot_name is forbidden", 403)

    base_dir = pathlib.Path(storage_dir, caller.tenant_id, "snapshots").resolve()
    target_path = (base_dir / decoded).resolve()

    if target_path == base_dir or not target_path.is_relative_to(base_dir):
        raise AuthError("Snapshot path outside tenant sandbox", 403)

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
