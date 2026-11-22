# -*- coding: utf-8 -*-
"""合规审计流水汇总摘要导出与租户季度归档快照读取服务。"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.parse
from typing import Any

from .auth import CallerContext
from .db import get_thread_connection

_SAFE_SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_STREAM_BATCH_SIZE = 1000


def export_audit_digest(
    db_path: str,
    caller: CallerContext,
    *,
    start_ts: int | None = None,
    end_ts: int | None = None,
    severity: str = "",
    sample_limit: int = 10,
) -> dict[str, Any]:
    """流式统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希（O(1) 内存）。

    滚动摘要规则：按 log_id 升序遍历匹配记录，依次向 SHA-256 更新
    f"{log_id}|{event_type}|{severity}|{amount_cents}|{masked_account}|{ts}\\n"。
    """
    if isinstance(sample_limit, bool) or not isinstance(sample_limit, int) or sample_limit < 0 or sample_limit > 1000:
        raise ValueError("sample_limit must be an integer between 0 and 1000")

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

    capped_sample = min(sample_limit, 50)
    hasher = hashlib.sha256()
    severity_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    samples: list[dict[str, Any]] = []
    total_records = 0
    total_amount_cents = 0

    conn = get_thread_connection(db_path)
    cursor = conn.execute(sql, tuple(params))
    try:
        while True:
            batch = cursor.fetchmany(_STREAM_BATCH_SIZE)
            if not batch:
                break
            for r in batch:
                log_id = int(r[0])
                evt = str(r[1])
                sev = str(r[2])
                amt = int(r[3])
                masked_acc = str(r[4])
                ts_val = int(r[5])

                total_records += 1
                total_amount_cents += amt
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                event_counts[evt] = event_counts.get(evt, 0) + 1
                hasher.update(f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts_val}\n".encode("utf-8"))

                if len(samples) < capped_sample:
                    samples.append(
                        {
                            "log_id": log_id,
                            "event_type": evt,
                            "severity": sev,
                            "amount_cents": amt,
                            "masked_account": masked_acc,
                            "ts": ts_val,
                        }
                    )
    finally:
        cursor.close()

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
    """安全读取当前租户归档目录下的合规季度快照文件（彻底封堵多变体路径穿越与符号链接逃逸）。"""
    if not isinstance(snapshot_name, str) or not snapshot_name:
        raise ValueError("snapshot_name is required")

    # 递归解码检测多层编码穿越（如 %252e%252e%252f、..\、空字节等）
    decoded = snapshot_name
    for _ in range(3):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt

    if (
        "\x00" in snapshot_name
        or "\x00" in decoded
        or "/" in decoded
        or "\\" in decoded
        or ".." in decoded
        or ":" in decoded
        or not _SAFE_SNAPSHOT_NAME_RE.match(snapshot_name)
    ):
        raise ValueError("Invalid snapshot_name: path traversal or illegal characters rejected")

    base_dir = (pathlib.Path(storage_dir) / caller.tenant_id / "snapshots").resolve()
    raw_target = base_dir / snapshot_name
    if raw_target.is_symlink():
        raise ValueError("Symbolic link snapshot access is forbidden")

    target_path = raw_target.resolve()
    if not target_path.is_relative_to(base_dir) or target_path == base_dir:
        raise ValueError("Snapshot path escapes tenant archive boundary")

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
