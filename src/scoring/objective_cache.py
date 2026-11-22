# -*- coding: utf-8 -*-
"""客观分（A/B/C）双指纹防篡改缓存与核验（对齐 silicon-rider-xiaonuo）。

核心职责：
1. 计算两项独立 SHA-256 指纹：
   - scoring_hash：评分配置（configs/benchmark.json）、初始模板与客观压测/红队脚本的整体哈希；
   - deliverables_hash：单局冻结交付物（protocol.json 关键承诺 + 冻结沙盒源码 code_sha256）的整体哈希。
2. 生成与核验定稿客观分记录（绑定两项指纹的 attestation 防伪签名），
   确保客观分与盲评分物理分离存储，绝不混入任何 D 层盲评字段。
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

CACHE_SCHEMA_VERSION = 1
SECRET_ATTESTATION_TAG = "shield-turbo-xiaonuo-v1-objective-seal"

SCORING_TRACKED_FILES = (
    "configs/benchmark.json",
    "src/scoring/metrics.py",
    "src/scoring/workload.py",
    "src/scoring/redteam.py",
    "src/scoring/score_run.py",
    "src/scoring/objective_cache.py",
    "src/sandbox_template/aegis_app/config.py",
    "src/sandbox_template/aegis_app/db.py",
    "src/sandbox_template/aegis_app/auth.py",
    "src/sandbox_template/aegis_app/rule_engine.py",
    "src/sandbox_template/aegis_app/search_service.py",
    "src/sandbox_template/aegis_app/audit_export.py",
    "src/sandbox_template/aegis_app/server.py",
)

OBJECTIVE_SIGNED_FIELDS = (
    "A_performance",
    "A_detail",
    "B_conservation_efficiency",
    "B_detail",
    "C_redteam_security",
    "C_detail",
    "total_objective_70",
    "run_summary",
    "code_sha256",
    "t0_source",
    "b2_reliable",
)

FORBIDDEN_BLIND_FIELDS = ("D_judged", "D", "D1", "D2", "D3", "judges", "reviews")


def compute_workspace_sha256(workspace_dir: Path) -> str:
    """对沙盒内源码与文档计算确定性哈希（忽略数据库、缓存与临时日志）。"""
    skip_dirs = {"__pycache__", ".pytest_cache", ".git", ".mypy_cache", ".venv", "venv"}
    skip_suffixes = {
        ".db",
        ".db-wal",
        ".db-shm",
        ".db-journal",
        ".sqlite",
        ".sqlite3",
        ".pyc",
        ".pyo",
        ".log",
        ".tmp",
    }
    h = hashlib.sha256()
    files: list[Path] = []
    ws = Path(workspace_dir).resolve()
    for p in ws.rglob("*"):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(ws).parts
        if any(part in skip_dirs for part in rel_parts):
            continue
        if p.suffix.lower() in skip_suffixes:
            continue
        files.append(p)
    for p in sorted(files, key=lambda x: x.relative_to(ws).as_posix()):
        rel = p.relative_to(ws).as_posix()
        norm = p.read_bytes().replace(b"\r\n", b"\n")
        h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(norm).digest() + b"\n")
    return h.hexdigest()


def compute_scoring_hash(root: Path = ROOT) -> str:
    """计算当前评分配置、压测/红队脚本与初始沙盒模板的整体 SHA-256 指纹。"""
    base = Path(root).resolve()
    h = hashlib.sha256()
    for rel in sorted(set(SCORING_TRACKED_FILES)):
        fp = base / Path(rel)
        if not fp.is_file():
            raise FileNotFoundError(f"缺少参与评分指纹计算的文件: {fp}")
        norm = fp.read_bytes().replace(b"\r\n", b"\n")
        h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(norm).digest() + b"\0")
    return h.hexdigest()


def check_missing_deliverables(run_dir: Path) -> list[str]:
    rpath = Path(run_dir)
    missing: list[str] = []
    if not (rpath / "protocol.json").is_file():
        missing.append("protocol.json")
    if not (rpath / "workspace" / "aegis_app" / "server.py").is_file():
        missing.append("workspace/aegis_app/server.py")
    return missing


def compute_deliverables_hash(run_dir: Path) -> tuple[str, str]:
    """返回 (deliverables_hash, actual_workspace_sha256)。"""
    rpath = Path(run_dir).resolve()
    missing = check_missing_deliverables(rpath)
    if missing:
        raise FileNotFoundError(f"运行目录 {rpath.name} 缺少交付物: {', '.join(missing)}")
    proto = json.loads((rpath / "protocol.json").read_text(encoding="utf-8"))
    ws_sha = compute_workspace_sha256(rpath / "workspace")
    timing = proto.get("timing") or {}
    material = json.dumps(
        {
            "run_name": proto.get("run_name"),
            "model_id": proto.get("model_id"),
            "t0_iso": timing.get("t0_iso"),
            "end_iso": timing.get("end_iso"),
            "endToEndSeconds": timing.get("endToEndSeconds"),
            "workspace_sha256": ws_sha,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest(), ws_sha


def canonical_objective_payload(score_obj: dict) -> str:
    payload = {k: score_obj.get(k) for k in OBJECTIVE_SIGNED_FIELDS}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compute_attestation(scoring_hash: str, deliverables_hash: str, score_obj: dict) -> str:
    canon = canonical_objective_payload(score_obj)
    material = f"{SECRET_ATTESTATION_TAG}:v{CACHE_SCHEMA_VERSION}:{scoring_hash}:{deliverables_hash}:{canon}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_objective_record(
    raw_score: dict,
    *,
    run_summary: dict,
    code_sha256: str,
    t0_source: str | None,
    b2_reliable: bool,
    scoring_hash: str,
    deliverables_hash: str,
) -> dict:
    out = {k: v for k, v in raw_score.items() if k not in FORBIDDEN_BLIND_FIELDS}
    out["run_summary"] = dict(run_summary)
    out["code_sha256"] = code_sha256
    out["t0_source"] = t0_source
    out["b2_reliable"] = bool(b2_reliable)
    out["cache_schema_version"] = CACHE_SCHEMA_VERSION
    out["scoring_hash"] = scoring_hash
    out["deliverables_hash"] = deliverables_hash
    out["finalized"] = True
    out["finalized_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    out["attestation"] = compute_attestation(scoring_hash, deliverables_hash, out)
    return out


def verify_objective_cache(
    score_obj: dict | None,
    *,
    expected_code_sha256: str | None,
    scoring_hash: str,
    deliverables_hash: str,
) -> tuple[bool, str]:
    if not isinstance(score_obj, dict):
        return False, "invalid_json"
    if any(k in score_obj and score_obj[k] is not None for k in FORBIDDEN_BLIND_FIELDS):
        return False, "contains_blind_fields"
    if score_obj.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
        return False, "schema_upgrade"
    for req in (
        "A_performance",
        "B_conservation_efficiency",
        "C_redteam_security",
        "total_objective_70",
        "run_summary",
    ):
        if req not in score_obj:
            return False, f"missing_{req}"

    if score_obj.get("scoring_hash") != scoring_hash:
        return False, "scoring_changed"
    if score_obj.get("deliverables_hash") != deliverables_hash:
        return False, "deliverables_changed"
    if expected_code_sha256 and score_obj.get("code_sha256") != expected_code_sha256:
        return False, "code_sha256_mismatch"
    if score_obj.get("finalized") is not True:
        return False, "not_finalized"

    saved_att = score_obj.get("attestation")
    expected_att = compute_attestation(scoring_hash, deliverables_hash, score_obj)
    if not saved_att or saved_att != expected_att:
        return False, "tampered"
    return True, "hit"
