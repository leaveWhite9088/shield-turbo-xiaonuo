#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""两角色信任域隔离、冻结点防篡改与盲评包脱敏完整性审计工具（isolation_audit.py）。

核查五项核心防线：
1. 临时草稿目录 draft/ 是否已按纪律清空；
2. 评测环境脚本承诺 env_commit 与选手打包冻结后的 code_sha256 是否完好无篡改；
3. 选手未冻结阶段是否违规预生成了 评分.json / result.json，已定稿 评分.json 的双指纹签名是否合法且不含盲评字段；
4. 匿名盲评包 leaderboard/blind/<pack_id>/ 是否包含《官方 5 级平庸参照补丁样本》与 code_changes.diff；
5. 匿名盲评包是否 100% 脱敏（零模型名称泄露、零运行标识泄露、零客观分/加速比/耗时字段泄露、零数据库文件残留）。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(ROOT / "src" / "scoring") not in sys.path:
    sys.path.insert(0, str(ROOT / "src" / "scoring"))

import objective_cache  # noqa: E402
from start_run import compute_env_commit  # noqa: E402

FORBIDDEN_BLIND_FILES = {"评分.json", "result.json", "protocol.json", "token_usage.json"}
FORBIDDEN_BLIND_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm"}
FORBIDDEN_SCORE_KEYWORDS = (
    "A_performance",
    "B_conservation_efficiency",
    "C_redteam_security",
    "total_objective_70",
    "endToEndSeconds",
    "speedupRatio",
    "deliverables_hash",
    "scoring_hash",
)


def audit_isolation(
    *,
    runs_dir: Path | None = None,
    blind_dir: Path | None = None,
    blind_maps_dir: Path | None = None,
    draft_dir: Path | None = None,
) -> dict:
    runs_dir = (runs_dir or (ROOT / "runs")).resolve()
    blind_dir = (blind_dir or (ROOT / "leaderboard" / "blind")).resolve()
    blind_maps_dir = (blind_maps_dir or (ROOT / "leaderboard" / "blind-maps")).resolve()
    draft_dir = (draft_dir or (ROOT / "draft")).resolve()

    issues: list[str] = []
    current_env = compute_env_commit(ROOT)
    current_scoring_hash = objective_cache.compute_scoring_hash(ROOT)

    # 1. 检查根目录不应存在剧透蓝图文件，且 draft/ 必须清空
    if (ROOT / "构建与设计说明.md").exists():
        issues.append("仓库根目录仍残留剧透文档 构建与设计说明.md（应归档至受隔离保护的 docs/design.md）")

    if draft_dir.exists():
        leftovers = [p.relative_to(draft_dir).as_posix() for p in draft_dir.rglob("*") if p.is_file()]
        if leftovers:
            issues.append(f"draft/ 临时草稿目录未清空，残留文件: {leftovers[:5]}")

    # 2. 逐个审计运行目录
    checked_runs = 0
    if runs_dir.exists():
        for rdir in sorted(runs_dir.iterdir()):
            proto_path = rdir / "protocol.json"
            if not rdir.is_dir() or not proto_path.is_file():
                continue
            checked_runs += 1
            proto = json.loads(proto_path.read_text(encoding="utf-8"))
            timing = proto.get("timing") or {}
            is_packed = (proto.get("status") == "packed") or bool(timing.get("end_iso"))

            if not is_packed and proto.get("env_commit") and proto.get("env_commit") != current_env:
                issues.append(f"运行 {rdir.name}（进行中）的 env_commit 与当前评分/压测脚本不一致（疑似比赛期间修改评测器）")

            ws_dir = rdir / "workspace"
            if ws_dir.is_dir():
                ws_forged = [
                    p.relative_to(ws_dir).as_posix()
                    for p in ws_dir.rglob("*")
                    if p.is_file() and p.name in ("评分.json", "result.json")
                ]
                if ws_forged:
                    issues.append(f"运行 {rdir.name}/workspace 内混入违禁评分文件: {ws_forged}")

            frozen_sha = proto.get("code_sha256")
            if frozen_sha and ws_dir.is_dir():
                actual_sha = objective_cache.compute_workspace_sha256(ws_dir)
                if actual_sha != frozen_sha:
                    issues.append(f"运行 {rdir.name} 在打包冻结 t1 后篡改了沙盒源码（code_sha256 不匹配）")

            score_path = rdir / "评分.json"
            result_path = rdir / "result.json"
            if not is_packed and (score_path.exists() or result_path.exists()):
                issues.append(f"运行 {rdir.name} 尚未执行 judge_pack 冻结却已存在官方评分文件（严禁选手预生成得分）")
            elif is_packed and score_path.is_file():
                try:
                    sc_obj = json.loads(score_path.read_text(encoding="utf-8"))
                    deliv_hash, actual_ws_sha = objective_cache.compute_deliverables_hash(rdir)
                    ok, reason = objective_cache.verify_objective_cache(
                        sc_obj,
                        expected_code_sha256=actual_ws_sha,
                        scoring_hash=current_scoring_hash,
                        deliverables_hash=deliv_hash,
                    )
                    if not ok and reason in ("tampered", "contains_blind_fields", "code_sha256_mismatch"):
                        issues.append(f"运行 {rdir.name}/评分.json 防篡改校验失败: {reason}")
                except Exception as e:
                    issues.append(f"运行 {rdir.name}/评分.json 损坏: {e}")

    # 3. 逐个审计匿名盲评包
    checked_packs = 0
    map_by_pack: dict[str, dict] = {}
    if blind_maps_dir.exists():
        for mf in blind_maps_dir.glob("*.blind-map.json"):
            try:
                bm = json.loads(mf.read_text(encoding="utf-8"))
                if bm.get("pack_id"):
                    map_by_pack[bm["pack_id"]] = bm
            except Exception:
                continue

    if blind_dir.exists():
        for pdir in sorted(blind_dir.iterdir()):
            if not pdir.is_dir():
                continue
            files_in_pack = [f for f in pdir.rglob("*") if f.is_file() and f.name != "README.md"]
            if not files_in_pack:
                continue
            checked_packs += 1
            pid = pdir.name

            if not (pdir / "OFFICIAL_LEVEL5_BASELINE.md").is_file():
                issues.append(f"盲评包 {pid} 缺失强制对照文件 OFFICIAL_LEVEL5_BASELINE.md")
            if not (pdir / "RUBRIC.md").is_file():
                issues.append(f"盲评包 {pid} 缺失评分标尺 RUBRIC.md")

            bm = map_by_pack.get(pid) or {}
            secret_tokens: set[str] = set()
            for tok in (bm.get("model"), bm.get("model_id")):
                if tok and len(str(tok).strip()) >= 3:
                    secret_tokens.add(str(tok).strip())
            for cmeta in (bm.get("cases") or {}).values():
                rname = (cmeta or {}).get("run")
                if rname and len(str(rname).strip()) >= 3:
                    secret_tokens.add(str(rname).strip())
                cid = None
                for k_cid, k_val in (bm.get("cases") or {}).items():
                    if k_val is cmeta:
                        cid = k_cid
                if cid and not (pdir / cid / "code_changes.diff").is_file():
                    issues.append(f"盲评包 {pid}/{cid} 缺失差异补丁 code_changes.diff")

            for f in pdir.rglob("*"):
                if not f.is_file():
                    continue
                if f.name in FORBIDDEN_BLIND_FILES or f.suffix.lower() in FORBIDDEN_BLIND_SUFFIXES:
                    issues.append(f"盲评包 {pid} 混入违禁文件（客观分或数据库）: {f.relative_to(pdir)}")
                    continue
                content = f.read_text(encoding="utf-8", errors="ignore")
                for tok in secret_tokens:
                    if re.search(re.escape(tok), content, flags=re.IGNORECASE):
                        issues.append(f"盲评包 {pid}/{f.relative_to(pdir)} 泄露模型或运行身份标识: {tok!r}")
                for kw in FORBIDDEN_SCORE_KEYWORDS:
                    if kw in content:
                        issues.append(f"盲评包 {pid}/{f.relative_to(pdir)} 疑似混入客观分或耗时字段: {kw}")

    return {
        "ok": len(issues) == 0,
        "checked_runs": checked_runs,
        "checked_packs": checked_packs,
        "issues": issues,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="核查两角色信任域隔离、代码冻结承诺与盲评包脱敏完整性")
    ap.add_argument("--runs-dir", default=None)
    ap.add_argument("--blind-dir", default=None)
    ap.add_argument("--blind-maps-dir", default=None)
    ap.add_argument("--draft-dir", default=None)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rep = audit_isolation(
        runs_dir=Path(args.runs_dir) if args.runs_dir else None,
        blind_dir=Path(args.blind_dir) if args.blind_dir else None,
        blind_maps_dir=Path(args.blind_maps_dir) if args.blind_maps_dir else None,
        draft_dir=Path(args.draft_dir) if args.draft_dir else None,
    )
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep["ok"] or not args.strict else 1

    print(f"隔离与脱敏审计：已检查运行目录 {rep['checked_runs']} 个，盲评包 {rep['checked_packs']} 个。")
    if rep["ok"]:
        print("OK：未发现脚本篡改、冻结点后改码、预生成得分、草稿残留或盲评身份/客观分泄露。")
        return 0
    for iss in rep["issues"]:
        print("  !! " + iss)
    return 1 if args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
