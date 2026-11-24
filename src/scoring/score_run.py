#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单局官方客观分评测与定稿工具（score_run.py）。

职责：
1. 严守隔离铁律：仅允许对已完成 judge_pack 冻结（或显式传入 --allow-unpacked 仅供内部基线自检）的运行执行评测；
2. 依次运行：① B1 60+ 项高密度业务零失真对账；② A1/A2/A3 同机大数据与高并发混合压测；③ C1/C2/C3 三波红队实弹轰炸；
3. 计算带双指纹防篡改签名（scoring_hash + deliverables_hash + attestation）的 评分.json 与 result.json。
"""
from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import metrics  # noqa: E402
import objective_cache  # noqa: E402
import redteam  # noqa: E402
import workload  # noqa: E402


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def evaluate_workspace_in_subprocess(
    candidate_workspace: Path,
    *,
    root: Path = ROOT,
    timeout_sec: float = 180.0,
) -> dict[str, Any]:
    """在独立隔离的 Python 子进程中执行 B1 对账、A 高压压测与 C 红队轰炸，防止被测模块全局状态污染主进程。"""
    worker_cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--_worker-eval",
        str(candidate_workspace.resolve()),
    ]
    proc = subprocess.run(
        worker_cmd,
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"评测子进程执行失败 (exit={proc.returncode}):\nSTDOUT:\n{proc.stdout[-800:]}\nSTDERR:\n{proc.stderr[-800:]}"
        )
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(f"评测子进程未输出合法 JSON 结果:\n{proc.stdout}")
    return json.loads(lines[-1])


def _run_worker_eval(candidate_ws: Path) -> int:
    cfg = metrics.load_benchmark_config(ROOT)
    template_dir = ROOT / "src" / "sandbox_template"
    b1_rep = workload.run_b1_conservation_check(template_dir, candidate_ws, cfg)
    perf_rep = workload.run_performance_benchmark(template_dir, candidate_ws, cfg)
    rt_rep = redteam.run_redteam_suite(template_dir, candidate_ws, cfg)
    out = {
        "b1_report": b1_rep,
        "perf_report": perf_rep,
        "redteam_report": rt_rep,
    }
    print(json.dumps(out, ensure_ascii=False))
    return 0


def score_and_finalize_run(
    run_dir: Path,
    *,
    recompute: bool = False,
    allow_unpacked: bool = False,
    b2_reliable: bool = True,
    scoring_hash: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """对单个 run 目录核验缓存或执行官方客观评测并落盘 评分.json / result.json。

    返回 (score_record, raw_eval_bundle, used_cache)。
    """
    rdir = Path(run_dir).resolve()
    missing = objective_cache.check_missing_deliverables(rdir)
    if missing:
        raise RuntimeError(f"{rdir.name}: 缺少交付物 {', '.join(missing)}")

    proto = json.loads((rdir / "protocol.json").read_text(encoding="utf-8"))
    timing = proto.get("timing") or {}
    is_packed = (proto.get("status") == "packed") or bool(timing.get("end_iso"))
    if not is_packed and not allow_unpacked:
        raise RuntimeError(
            f"{rdir.name}: 尚未执行 judge_pack.py 冻结计时与代码快照！选手阶段严禁提前运行客观评分。"
        )

    scoring_hash = scoring_hash or objective_cache.compute_scoring_hash(ROOT)
    deliv_hash, actual_ws_sha = objective_cache.compute_deliverables_hash(rdir)

    recorded_sha = proto.get("code_sha256")
    if recorded_sha and recorded_sha != actual_ws_sha:
        raise RuntimeError(
            f"{rdir.name}: 沙盒代码在打包冻结 t1 后被篡改（期望 {recorded_sha[:12]}，实测 {actual_ws_sha[:12]}）！"
        )

    score_path = rdir / "评分.json"
    result_path = rdir / "result.json"
    if not recompute and score_path.is_file():
        try:
            cached_sc = json.loads(score_path.read_text(encoding="utf-8"))
        except Exception:
            cached_sc = None
        ok, _reason = objective_cache.verify_objective_cache(
            cached_sc,
            expected_code_sha256=actual_ws_sha,
            scoring_hash=scoring_hash,
            deliverables_hash=deliv_hash,
        )
        if ok and cached_sc is not None:
            raw_res = json.loads(result_path.read_text(encoding="utf-8")) if result_path.is_file() else {}
            return cached_sc, raw_res, True

    # 计算端到端墙钟秒数
    e2e_sec = timing.get("endToEndSeconds")
    if e2e_sec is None:
        t0_ep = _epoch(timing.get("t0_iso")) or _epoch(timing.get("process_iso"))
        t1_ep = _epoch(timing.get("end_iso")) or datetime.datetime.now(datetime.timezone.utc).timestamp()
        e2e_sec = max(0.0, (t1_ep - t0_ep)) if t0_ep is not None else 0.0
    e2e_sec = float(e2e_sec)

    cfg = metrics.load_benchmark_config(ROOT)
    eval_bundle = evaluate_workspace_in_subprocess(rdir / "workspace", root=ROOT)

    raw_score = metrics.compute_objective_scores(
        b1_report=eval_bundle["b1_report"],
        perf_report=eval_bundle["perf_report"],
        redteam_report=eval_bundle["redteam_report"],
        e2e_seconds=e2e_sec,
        cfg=cfg,
    )

    ad = raw_score["A_detail"]
    bd = raw_score["B_detail"]
    run_summary = {
        "run_name": rdir.name,
        "model_id": proto.get("model_id"),
        "speedupRatio": ad["speedup_ratio"],
        "concurrentRpsRatio": ad["concurrent_rps_ratio"],
        "concurrentReadP95Ms": ad["concurrent_read_p95_ms"],
        "concurrentReadP99Ms": ad.get("concurrent_read_p99_ms", ad["concurrent_read_p95_ms"]),
        "sqlReductionPct": round(ad["sql_reduction_ratio"] * 100.0, 1),
        "memReductionPct": round(ad["mem_reduction_ratio"] * 100.0, 1),
        "residentHeapMb": ad.get("resident_heap_mb", 0.0),
        "b1AccuracyPct": round(bd["b1_accuracy"] * 100.0, 2),
        "endToEndSeconds": round(e2e_sec, 2),
        "endToEndMin": round(e2e_sec / 60.0, 2),
    }

    sealed_record = objective_cache.build_objective_record(
        raw_score,
        run_summary=run_summary,
        code_sha256=actual_ws_sha,
        t0_source=timing.get("t0_source"),
        b2_reliable=b2_reliable,
        scoring_hash=scoring_hash,
        deliverables_hash=deliv_hash,
    )

    result_payload = {
        "run_name": rdir.name,
        "evaluated_at": sealed_record["finalized_at"],
        "endToEndSeconds": round(e2e_sec, 2),
        "summary": run_summary,
        "b1_report": eval_bundle["b1_report"],
        "perf_report": eval_bundle["perf_report"],
        "redteam_report": eval_bundle["redteam_report"],
    }

    score_path.write_text(json.dumps(sealed_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result_path.write_text(json.dumps(result_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return sealed_record, result_payload, False


def main() -> int:
    ap = argparse.ArgumentParser(description="对已冻结的选手沙盒执行高压性能压测与红队实弹攻防定稿（仅限汇总/评测侧使用）")
    ap.add_argument("run_dir", nargs="?", help="目标运行目录，如 runs/deepseek-v4")
    ap.add_argument("--recompute", action="store_true", help="忽略防篡改缓存强制重新压测")
    ap.add_argument("--allow-unpacked", action="store_true", help="仅供维护自检调试未打包目录")
    ap.add_argument("--_worker-eval", dest="worker_eval", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.worker_eval:
        return _run_worker_eval(Path(args.worker_eval))

    if not args.run_dir:
        ap.error("请指定 run_dir")

    sc, _, cached = score_and_finalize_run(
        Path(args.run_dir),
        recompute=args.recompute,
        allow_unpacked=args.allow_unpacked,
    )
    tag = "CACHE-HIT" if cached else "EVALUATED"
    print(
        f"[{tag}] {Path(args.run_dir).name} -> "
        f"客观总分={sc['total_objective_70']:.2f}/70 "
        f"(A={sc['A_performance']:.2f}/30, B={sc['B_conservation_efficiency']:.2f}/15, C={sc['C_redteam_security']:.2f}/25)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
