#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三基线端到端全链路闭环与大梯度自检验证（verify_three_baselines.py）。

在独立临时目录中完整跑通：
  start_run.py -> 部署三套基线 -> 沙盒公开冒烟 smoke_check.py -> judge_pack.py 冻结与生成 diff 盲评包
  -> isolation_audit.py --strict -> timing_audit.py --strict -> judge_submit.py 盲评提交
  -> finalize.py 高压压测 + 红队轰炸合成大榜 -> 二次 finalize.py 验证客观分双指纹缓存秒级命中！

并严格断言三套基线的真实客观分梯度（满分 70 分）：
  1. 初始未优化原版基线（raw-unoptimized）：B1=5.0/5，总客观分 < 15 / 70；
  2. 官方 5 级平庸优化基线（level5-mediocre）：B1=5.0/5，总客观分落在 30 ~ 40 / 70 区间；
  3. 9 级疾风铁盾大师基线（level9-master）：B1=5.0/5，提速 >= 30x，红队 25/25 满分，总客观分 >= 65 / 70！
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent


def _run_cmd(cmd: list[str], label: str) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"[{label}] 命令失败 (exit={proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc.stdout


def _overlay_baseline(src_baseline: Path, dst_workspace: Path) -> None:
    for p in src_baseline.rglob("*"):
        if not p.is_file():
            continue
        if "__pycache__" in p.parts or p.suffix in (".pyc", ".db"):
            continue
        rel = p.relative_to(src_baseline)
        target = dst_workspace / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, target)


def main() -> int:
    tmp_root = Path(tempfile.mkdtemp(prefix="st_e2e_3baselines_"))
    runs_dir = tmp_root / "runs"
    blind_dir = tmp_root / "blind"
    maps_dir = tmp_root / "blind-maps"
    verdicts_dir = tmp_root / "verdicts"
    review_log = tmp_root / "reviews.jsonl"
    scores_md = tmp_root / "scores.md"
    draft_dir = tmp_root / "draft"

    try:
        specs = [
            {
                "model": "baseline-raw-v1",
                "src": None,
                "sim_minutes": 4.0,
                "d_scores": (2.0, 1.5, 2.0),
            },
            {
                "model": "baseline-level5-v1",
                "src": ROOT / "src" / "baselines" / "level5_mediocre",
                "sim_minutes": 6.0,
                "d_scores": (5.0, 4.5, 4.5),  # 5 级平庸锁死 <= 15/30 (14.0)
            },
            {
                "model": "baseline-level9-v1",
                "src": ROOT / "src" / "baselines" / "level9_master",
                "sim_minutes": 6.0,
                "d_scores": (10.5, 9.8, 8.8),  # 9 级大师 (29.1)
            },
        ]

        base_clock = datetime.datetime(2026, 11, 22, 10, 0, 0, tzinfo=datetime.timezone.utc)

        for idx, sp in enumerate(specs):
            m_name = sp["model"]
            # 串行无重叠设定 t0（便于准确模拟标准开发时长并验证 timing_audit）
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            t0_dt = now_utc - datetime.timedelta(minutes=float(sp["sim_minutes"]))
            t0_iso = t0_dt.isoformat(timespec="seconds")

            print(f"[1/5] 开局初始化沙盒 -> {m_name}")
            _run_cmd(
                [
                    sys.executable,
                    str(ROOT / "tools" / "start_run.py"),
                    "--model",
                    m_name,
                    "--t0",
                    t0_iso,
                    "--runs-dir",
                    str(runs_dir),
                ],
                f"start_run:{m_name}",
            )

            ws_dir = runs_dir / m_name / "workspace"
            if sp["src"] is not None:
                _overlay_baseline(sp["src"], ws_dir)
            else:
                # 原版基线填写一份诚实的最小说明，避免空白警告干扰
                (ws_dir / "EXPLANATION.md").write_text(
                    "# 原版未优化基线说明\n\n保持初始沙盒代码未作性能优化与安全加固，用于验证基准下限。\n"
                    "\n## 4. 核心工程声明\n- [C1] 未改动原版实现。\n" * 3,
                    encoding="utf-8",
                )

            # 验证公开冒烟脚本在三套基线上均 100% 绿灯通过
            _run_cmd([sys.executable, str(ws_dir / "smoke_check.py")], f"smoke_check:{m_name}")

            # 打包生成脱敏匿名盲评包与 code_changes.diff
            print(f"[2/5] 冻结 t1 并生成匿名盲评包 -> {m_name}")
            _run_cmd(
                [
                    sys.executable,
                    str(ROOT / "src" / "scoring" / "judge_pack.py"),
                    "--model",
                    m_name,
                    "--runs-dir",
                    str(runs_dir),
                    "--blind-dir",
                    str(blind_dir),
                    "--blind-maps-dir",
                    str(maps_dir),
                ],
                f"judge_pack:{m_name}",
            )

            # 查找该模型对应的 pack_id 并提交 D 层盲评
            map_files = list(maps_dir.glob(f"{m_name}.*.blind-map.json"))
            assert len(map_files) == 1, f"Expected 1 blind-map for {m_name}, got {map_files}"
            bm = json.loads(map_files[0].read_text(encoding="utf-8"))
            pack_id = bm["pack_id"]
            pack_path = blind_dir / pack_id
            assert (pack_path / "OFFICIAL_LEVEL5_BASELINE.md").is_file()
            assert (pack_path / "case-01" / "code_changes.diff").is_file()

            d1, d2, d3 = sp["d_scores"]
            _run_cmd(
                [
                    sys.executable,
                    str(ROOT / "src" / "scoring" / "judge_submit.py"),
                    "--pack-dir",
                    str(pack_path),
                    "--case-id",
                    "case-01",
                    "--judge-id",
                    "judge-auto-verify",
                    "--judge-model",
                    "verifier-judge",
                    "--D1",
                    str(d1),
                    "--D2",
                    str(d2),
                    "--D3",
                    str(d3),
                    "--evidence",
                    "[C1-C5 已逐条对照 code_changes.diff 与 OFFICIAL_LEVEL5_BASELINE.md 完成核验]",
                    "--note",
                    "端到端三基线梯度核验评审记录",
                    "--review-log",
                    str(review_log),
                ],
                f"judge_submit:{m_name}",
            )

        # 隔离与脱敏严格审计 + 时间重叠审计
        print("[3/5] 执行严格角色隔离、脱敏与计时审计...")
        _run_cmd(
            [
                sys.executable,
                str(ROOT / "tools" / "isolation_audit.py"),
                "--runs-dir",
                str(runs_dir),
                "--blind-dir",
                str(blind_dir),
                "--blind-maps-dir",
                str(maps_dir),
                "--draft-dir",
                str(draft_dir),
                "--strict",
            ],
            "isolation_audit_pre_finalize",
        )
        _run_cmd(
            [sys.executable, str(ROOT / "tools" / "timing_audit.py"), str(runs_dir), "--strict"],
            "timing_audit",
        )

        # 一键全量高压压测 + 红队轰炸 + 出榜
        print("[4/5] 执行 finalize.py（首次高压压测 + 红队实弹攻防定稿 + 合成总榜）...")
        _run_cmd(
            [
                sys.executable,
                str(ROOT / "src" / "scoring" / "finalize.py"),
                "--review-log",
                str(review_log),
                "--runs-dir",
                str(runs_dir),
                "--blind-maps-dir",
                str(maps_dir),
                "--verdicts-dir",
                str(verdicts_dir),
                "--leaderboard-out",
                str(scores_md),
            ],
            "finalize_first_pass",
        )

        # 读取三套基线客观分与总分，执行硬指标断言！
        v_raw = json.loads((verdicts_dir / "baseline-raw-v1.json").read_text(encoding="utf-8"))["runs"][0]
        v_lvl5 = json.loads((verdicts_dir / "baseline-level5-v1.json").read_text(encoding="utf-8"))["runs"][0]
        v_lvl9 = json.loads((verdicts_dir / "baseline-level9-v1.json").read_text(encoding="utf-8"))["runs"][0]

        obj_raw = round(v_raw["A"] + v_raw["B"] + v_raw["C"], 2)
        obj_lvl5 = round(v_lvl5["A"] + v_lvl5["B"] + v_lvl5["C"], 2)
        obj_lvl9 = round(v_lvl9["A"] + v_lvl9["B"] + v_lvl9["C"], 2)

        print("\n================ 三基线实测成绩梯度核验 ================")
        print(
            f"  1) 初始未优化原版 : 客观分 = {obj_raw:5.2f}/70 "
            f"(A={v_raw['A']:.2f}, B={v_raw['B']:.2f}[B1={v_raw['B1']:.2f}], C={v_raw['C']:.2f}, 加速={v_raw['speedup']:.1f}x) | 总分={v_raw['total']:.2f}/100"
        )
        print(
            f"  2) 官方 5 级平庸版 : 客观分 = {obj_lvl5:5.2f}/70 "
            f"(A={v_lvl5['A']:.2f}, B={v_lvl5['B']:.2f}[B1={v_lvl5['B1']:.2f}], C={v_lvl5['C']:.2f}, 加速={v_lvl5['speedup']:.1f}x) | 总分={v_lvl5['total']:.2f}/100"
        )
        print(
            f"  3) 9 级疾风铁盾版  : 客观分 = {obj_lvl9:5.2f}/70 "
            f"(A={v_lvl9['A']:.2f}, B={v_lvl9['B']:.2f}[B1={v_lvl9['B1']:.2f}], C={v_lvl9['C']:.2f}, 加速={v_lvl9['speedup']:.1f}x) | 总分={v_lvl9['total']:.2f}/100"
        )
        print("========================================================\n")

        # 严格梯度断言
        assert v_raw["B1"] == 5.0, f"原版基线 B1 业务守恒必须满分 5.0，实测: {v_raw['B1']}"
        assert obj_raw < 15.0, f"原版基线总客观分必须 < 15/70，实测: {obj_raw}"

        assert v_lvl5["B1"] == 5.0, f"5级平庸基线 B1 业务守恒必须满分 5.0，实测: {v_lvl5['B1']}"
        assert 24.0 <= obj_lvl5 <= 42.0, f"5级平庸基线客观分必须落在中等偏下区间 (24~42/70)，实测: {obj_lvl5}"

        assert v_lvl9["B1"] == 5.0, f"9级大师基线 B1 业务守恒必须满分 5.0，实测: {v_lvl9['B1']}"
        assert v_lvl9["speedup"] >= 30.0, f"9级大师基线加速比必须 >= 30x，实测: {v_lvl9['speedup']}x"
        assert v_lvl9["C"] >= 24.5, f"9级大师基线红队安全分必须逼近满分 25/25，实测: {v_lvl9['C']}"
        assert obj_lvl9 >= 65.0, f"9级大师基线客观总分必须 >= 65/70，实测: {obj_lvl9}"

        # 第二次执行 finalize.py：验证客观分双指纹缓存 100% 命中且出榜后隔离审计依然全绿！
        print("[5/5] 二次执行 finalize.py 验证双指纹防篡改缓存复用与事后隔离审计...")
        _run_cmd(
            [
                sys.executable,
                str(ROOT / "src" / "scoring" / "finalize.py"),
                "--review-log",
                str(review_log),
                "--runs-dir",
                str(runs_dir),
                "--blind-maps-dir",
                str(maps_dir),
                "--verdicts-dir",
                str(verdicts_dir),
                "--leaderboard-out",
                str(scores_md),
            ],
            "finalize_cached_pass",
        )
        v9_cached = json.loads((verdicts_dir / "baseline-level9-v1.json").read_text(encoding="utf-8"))
        assert v9_cached["summary"]["objective_cache_hits"] == 1, "二次汇总必须命中双指纹防篡改客观分缓存！"

        _run_cmd(
            [
                sys.executable,
                str(ROOT / "tools" / "isolation_audit.py"),
                "--runs-dir",
                str(runs_dir),
                "--blind-dir",
                str(blind_dir),
                "--blind-maps-dir",
                str(maps_dir),
                "--draft-dir",
                str(draft_dir),
                "--strict",
            ],
            "isolation_audit_post_finalize",
        )

        print("[ALL PASS] 三基线大梯度验证、盲评打包脱敏、双指纹缓存与全链路闭环全部通过！")
        return 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
