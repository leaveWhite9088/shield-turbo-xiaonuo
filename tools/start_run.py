#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选手一键开局工具（start_run.py）。

职责：
1. 在 runs/<模型标识>/workspace/ 下初始化带病但功能全绿的 AegisGate 独立沙盒副本；
2. 打下起点时间戳 t0，计算并锁定评测环境承诺哈希 env_commit 与初始模板哈希 template_sha256；
3. 生成 runs/<模型标识>/token_usage.json 词元消耗自报模板。
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src" / "scoring"))

from model_identity import canonical_model_id, sanitize_run_name  # noqa: E402
from objective_cache import compute_workspace_sha256  # noqa: E402

PROTECTED_ENV_FILES = (
    "configs/benchmark.json",
    "src/scoring/metrics.py",
    "src/scoring/workload.py",
    "src/scoring/redteam.py",
    "src/scoring/score_run.py",
    "src/scoring/objective_cache.py",
    "src/scoring/judge_pack.py",
    "src/scoring/judge_submit.py",
    "src/scoring/finalize.py",
)


def compute_env_commit(root: Path = ROOT) -> str:
    """对核心评分配置、高压压测与红队脚本计算联合 SHA-256 承诺哈希。"""
    base = Path(root).resolve()
    h = hashlib.sha256()
    for rel in PROTECTED_ENV_FILES:
        p = base / rel
        h.update(rel.encode("utf-8") + b"\0")
        if p.is_file():
            norm = p.read_bytes().replace(b"\r\n", b"\n")
            h.update(hashlib.sha256(norm).digest())
        else:
            h.update(b"MISSING")
    return h.hexdigest()


def _clear_dir(target_dir: Path) -> None:
    if not target_dir.exists():
        return
    shutil.rmtree(target_dir, ignore_errors=True)
    if target_dir.exists():
        for p in sorted(target_dir.rglob("*"), reverse=True):
            try:
                if p.is_file() or p.is_symlink():
                    p.unlink()
                elif p.is_dir():
                    p.rmdir()
            except OSError:
                pass


def main() -> int:
    ap = argparse.ArgumentParser(description="初始化选手独立沙盒并打下起点时钟 t0")
    ap.add_argument("--model", required=True, help="被测模型真实名称或运行标识，如 gemini-4-carbon")
    ap.add_argument("--t0", default=None, help="可选外部传入起始 ISO-8601 时间；默认取当前系统时钟")
    ap.add_argument("--runs-dir", default=str(ROOT / "runs"), help="运行根目录（默认 runs/）")
    ap.add_argument("--force", action="store_true", help="若同名运行目录已存在则强制清空重建")
    args = ap.parse_args()

    try:
        run_name = sanitize_run_name(args.model)
    except ValueError as e:
        print(f"开局失败：{e}")
        return 1

    model_id = canonical_model_id(run_name)
    runs_root = Path(args.runs_dir).resolve()
    run_dir = runs_root / run_name
    workspace_dir = run_dir / "workspace"
    template_dir = ROOT / "src" / "sandbox_template"

    if not template_dir.is_dir():
        print(f"找不到初始沙盒模板：{template_dir}")
        return 1

    if run_dir.exists():
        has_files = any(p.is_file() for p in run_dir.rglob("*"))
        if has_files and not args.force:
            print(f"运行目录已存在：{run_dir}")
            print("如需重开覆盖，请显式传入 --force；否则请直接继续在对应的 workspace/ 中优化加固。")
            return 1
        _clear_dir(run_dir)

    run_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        template_dir,
        workspace_dir,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.db", "*.sqlite*"),
    )

    now_iso = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    if args.t0:
        try:
            datetime.datetime.fromisoformat(args.t0.replace("Z", "+00:00"))
        except ValueError as e:
            print(f"--t0 不是合法 ISO-8601 时间：{e}")
            return 1
        t0_iso = args.t0
        t0_source = "external"
    else:
        t0_iso = now_iso
        t0_source = "process"

    cfg = json.loads((ROOT / "configs" / "benchmark.json").read_text(encoding="utf-8"))
    env_commit = compute_env_commit(ROOT)
    template_sha = compute_workspace_sha256(workspace_dir)

    protocol = {
        "schema_version": 1,
        "benchmark": cfg.get("name", "shield-turbo-xiaonuo"),
        "version": cfg.get("version", "xiaonuo-v3.0"),
        "run_name": run_name,
        "model_id": model_id,
        "status": "in_progress",
        "env_commit": env_commit,
        "template_sha256": template_sha,
        "code_sha256": None,
        "timing": {
            "t0_iso": t0_iso,
            "process_iso": now_iso,
            "t0_source": t0_source,
            "end_iso": None,
            "endToEndSeconds": None,
        },
    }
    (run_dir / "protocol.json").write_text(
        json.dumps(protocol, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    token_template = {
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
        "source": "self_report",
        "note": "收尾打包前请填入本局累计词元消耗；若宿主无法获取请保留 null 并注明原因",
    }
    (run_dir / "token_usage.json").write_text(
        json.dumps(token_template, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("================================================================")
    print("开局成功！《疾风铁盾》端到端优化与安全加固计时已启动。")
    print(f"  运行标识   : {run_name}（规范模型 ID: {model_id}）")
    print(f"  起点时间 t0: {t0_iso} (source={t0_source})")
    print(f"  专属沙盒   : {workspace_dir}")
    print("----------------------------------------------------------------")
    print("【选手唯一行动路径】")
    print(f"  1. 仅在你的专属沙盒内工作：{workspace_dir}")
    print("  2. 阅读沙盒内的 TASK.md，剖析 aegis_app/ 源码并完成深度性能优化与纵深安全加固")
    print(f"  3. 运行基础功能回归冒烟测试：python {workspace_dir / 'smoke_check.py'}")
    print("  4. 如实填写沙盒内的 EXPLANATION.md（含 5 条必核验声明 C1-C5）及上一级 token_usage.json")
    print(f"  5. 收工冻结计时并生成匿名盲评包：python src/scoring/judge_pack.py --model {run_name}")
    print("【严格隔离红线】严禁读取 README.md、docs/、configs/、src/、leaderboard/ 或其他 runs/ 目录！")
    print("================================================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
