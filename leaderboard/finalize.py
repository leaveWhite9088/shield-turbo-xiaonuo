#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键全量汇总出榜薄入口（对齐 silicon-rider-xiaonuo）。

用法：
    python leaderboard/finalize.py                 # 全部模型出榜（客观分未变动时自动复用双指纹缓存，盲评实时重读）
    python leaderboard/finalize.py --recompute     # 强制忽略缓存，全量重跑高压压测与红队实弹攻防
    python leaderboard/finalize.py --dry-run       # 仅预览不写榜
    python leaderboard/finalize.py --model Demo    # 仅更新单个模型并重排总榜
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

args = [
    sys.executable,
    str(ROOT / "src" / "scoring" / "finalize.py"),
    "--review-log",
    str(ROOT / "leaderboard" / "reviews.jsonl"),
    "--d-aggregate",
    "mean",
    "--min-judges",
    "1",
    *sys.argv[1:],
]
raise SystemExit(subprocess.run(args, cwd=str(ROOT)).returncode)
