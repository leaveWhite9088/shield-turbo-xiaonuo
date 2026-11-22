#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总查看中心评审日志（leaderboard/reviews.jsonl）。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import review_log  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="预览并聚合中心盲评记录")
    ap.add_argument("--log", default=str(review_log.DEFAULT_LOG))
    ap.add_argument("--out", default=None)
    ap.add_argument("--aggregate", choices=("mean", "median"), default="mean")
    args = ap.parse_args()

    reviews = review_log.read_reviews(args.log)
    latest, dup_cnt = review_log.dedupe_latest(reviews)
    groups = review_log.aggregate_reviews(latest, mode=args.aggregate)
    payload = {
        "total_entries": len(reviews),
        "superseded_entries": dup_cnt,
        "active_entries": len(latest),
        "aggregate_mode": args.aggregate,
        "cases": groups,
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        out_p = Path(args.out).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
