#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""B2 端到端墙钟时间重叠审计工具（timing_audit.py · 对齐 silicon-rider-xiaonuo）。"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src" / "scoring") not in sys.path:
    sys.path.insert(0, str(ROOT / "src" / "scoring"))
from model_identity import canonical_model_id  # noqa: E402


def epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def load_run(run_dir: Path) -> dict | None:
    proto_path = run_dir / "protocol.json"
    if not proto_path.is_file():
        return None
    proto = json.loads(proto_path.read_text(encoding="utf-8"))
    timing = proto.get("timing") or {}
    start = epoch(timing.get("t0_iso")) or epoch(timing.get("process_iso"))
    end = epoch(timing.get("end_iso"))
    if start is None or end is None:
        return None
    name = run_dir.name
    return {
        "name": name,
        "model": canonical_model_id(proto.get("model_id") or name),
        "start": start,
        "end": end,
        "e2e_min": round((end - start) / 60.0, 2),
        "overlaps": [],
    }


def collect(root: Path) -> list[dict]:
    if not root.exists():
        return []
    if (root / "protocol.json").is_file():
        dirs = [root]
    else:
        dirs = [p for p in sorted(root.iterdir()) if p.is_dir() and (p / "protocol.json").is_file()]
    rows = [r for r in (load_run(d) for d in dirs) if r is not None]
    for a in rows:
        for b in rows:
            if a is b or a["model"] != b["model"]:
                continue
            if max(a["start"], b["start"]) < min(a["end"], b["end"]):
                a["overlaps"].append(b["name"])
    for a in rows:
        a["b2_comparable"] = not a["overlaps"]
    return rows


def build_report(rows: list[dict]) -> dict:
    any_overlap = any(bool(r["overlaps"]) for r in rows)
    return {
        "ok": not any_overlap,
        "overlapRuns": sum(1 for r in rows if r["overlaps"]),
        "runs": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="检查同一模型的多局运行是否存在墙钟重叠污染 B2")
    ap.add_argument("runs_dir", nargs="?", default=str(ROOT / "runs"))
    ap.add_argument("--strict", action="store_true", help="发现同模型时间重叠时以退出码 1 报错")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = collect(Path(args.runs_dir))
    if not rows:
        if args.json:
            print(json.dumps({"ok": True, "overlapRuns": 0, "runs": []}, ensure_ascii=False, indent=2))
        else:
            print("没有找到已完成冻结计时的 run 目录。")
        return 0

    report = build_report(rows)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] or not args.strict else 1

    print(f"{'run':40} {'e2e':>8}  同模型时间重叠")
    print("-" * 74)
    for r in sorted(rows, key=lambda x: (x["start"], x["name"])):
        ov = ("[OVERLAP] " + ", ".join(r["overlaps"])) if r["overlaps"] else "-"
        print(f"{r['name']:40} {r['e2e_min']:7.2f}m  {ov}")

    if not report["ok"]:
        print("\n警告：检测到同一模型多局时间重叠，并行队列等待会污染 B2 墙钟耗时；正式成绩请串行运行。")
        return 1 if args.strict else 0
    print("\nOK：未发现同模型多局时间重叠，B2 墙钟口径有效。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
