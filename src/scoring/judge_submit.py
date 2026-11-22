#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""评委提交单条 D 层盲评打分：只追加到中心评审日志，不读取或回显其他评委分数；支持同一评委随时重评。"""
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
    ap = argparse.ArgumentParser(description="提交或重评更新匿名盲评包 D1/D2/D3 得分")
    ap.add_argument("--pack-dir", required=True, help="评委收到的 leaderboard/blind/<pack_id>/ 目录")
    ap.add_argument("--case-id", required=True, help="包内案例编号，如 case-01")
    ap.add_argument("--judge-id", required=True, help="评委唯一 ID（重评更新时请保持同一 ID）")
    ap.add_argument("--judge-model", required=True, help="评委模型或姓名标识")
    ap.add_argument("--D1", type=float, required=True, help="D1 算法降维与缓存/锁粒度设计 (0-11)")
    ap.add_argument("--D2", type=float, required=True, help="D2 纵深安全防御体系化 (0-10)")
    ap.add_argument("--D3", type=float, required=True, help="D3 补丁外科手术品味与诚实度 (0-9)")
    ap.add_argument("--evidence", required=True, help="必填：C1-C5 诚实度核验结论 + 对照 5 级样本的具体 diff/源码定位证据")
    ap.add_argument("--note", required=True, help="必填：指出该作品的最强反证与核心工程短板")
    ap.add_argument("--review-log", default=str(review_log.DEFAULT_LOG))
    ap.add_argument("--update", action="store_true", help="显式声明重评覆盖同一 judge-id 的历史打分")
    ap.add_argument("--reject-duplicate", action="store_true", help="若该评委已评过同一 case 则拒绝提交")
    args = ap.parse_args()

    pack_dir = Path(args.pack_dir).resolve()
    manifest_path = pack_dir / "pack.json"
    if not manifest_path.is_file():
        print(f"找不到盲评包清单：{manifest_path}")
        return 1

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"盲评包清单解析失败：{e}")
        return 1

    pack_id = manifest.get("pack_id")
    case_ids = [c.get("case_id") for c in (manifest.get("cases") or []) if c.get("case_id")]
    if not pack_id or args.case_id not in case_ids:
        print(f"pack_id 或 case_id 无效：pack={pack_id} case={args.case_id}")
        print("可用 case：" + ", ".join(case_ids))
        return 1

    if len(args.evidence.strip()) < 12:
        print("--evidence 过短；请列出 C1-C5 核验结果及具体源码/补丁证据。")
        return 1
    if len(args.note.strip()) < 4:
        print("--note 不能为空；请写出最强反证或工程短板。")
        return 1

    reject_dup = bool(args.reject_duplicate and not args.update)
    rec = {
        "schema_version": review_log.SCHEMA_VERSION,
        "judge_id": args.judge_id.strip(),
        "judge_model": args.judge_model.strip(),
        "pack_id": pack_id,
        "case_id": args.case_id,
        "D1": args.D1,
        "D2": args.D2,
        "D3": args.D3,
        "evidence": args.evidence.strip(),
        "note": args.note.strip(),
    }

    try:
        saved, prior_count = review_log.append_review(
            args.review_log,
            rec,
            reject_duplicate=reject_dup,
            return_prior_count=True,
        )
    except review_log.DuplicateReviewError as e:
        print("提交失败：" + str(e))
        return 2
    except review_log.ReviewLogError as e:
        print("提交失败：" + str(e))
        return 1

    if prior_count > 0:
        print(f"评分重评提交成功（已追加新记录，覆盖同一评委此前 {prior_count} 条旧记录；出榜时实时取最新一条生效）。")
    else:
        print("评分提交成功。")
    print(f"review_id={saved['review_id']}  pack_id={saved['pack_id']}  case_id={saved['case_id']}  D_total={saved['total']:.2f}/30")
    print("本次提交仅追加日志，未读取或回显其他评委的评分。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
