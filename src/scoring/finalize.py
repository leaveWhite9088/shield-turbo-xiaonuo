#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总出榜引擎（finalize.py · 对齐 silicon-rider-xiaonuo）。

核心机制：
1. 客观分（A30 + B15 + C25 = 70）与盲评分（D30）物理分离存储、独立校验：
   - 客观分定稿于各局 评分.json（绑定 scoring_hash、deliverables_hash 与 attestation 防篡改签名）；
   - 盲评分独立存储于中心追加日志 leaderboard/reviews.jsonl（绝不缓存在客观分中）。
2. 双指纹防篡改缓存：
   - 配置、评测脚本与冻结沙盒源码均未变动时，秒级复用已定稿客观分；
   - 传入 --recompute（或 --force-rescore）可强制全量重跑高压压测与红队实弹轰炸。
3. 盲评随时重评、实时生效：
   - 每次汇总均实时重读 reviews.jsonl，按 (pack_id, case_id, judge_id) 取最新一条合成总分。
4. 同一规范模型多局明细完整保留，总榜严格按多局算术平均数排名。
"""
from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
import statistics
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
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from model_identity import canonical_model_id  # noqa: E402
import objective_cache  # noqa: E402
import review_log  # noqa: E402
import score_run  # noqa: E402
import timing_audit  # noqa: E402

DEFAULT_LEADERBOARD = ROOT / "leaderboard" / "scores.md"
DEFAULT_VERDICTS = ROOT / "leaderboard" / "verdicts"
DEFAULT_BLIND_MAPS = ROOT / "leaderboard" / "blind-maps"


DEFAULT_HEAD = """# 排行榜 · shield-turbo-xiaonuo（疾风铁盾）

> D 层盲评记录由独立评委通过 `judge_submit.py` 追加至中心日志 `leaderboard/reviews.jsonl`；客观压测与红队实弹攻防得分由 `finalize.py` 统一核验定稿并合成总榜。
>
> **当前赛制版本：`xiaonuo-v2.0`（十六模块深水版）** — `A 性能压榨(30) + B 业务守恒与效率(15) + C 红队安全攻防(25) + D 优化与安全思想盲评(30) = 100 分`。

## 计分与封顶口径

| 维度 | 满分 | 核心规则 |
| --- | --- | --- |
| **A 性能压榨** | **30** | `A1` 穿插实时写入的检索与三跳滑窗批处理两段式对数加速比（12，拐点 60× 得 9 分、180× 满分）+ `A2` 高并发混合读写吞吐（4.5）与 P95（3.5）/ P99（2.0）尾延迟（严惩全局粗暴大锁串行退化）+ `A3` SQL 查询削减（3.5）、流式导出内存下降（2.5）与常驻堆内存预算 `≤ 8MB`（2.0）（严惩无脑全表常驻内存） |
| **B 守恒与效率** | **15** | `B1` 80+ 项全契约业务输出零失真守恒（5）+ `B2` 端到端优化耗时（10，6 分钟内满分、8 分钟半衰期）；若 `B1` 准确率 `< 100%`，`A` 与 `B2` 强行乘以 `B1_acc ** 5`，且 `B2` 同时受 `(A + C) / 55` 质量得分率与 `(C / 25) ** 2` 安全完整度因子双重封顶 |
| **C 红队安全攻防** | **25** | `C1` 一/二阶模板 SQL 注入、多变体路径穿越、`.format` 反射窃密、三级利益冲突隔离墙与借调级联撤权竞态（9）+ `C2` 30 路并发穿盾、24 路双向跨池调拨死锁探测、12 路并发 Nonce 重放与半批传染图原子回滚（8）+ `C3` 多变体/花括号大上界 ReDoS、千层 JSON/膨胀树、通配放大与混写穿透洪泛 P95 护盾（8） |
| **D 工程思想盲评** | **30** | 独立评委审阅匿名 `code_changes.diff` 对照《官方 5 级平庸参照补丁样本》盲评：`D1` 增量降维与锁/缓存架构（11）+ `D2` 纵深防御体系化（10）+ `D3` 外科手术品味与 C1–C5 诚实度（9）；**四档硬封顶**：平庸 `≤ 14.0/30`、非增量索引或调拨死锁隐患 `≤ 20.5/30`、局部耦合或边界漏防 `≤ 24.5/30`、零死角闭环大师 `25.5–30.0/30` |

---

"""


def _load_realtime_review_groups(review_log_path: str, d_aggregate: str) -> tuple[dict[tuple[str, str], dict], int]:
    try:
        reviews = review_log.read_reviews(review_log_path)
    except review_log.ReviewLogError as e:
        raise RuntimeError("读取评审日志失败：" + str(e)) from e
    if not reviews:
        raise RuntimeError("评审日志为空：" + str(Path(review_log_path).resolve()))
    used, duplicates = review_log.dedupe_latest(reviews)
    groups = review_log.aggregate_reviews(used, d_aggregate)
    by_key = {(g["pack_id"], g["case_id"]): g for g in groups}
    return by_key, duplicates


def _parse_existing_leaderboard(leaderboard_path: Path) -> tuple[str, dict[str, str], list[str]]:
    if not leaderboard_path.exists():
        return DEFAULT_HEAD, {}, []
    raw = leaderboard_path.read_text(encoding="utf-8")
    head_part, sep, body = raw.partition("### 最终成绩")
    head = DEFAULT_HEAD
    sec_by_model: dict[str, str] = {}
    extra_secs: list[str] = []
    if sep:
        raw_secs = (sep + body).split("\n### 最终成绩")
        for idx, s in enumerate(raw_secs):
            chunk = (s if idx == 0 else "### 最终成绩" + s).strip()
            if not chunk:
                continue
            first_line = chunk.splitlines()[0]
            if first_line.startswith("### 最终成绩 · "):
                m_part = first_line[len("### 最终成绩 · "):].split(" — ", 1)[0].strip()
                sec_by_model[m_part] = chunk
            else:
                extra_secs.append(chunk)
    return head, sec_by_model, extra_secs


def _write_sorted_leaderboard(
    leaderboard_path: Path,
    verdicts_dir: Path,
    updated_sections: dict[str, str],
    *,
    replace_all: bool,
) -> None:
    head, existing_secs, extra_secs = _parse_existing_leaderboard(leaderboard_path)
    if replace_all:
        sec_by_model = dict(updated_sections)
        extra_secs = []
        target_models = list(updated_sections.keys())
    else:
        sec_by_model = dict(existing_secs)
        sec_by_model.update(updated_sections)
        target_models = sorted({vf.stem for vf in verdicts_dir.glob("*.json")} | set(sec_by_model.keys()))

    board: list[dict[str, Any]] = []
    for mid in target_models:
        vf = verdicts_dir / f"{mid}.json"
        if vf.is_file():
            try:
                board.append(json.loads(vf.read_text(encoding="utf-8")))
            except Exception:
                pass
    board.sort(key=lambda v: (-(v.get("mean", {}).get("total") or 0.0), v.get("model", "")))

    blines = [
        "## 大榜（按各模型总分均值排名）",
        "",
        "| 排名 | 模型 | 总分(100) | A性能(30) | B1守恒(5) | B2耗时(10) | C1边界缓存(9) | C2并发重放(8) | C3抗DoS(8) | D1降维(11) | D2安全(10) | D3品味诚实(9) | 加速倍数 | 耗时(分) | 已评run |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def cell(m: dict, k: str) -> str:
        x = m.get(k) if isinstance(m, dict) else None
        return f"{x:.2f}" if isinstance(x, (int, float)) else "-"

    for i, v in enumerate(board, 1):
        m = v.get("mean") or {}
        s = v.get("summary") or {}
        sp = m.get("speedup")
        sp_str = f"{sp:.1f}x" if isinstance(sp, (int, float)) else "-"
        e2e = m.get("endToEndMin")
        e2e_str = f"{e2e:.1f}" if isinstance(e2e, (int, float)) else "-"
        blines.append(
            f"| {i} | {v['model']} | **{m['total']:.2f}** | {cell(m, 'A')} | {cell(m, 'B1')} | {cell(m, 'B2')} "
            f"| {cell(m, 'C1')} | {cell(m, 'C2')} | {cell(m, 'C3')} | {cell(m, 'D1')} | {cell(m, 'D2')} | {cell(m, 'D3')} "
            f"| {sp_str} | {e2e_str} | {s.get('runs_scored', '-')} |"
        )
    blines += ["", ""]

    ordered_secs = [sec_by_model.pop(v["model"]) for v in board if v.get("model") in sec_by_model]
    ordered_secs.extend(sec_by_model.values())
    ordered_secs.extend(extra_secs)
    detail_text = ("\n\n".join(ordered_secs) + "\n") if ordered_secs else ""

    leaderboard_path.parent.mkdir(parents=True, exist_ok=True)
    leaderboard_path.write_text(head + "\n".join(blines) + detail_text, encoding="utf-8")


def finalize_model(
    target_model: str,
    args: argparse.Namespace,
    *,
    scoring_hash: str,
    review_groups_cache: dict[tuple[str, str], dict] | None = None,
    overlap_set: set[str] | None = None,
    blind_maps_dir: Path = DEFAULT_BLIND_MAPS,
    verdicts_dir: Path = DEFAULT_VERDICTS,
) -> tuple[dict[str, Any], str]:
    model_id = (args.model_id.strip().lower() if args.model_id else canonical_model_id(target_model)).strip()
    if not model_id:
        raise RuntimeError("--model/--model-id 不能为空")

    map_args = args.blind_map or []
    map_files = [Path(p).resolve() for p in map_args]
    if not map_files and blind_maps_dir.exists():
        for mf in sorted(blind_maps_dir.glob("*.blind-map.json")):
            try:
                bm = json.loads(mf.read_text(encoding="utf-8"))
            except Exception:
                continue
            if bm.get("superseded_by"):
                continue
            map_mid = canonical_model_id(bm.get("model_id") or bm.get("model", ""))
            if map_mid == model_id:
                map_files.append(mf)
    map_files = list(dict.fromkeys(map_files))

    blind_maps = []
    model_inputs = {target_model}
    run_to_case: dict[str, str] = {}
    run_to_pack: dict[str, str] = {}
    for mf in map_files:
        if not mf.exists():
            raise RuntimeError(f"找不到盲评私有映射：{mf}")
        bm = json.loads(mf.read_text(encoding="utf-8"))
        if bm.get("superseded_by"):
            continue
        map_mid = canonical_model_id(bm.get("model_id") or bm.get("model", ""))
        if map_mid and map_mid != model_id:
            raise RuntimeError(f"盲评映射模型 {map_mid} 与目标 {model_id} 不一致")
        if bm.get("model"):
            model_inputs.add(bm["model"])
        pack_id = bm.get("pack_id")
        if not pack_id:
            raise RuntimeError(f"映射缺少 pack_id：{mf}")
        for cid, meta in (bm.get("cases") or {}).items():
            raw_run = (meta or {}).get("run")
            if not raw_run:
                continue
            rname = Path(raw_run).name
            if rname in run_to_case:
                raise RuntimeError(f"run {rname} 重复出现在多个有效盲评映射中")
            run_to_case[rname] = cid
            run_to_pack[rname] = pack_id
        blind_maps.append(bm)

    runs_root = Path(args.runs_dir).resolve() if getattr(args, "runs_dir", None) else (ROOT / "runs")
    if args.runs:
        runs = [Path(p).resolve() for p in args.runs]
    elif run_to_case:
        runs = [(runs_root / rname).resolve() for rname in sorted(run_to_case)]
    else:
        raise RuntimeError(f"未找到模型 {model_id} 的有效盲评映射或 --runs")

    # 实时读取最新盲评记录（绝不缓存）
    if review_groups_cache is not None:
        by_key = review_groups_cache
    else:
        by_key, _ = _load_realtime_review_groups(args.review_log, args.d_aggregate)

    runs_total_all = len(runs)
    ds: list[float | None] = []
    d_dims: list[dict[str, float] | None] = []
    case_ids: list[str | None] = []
    pack_ids: list[str | None] = []
    d_counts: list[int] = []

    for r in runs:
        cid = run_to_case.get(r.name)
        pid = run_to_pack.get(r.name)
        if not cid or not pid:
            if args.allow_partial:
                ds.append(None); d_dims.append(None); case_ids.append(None); pack_ids.append(None); d_counts.append(0)
                continue
            raise RuntimeError(f"私有映射中缺少运行目录 {r.name}")
        g = by_key.get((pid, cid))
        if not g or g["judge_count"] < args.min_judges:
            if args.allow_partial:
                ds.append(None); d_dims.append(None); case_ids.append(cid); pack_ids.append(pid); d_counts.append(0)
                continue
            if not g:
                raise RuntimeError(f"评审日志里尚无 pack={pid} case={cid}（run={r.name}）的盲评打分")
            raise RuntimeError(f"{r.name} 当前仅有 {g['judge_count']} 位评委，少于 --min-judges {args.min_judges}")
        ds.append(g["D"])
        d_dims.append({"D1": g["D1"], "D2": g["D2"], "D3": g["D3"]})
        case_ids.append(cid)
        pack_ids.append(pid)
        d_counts.append(g["judge_count"])

    judge_reviews_all = sum(d_counts)
    scored_idx = [i for i, d in enumerate(ds) if d is not None]
    if not scored_idx:
        raise RuntimeError(f"模型 {model_id} 没有可汇总的已完成盲评 run")

    runs = [runs[i] for i in scored_idx]
    ds_valid = [float(ds[i]) for i in scored_idx]  # type: ignore[arg-type]
    d_dims_valid = [d_dims[i] or {} for i in scored_idx]
    case_ids_valid = [case_ids[i] for i in scored_idx]
    pack_ids_valid = [pack_ids[i] for i in scored_idx]
    d_counts_valid = [d_counts[i] for i in scored_idx]

    rows = []
    errors = []
    cache_hits = 0
    recomputed = 0

    for run, d_val, dd, cid, j_cnt, pid in zip(
        runs, ds_valid, d_dims_valid, case_ids_valid, d_counts_valid, pack_ids_valid
    ):
        b2_ok = (overlap_set is None) or (run.name not in overlap_set)
        try:
            sc, _res_obj, used_cache = score_run.score_and_finalize_run(
                run,
                recompute=args.recompute,
                allow_unpacked=False,
                b2_reliable=b2_ok,
                scoring_hash=scoring_hash,
            )
            if used_cache:
                cache_hits += 1
            else:
                recomputed += 1
        except Exception as e:
            errors.append(str(e))
            continue

        rs = sc.get("run_summary") or {}
        ad = sc.get("A_detail") or {}
        bd = sc.get("B_detail") or {}
        cd = sc.get("C_detail") or {}
        A = float(sc["A_performance"])
        B = float(sc["B_conservation_efficiency"])
        C = float(sc["C_redteam_security"])
        rows.append(
            {
                "run": run.name,
                "pack_id": pid,
                "case_id": cid,
                "judge_count": j_cnt,
                "code_sha256": str(sc.get("code_sha256") or "")[:12],
                "objective_cached": used_cache,
                "b2_reliable": b2_ok,
                "speedup": rs.get("speedupRatio", ad.get("speedup_ratio", 1.0)),
                "b1AccuracyPct": rs.get("b1AccuracyPct", 100.0),
                "endToEndMin": rs.get("endToEndMin", bd.get("endToEndMinutes", 0.0)),
                "A": A,
                "B": B,
                "C": C,
                "D": d_val,
                "total": round(A + B + C + d_val, 2),
                "A1": ad.get("A1_batch_search12"),
                "A2": ad.get("A2_concurrency10"),
                "A3": ad.get("A3_resource8"),
                "B1": bd.get("B1_conservation5"),
                "B2": bd.get("B2_time10"),
                "C1": cd.get("C1_access_cache9"),
                "C2": cd.get("C2_toctou_replay8"),
                "C3": cd.get("C3_anti_dos8"),
                "D1": dd.get("D1"),
                "D2": dd.get("D2"),
                "D3": dd.get("D3"),
            }
        )

    if errors:
        raise RuntimeError("不能出榜：\n" + "\n".join("  !! " + e for e in errors))

    def agg(key: str) -> tuple[float | None, float | None]:
        vals = [float(r[key]) for r in rows if isinstance(r.get(key), (int, float))]
        return (round(statistics.mean(vals), 2), round((max(vals) - min(vals)) / 2.0, 2)) if vals else (None, None)

    def f2(x: Any) -> str:
        return f"{x:.2f}" if isinstance(x, (int, float)) else "-"

    lines = [
        f"### 最终成绩 · {model_id} — {datetime.datetime.now():%Y-%m-%d %H:%M}",
        "",
        "| 运行标识 | 加速比 | 守恒率 | 耗时(分) | A(30) | B1守恒(5) | B2耗时(10) | C1(9) | C2(8) | C3(8) | D1(11) | D2(10) | D3(9) | 评委 | 总分(100) | 代码承诺 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(
            f"| {r['run']} | {r['speedup']:.1f}x | {r['b1AccuracyPct']:.1f}% | {r['endToEndMin']:.1f} "
            f"| {f2(r['A'])} | {f2(r['B1'])} | {f2(r['B2'])} | {f2(r['C1'])} | {f2(r['C2'])} | {f2(r['C3'])} "
            f"| {f2(r['D1'])} | {f2(r['D2'])} | {f2(r['D3'])} | {r['judge_count']} | **{r['total']:.2f}** | `{r['code_sha256']}` |"
        )

    mA, rA = agg("A"); mB, rB = agg("B"); mC, rC = agg("C")
    mD, rD = agg("D"); mT, rT = agg("total"); mSp, rSp = agg("speedup")
    mE2E, _ = agg("endToEndMin")
    mB1, _ = agg("B1"); mB2, _ = agg("B2")
    mC1, _ = agg("C1"); mC2, _ = agg("C2"); mC3, _ = agg("C3")
    mD1, _ = agg("D1"); mD2, _ = agg("D2"); mD3, _ = agg("D3")

    if len(rows) > 1:
        lines.append(
            f"| **平均** | {mSp:.1f}x | - | {mE2E:.1f} "
            f"| {f2(mA)} | {f2(mB1)} | {f2(mB2)} | {f2(mC1)} | {f2(mC2)} | {f2(mC3)} "
            f"| {f2(mD1)} | {f2(mD2)} | {f2(mD3)} | - | **{mT:.2f}** | - |"
        )

    lines += [
        "",
        f"**均值 ± 半极差**：加速比 {mSp:.1f}x ±{rSp:.1f}x｜A {mA:.2f} ±{rA:.2f}｜B {mB:.2f} ±{rB:.2f}"
        f"｜C {mC:.2f} ±{rC:.2f}｜D {mD:.2f} ±{rD:.2f}｜**总分 {mT:.2f} ±{rT:.2f}**",
        "",
        f"- 模型汇总：运行 {runs_total_all} 局（已评分 {len(rows)} 局），累计有效评委记录 {judge_reviews_all} 条。",
        f"- 客观分核验：复用双指纹防篡改缓存 {cache_hits} 局，现场高压压测与红队轰炸定稿 {recomputed} 局（scoring_hash `{scoring_hash[:12]}…`）；盲评 D 实时读取自 `reviews.jsonl`（聚合={args.d_aggregate}）。",
    ]
    section_text = "\n".join(lines)
    print(section_text)

    verdict_obj = {
        "model": model_id,
        "model_inputs": sorted(model_inputs),
        "finalized_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "scoring_hash": scoring_hash,
        "blind_pack_ids": sorted({r["pack_id"] for r in rows if r.get("pack_id")}),
        "d_aggregate": args.d_aggregate,
        "summary": {
            "runs_total": runs_total_all,
            "runs_scored": len(rows),
            "judge_reviews": judge_reviews_all,
            "objective_cache_hits": cache_hits,
            "objective_recomputed": recomputed,
        },
        "runs": rows,
        "mean": {
            "speedup": mSp,
            "endToEndMin": mE2E,
            "A": mA,
            "B": mB,
            "C": mC,
            "D": mD,
            "total": mT,
            "B1": mB1,
            "B2": mB2,
            "C1": mC1,
            "C2": mC2,
            "C3": mC3,
            "D1": mD1,
            "D2": mD2,
            "D3": mD3,
        },
    }

    if not args.dry_run:
        verdicts_dir.mkdir(parents=True, exist_ok=True)
        (verdicts_dir / f"{model_id}.json").write_text(
            json.dumps(verdict_obj, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return verdict_obj, section_text.strip()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="统一核验客观压测/红队攻防缓存并实时合成最新盲评出榜")
    ap.add_argument("--model", default=None, help="指定单个规范模型名；缺省自动发现 blind-maps 中全部模型一次性出榜")
    ap.add_argument("--model-id", default=None)
    ap.add_argument("--runs", nargs="*", default=None)
    ap.add_argument("--review-log", default=str(review_log.DEFAULT_LOG))
    ap.add_argument("--d-aggregate", choices=("mean", "median"), default="mean")
    ap.add_argument("--min-judges", type=int, default=1)
    ap.add_argument("--blind-map", action="append", default=None)
    ap.add_argument(
        "--recompute",
        "--force-recompute",
        "--force-rescore",
        dest="recompute",
        action="store_true",
        help="忽略客观分双指纹缓存，强制全量重跑高压性能压测与红队轰炸",
    )
    ap.add_argument("--allow-partial", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--leaderboard-out", default=None)
    ap.add_argument("--verdicts-dir", default=None)
    ap.add_argument("--blind-maps-dir", default=None)
    ap.add_argument("--runs-dir", default=None)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.min_judges < 1:
        print("--min-judges 必须 >= 1")
        return 1

    leaderboard_path = Path(args.leaderboard_out).resolve() if args.leaderboard_out else DEFAULT_LEADERBOARD
    verdicts_dir = Path(args.verdicts_dir).resolve() if args.verdicts_dir else DEFAULT_VERDICTS
    blind_maps_dir = Path(args.blind_maps_dir).resolve() if args.blind_maps_dir else DEFAULT_BLIND_MAPS
    runs_dir = Path(args.runs_dir).resolve() if args.runs_dir else (ROOT / "runs")

    scoring_hash = objective_cache.compute_scoring_hash(ROOT)
    timing_rows = timing_audit.collect(runs_dir)
    overlap_set = {r["name"] for r in timing_rows if r.get("overlaps")}

    try:
        review_groups_cache, duplicates = _load_realtime_review_groups(args.review_log, args.d_aggregate)
        if duplicates:
            print(f"!! 评审日志含 {duplicates} 条同评委重评历史记录，已实时采信最新一条")
    except RuntimeError as e:
        print(str(e))
        return 1

    if not args.model:
        discovered: list[str] = []
        if blind_maps_dir.exists():
            for mf in sorted(blind_maps_dir.glob("*.blind-map.json")):
                try:
                    bm = json.loads(mf.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if bm.get("superseded_by"):
                    continue
                mid = canonical_model_id(bm.get("model_id") or bm.get("model", ""))
                if mid and mid not in discovered:
                    discovered.append(mid)
        if not discovered:
            print("未指定 --model，且 blind-maps 目录中没有可汇总的模型")
            return 1
        print(f"自动发现 {len(discovered)} 个模型并汇总出榜：{', '.join(discovered)}")
        updated_secs: dict[str, str] = {}
        failed: list[str] = []
        for mid in discovered:
            print(f"\n===== {mid} =====")
            try:
                _v, sec_md = finalize_model(
                    mid,
                    args,
                    scoring_hash=scoring_hash,
                    review_groups_cache=review_groups_cache,
                    overlap_set=overlap_set,
                    blind_maps_dir=blind_maps_dir,
                    verdicts_dir=verdicts_dir,
                )
                updated_secs[mid] = sec_md
            except RuntimeError as e:
                print(str(e))
                failed.append(mid)

        if not args.dry_run and updated_secs:
            _write_sorted_leaderboard(leaderboard_path, verdicts_dir, updated_secs, replace_all=True)
            print(f"\n排行榜已写入：{leaderboard_path}")
        if failed:
            print(f"\n以下模型出榜失败：{', '.join(failed)}")
            return 1
        return 0

    try:
        verdict_obj, sec_md = finalize_model(
            args.model,
            args,
            scoring_hash=scoring_hash,
            review_groups_cache=review_groups_cache,
            overlap_set=overlap_set,
            blind_maps_dir=blind_maps_dir,
            verdicts_dir=verdicts_dir,
        )
    except RuntimeError as e:
        print(str(e))
        return 1

    if not args.dry_run:
        _write_sorted_leaderboard(leaderboard_path, verdicts_dir, {verdict_obj["model"]: sec_md}, replace_all=False)
        print(f"\n已更新：{leaderboard_path} 与 {verdicts_dir / (verdict_obj['model'] + '.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
