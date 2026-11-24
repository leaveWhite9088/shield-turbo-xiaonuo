# -*- coding: utf-8 -*-
"""四维客观分（A 性能压榨 30 + B 守恒与效率 15 + C 红队攻防 25 = 70）连续插值与严苛封顶计分函数（xiaonuo-v2.0）。

所有权重、分段拐点、尾延迟门限、常驻堆内存预算与半衰期参数均从 configs/benchmark.json 读取。
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def load_benchmark_config(root: Path = ROOT) -> dict[str, Any]:
    cfg_path = Path(root).resolve() / "configs" / "benchmark.json"
    return json.loads(cfg_path.read_text(encoding="utf-8"))


def score_log_speedup(
    ratio: float,
    max_score: float,
    target_ratio: float,
    min_ratio: float = 1.05,
) -> float:
    """对数加速比连续计分曲线：ratio <= min_ratio 得 0，ratio >= target_ratio 得满分。"""
    if not isinstance(ratio, (int, float)) or math.isnan(ratio) or ratio <= min_ratio:
        return 0.0
    if ratio >= target_ratio:
        return float(max_score)
    num = math.log(ratio / min_ratio)
    den = math.log(target_ratio / min_ratio)
    if den <= 0:
        return 0.0
    return max(0.0, min(float(max_score), float(max_score) * (num / den)))


def score_piecewise_log_speedup(
    ratio: float,
    max_score: float,
    target_ratio: float,
    *,
    knee_ratio: float | None = None,
    knee_score: float | None = None,
    min_ratio: float = 1.05,
) -> float:
    """两段式边际递减对数加速曲线：过拐点后需冲刺极高增量并发加速比方可拿满顶部分值。"""
    if not isinstance(ratio, (int, float)) or math.isnan(ratio) or ratio <= min_ratio:
        return 0.0
    if ratio >= target_ratio:
        return float(max_score)
    if (
        knee_ratio is None
        or knee_score is None
        or knee_ratio <= min_ratio
        or knee_ratio >= target_ratio
        or knee_score <= 0
        or knee_score >= max_score
    ):
        return score_log_speedup(ratio, max_score, target_ratio, min_ratio=min_ratio)

    if ratio <= knee_ratio:
        frac = math.log(ratio / min_ratio) / math.log(knee_ratio / min_ratio)
        return max(0.0, min(float(knee_score), float(knee_score) * frac))

    tail_frac = math.log(ratio / knee_ratio) / math.log(target_ratio / knee_ratio)
    return max(
        0.0,
        min(float(max_score), float(knee_score) + (float(max_score) - float(knee_score)) * tail_frac),
    )


def score_latency_p95(
    p95_ms: float,
    max_score: float,
    target_ms: float,
    degraded_ms: float,
) -> float:
    """尾延迟对数连续计分：<= target_ms 得满分，>= degraded_ms 得 0 分。"""
    if not isinstance(p95_ms, (int, float)) or math.isnan(p95_ms) or p95_ms <= 0:
        return float(max_score)
    if p95_ms <= target_ms:
        return float(max_score)
    if p95_ms >= degraded_ms:
        return 0.0
    num = math.log(degraded_ms / p95_ms)
    den = math.log(degraded_ms / target_ms)
    return max(0.0, min(float(max_score), float(max_score) * (num / den)))


def score_reduction_ratio(reduction: float, max_score: float, target_reduction: float) -> float:
    """资源削减率平滑计分：reduction <= 0.02 得 0，>= target_reduction 得满分。"""
    if not isinstance(reduction, (int, float)) or math.isnan(reduction) or reduction <= 0.02:
        return 0.0
    if reduction >= target_reduction:
        return float(max_score)
    norm = (reduction - 0.02) / max(1e-6, target_reduction - 0.02)
    return max(0.0, min(float(max_score), float(max_score) * (norm ** 1.15)))


def score_heap_budget(
    resident_mb: float,
    max_score: float,
    budget_mb: float,
    zero_mb: float,
) -> float:
    """常驻堆内存增量预算计分：<= budget_mb 得满分，>= zero_mb（无脑全表常驻内存）得 0 分。"""
    if not isinstance(resident_mb, (int, float)) or math.isnan(resident_mb) or resident_mb <= budget_mb:
        return float(max_score)
    if resident_mb >= zero_mb:
        return 0.0
    frac = (zero_mb - resident_mb) / max(1e-6, zero_mb - budget_mb)
    return max(0.0, min(float(max_score), float(max_score) * frac))


def score_b2_wall_clock(
    e2e_minutes: float,
    max_score: float = 10.0,
    full_minutes: float = 6.0,
    half_life_minutes: float = 8.0,
) -> float:
    """端到端墙钟时间衰减曲线：full_minutes 内满分，超出按 half_life_minutes 指数减半。"""
    if e2e_minutes < 0 or math.isnan(e2e_minutes):
        return 0.0
    if e2e_minutes <= full_minutes:
        return float(max_score)
    exponent = (e2e_minutes - full_minutes) / max(1e-6, half_life_minutes)
    return max(0.0, float(max_score) * (0.5 ** exponent))


def compute_objective_scores(
    *,
    b1_report: dict[str, Any],
    perf_report: dict[str, Any],
    redteam_report: dict[str, Any],
    e2e_seconds: float,
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """综合 B1 无损守恒、A 性能压榨、C 红队攻防与 B2 端到端耗时计算全部 70 分客观指标。"""
    cfg = cfg or load_benchmark_config()
    sc_cfg = cfg["scoring"]
    a_cfg = sc_cfg["A_detail"]
    b_cfg = sc_cfg["B_detail"]

    # 1. B1 业务零失真守恒准确率与五次方毁灭性封顶系数
    b1_total = max(1, int(b1_report.get("total_checks", 1)))
    b1_passed = max(0, min(b1_total, int(b1_report.get("passed_checks", 0))))
    b1_acc = b1_passed / b1_total
    penalty_exp = float(b_cfg.get("accuracy_penalty_exponent", 5.0))
    conservation_factor = 1.0 if b1_acc >= 1.0 - 1e-9 else (b1_acc ** penalty_exp)
    b1_score = round(float(b_cfg["B1_accuracy_max"]) * conservation_factor, 2)

    # 2. A1 两段式对数加速曲线
    speedup_a1 = float(perf_report.get("a1_speedup_ratio", 1.0))
    a1_raw = score_piecewise_log_speedup(
        speedup_a1,
        max_score=float(a_cfg["A1_batch_search_speedup_max"]),
        target_ratio=float(a_cfg["A1_target_speedup"]),
        knee_ratio=float(a_cfg["A1_knee_speedup"]) if "A1_knee_speedup" in a_cfg else None,
        knee_score=float(a_cfg["A1_knee_score"]) if "A1_knee_score" in a_cfg else None,
        min_ratio=float(a_cfg.get("A1_min_speedup", 1.05)),
    )

    # 3. A2 混合并发吞吐 + P95 尾延迟 + P99 尖刺门控 + 全局大锁退化折算
    rps_ratio = float(perf_report.get("a2_rps_ratio", 1.0))
    conc_p95_ms = float(perf_report.get("a2_concurrent_read_p95_ms", 999.0))
    conc_p99_ms = float(perf_report.get("a2_concurrent_read_p99_ms", conc_p95_ms))
    cross_block_ratio = float(perf_report.get("a2_cross_tenant_block_ratio", 1.0))
    probe_p80_ms = float(perf_report.get("a2_probe_read_p80_ms", 0.0))
    conc_error_rate = float(perf_report.get("a2_error_rate", 0.0))

    a2_rps_part = score_log_speedup(
        rps_ratio,
        max_score=float(a_cfg["A2_rps_subweight"]),
        target_ratio=float(a_cfg["A2_target_rps_ratio"]),
        min_ratio=1.05,
    )
    a2_p95_part = score_latency_p95(
        conc_p95_ms,
        max_score=float(a_cfg["A2_p95_subweight"]),
        target_ms=float(a_cfg["A2_target_p95_ms"]),
        degraded_ms=float(a_cfg["A2_degraded_p95_ms"]),
    )
    p99_subw = float(a_cfg.get("A2_p99_subweight", 0.0))
    a2_p99_part = (
        score_latency_p95(
            conc_p99_ms,
            max_score=p99_subw,
            target_ms=float(a_cfg.get("A2_target_p99_ms", 20.0)),
            degraded_ms=float(a_cfg.get("A2_degraded_p99_ms", 280.0)),
        )
        if p99_subw > 0
        else 0.0
    )
    a2_raw = a2_rps_part + a2_p95_part + a2_p99_part

    global_lock_penalized = False
    penalty_threshold = float(a_cfg.get("A2_global_lock_serialization_penalty_ratio", 2.4))
    min_blocked_ms = float(a_cfg.get("A2_global_lock_min_blocked_ms", 20.0))
    if probe_p80_ms >= min_blocked_ms and cross_block_ratio >= penalty_threshold:
        global_lock_penalized = True
        degrade_mult = max(0.35, min(0.75, penalty_threshold / cross_block_ratio))
        a2_raw *= degrade_mult

    if conc_error_rate > 0:
        a2_raw *= max(0.0, 1.0 - min(1.0, conc_error_rate * 5.0))

    # 4. A3 SQL 削减率 + 流式导出内存下降率 + 常驻堆内存预算（打击无脑全表进内存）
    q_red = float(perf_report.get("a3_sql_reduction_ratio", 0.0))
    m_red = float(perf_report.get("a3_mem_reduction_ratio", 0.0))
    resident_heap_mb = float(perf_report.get("a3_resident_heap_mb", 0.0))

    a3_q_part = score_reduction_ratio(
        q_red,
        max_score=float(a_cfg["A3_query_reduction_subweight"]),
        target_reduction=float(a_cfg["A3_target_query_reduction"]),
    )
    a3_m_part = score_reduction_ratio(
        m_red,
        max_score=float(a_cfg["A3_memory_reduction_subweight"]),
        target_reduction=float(a_cfg["A3_target_memory_reduction"]),
    )
    heap_subw = float(a_cfg.get("A3_heap_budget_subweight", 0.0))
    # 仅在确实取得有效 SQL 削减（已建立索引/缓存机制）时兑现堆内存控制奖励，防止零缓存未优化原版白拿该子项
    if heap_subw > 0:
        raw_heap_score = score_heap_budget(
            resident_heap_mb,
            max_score=heap_subw,
            budget_mb=float(a_cfg.get("A3_resident_heap_budget_mb", 6.0)),
            zero_mb=float(a_cfg.get("A3_resident_heap_zero_mb", 24.0)),
        )
        eff_gate = min(1.0, max(0.0, q_red / 0.50))
        a3_heap_part = raw_heap_score * eff_gate
    else:
        a3_heap_part = 0.0

    a3_raw = a3_q_part + a3_m_part + a3_heap_part

    # 乘以 B1^5 业务守恒封顶
    a1_final = round(a1_raw * conservation_factor, 2)
    a2_final = round(a2_raw * conservation_factor, 2)
    a3_final = round(a3_raw * conservation_factor, 2)
    a_total = round(a1_final + a2_final + a3_final, 2)

    # 5. C 层红队攻防得分
    c1_raw = float(redteam_report.get("C1_score", 0.0))
    c2_raw = float(redteam_report.get("C2_score", 0.0))
    c3_raw = float(redteam_report.get("C3_score", 0.0))
    avail_gate = 1.0 if b1_acc >= 0.8 else (b1_acc / 0.8) ** 2
    c1_final = round(c1_raw * avail_gate, 2)
    c2_final = round(c2_raw * avail_gate, 2)
    c3_final = round(c3_raw * avail_gate, 2)
    c_total = round(c1_final + c2_final + c3_final, 2)

    # 6. B2 端到端优化耗时（受质量得分率、安全完整度二次方与 B1^5 守恒三重封顶）
    e2e_min = max(0.0, float(e2e_seconds) / 60.0)
    b2_unbounded = score_b2_wall_clock(
        e2e_min,
        max_score=float(b_cfg["B2_time_max"]),
        full_minutes=float(b_cfg["B2_full_score_minutes"]),
        half_life_minutes=float(b_cfg["B2_half_life_minutes"]),
    )
    qual_denom = float(b_cfg.get("quality_cap_denominator", 55.0))
    c_max = float(sc_cfg.get("weights", {}).get("C_redteam_security", 25.0))
    security_integrity_factor = min(1.0, max(0.0, c_total / max(1e-6, c_max))) ** 2
    b2_quality_cap = (
        float(b_cfg["B2_time_max"])
        * min(1.0, (a_total + c_total) / max(1e-6, qual_denom))
        * security_integrity_factor
    )
    b2_final = round(min(b2_unbounded, b2_quality_cap) * conservation_factor, 2)

    b_total = round(b1_score + b2_final, 2)
    total_obj = round(a_total + b_total + c_total, 2)

    return {
        "A_performance": a_total,
        "A_detail": {
            "A1_batch_search12": a1_final,
            "A2_concurrency10": a2_final,
            "A3_resource8": a3_final,
            "raw_before_b1_cap": round(a1_raw + a2_raw + a3_raw, 2),
            "speedup_ratio": round(speedup_a1, 2),
            "concurrent_rps_ratio": round(rps_ratio, 2),
            "concurrent_read_p95_ms": round(conc_p95_ms, 2),
            "concurrent_read_p99_ms": round(conc_p99_ms, 2),
            "cross_tenant_block_ratio": round(cross_block_ratio, 2),
            "global_lock_penalized": global_lock_penalized,
            "sql_reduction_ratio": round(q_red, 4),
            "mem_reduction_ratio": round(m_red, 4),
            "resident_heap_mb": round(resident_heap_mb, 3),
        },
        "B_conservation_efficiency": b_total,
        "B_detail": {
            "B1_conservation5": b1_score,
            "B2_time10": b2_final,
            "B2_raw_unbounded": round(b2_unbounded, 2),
            "B2_quality_cap": round(b2_quality_cap, 2),
            "b1_accuracy": round(b1_acc, 6),
            "b1_passed": b1_passed,
            "b1_total": b1_total,
            "conservation_factor": round(conservation_factor, 6),
            "endToEndMinutes": round(e2e_min, 2),
        },
        "C_redteam_security": c_total,
        "C_detail": {
            "C1_access_cache9": c1_final,
            "C2_toctou_replay8": c2_final,
            "C3_anti_dos8": c3_final,
            "subchecks": redteam_report.get("details", {}),
        },
        "total_objective_70": total_obj,
    }
