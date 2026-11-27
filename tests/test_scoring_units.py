#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""计分公式（xiaonuo-v3.0）、常驻堆内存预算、防篡改双指纹缓存、盲评重评与隔离审计单元测试。"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "scoring"))
sys.path.insert(0, str(ROOT / "tools"))

import isolation_audit  # noqa: E402
import metrics  # noqa: E402
from model_identity import canonical_model_id, matches_batch_run, sanitize_run_name  # noqa: E402
import objective_cache  # noqa: E402
import review_log  # noqa: E402


class TestScoringAndIsolationUnits(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = metrics.load_benchmark_config(ROOT)

    def test_model_identity_normalization(self) -> None:
        self.assertEqual(canonical_model_id("deepseek-v4.1-flash-s1"), "deepseek-v4.1-flash")
        self.assertEqual(canonical_model_id("deepseek-r1"), "deepseek-r1")
        self.assertEqual(canonical_model_id("gemini-4-carbon（Max）-run2"), "gemini-4-carbon（max）")
        self.assertTrue(matches_batch_run("gemini-4-carbon", "gemini-4-carbon-s1"))
        with self.assertRaises(ValueError):
            sanitize_run_name("../evil")

    def test_piecewise_speedup_heap_budget_and_conservation_cap(self) -> None:
        self.assertEqual(metrics.score_piecewise_log_speedup(1.0, 13.0, 260.0, knee_ratio=95.0, knee_score=8.5), 0.0)
        self.assertAlmostEqual(
            metrics.score_piecewise_log_speedup(95.0, 13.0, 260.0, knee_ratio=95.0, knee_score=8.5),
            8.5,
            places=2,
        )
        self.assertEqual(metrics.score_piecewise_log_speedup(280.0, 13.0, 260.0, knee_ratio=95.0, knee_score=8.5), 13.0)

        # 常驻堆内存预算：<= 4.5MB 满分 2.8，>= 18.0MB 得 0 分
        self.assertEqual(metrics.score_heap_budget(2.2, 2.8, 4.5, 18.0), 2.8)
        self.assertAlmostEqual(metrics.score_heap_budget(11.25, 2.8, 4.5, 18.0), 1.4, places=2)
        self.assertEqual(metrics.score_heap_budget(20.0, 2.8, 4.5, 18.0), 0.0)

        # 验证 B1 < 100% 时的 B1_acc ** 5 毁灭性封顶（0.5^5 = 0.03125）
        sc_damaged = metrics.compute_objective_scores(
            b1_report={"total_checks": 100, "passed_checks": 50},
            perf_report={
                "a1_speedup_ratio": 300.0,
                "a2_rps_ratio": 200.0,
                "a2_concurrent_read_p95_ms": 2.0,
                "a2_concurrent_read_p99_ms": 4.0,
                "a2_probe_read_p80_ms": 2.0,
                "a2_cross_tenant_block_ratio": 1.1,
                "a2_error_rate": 0.0,
                "a3_sql_reduction_ratio": 0.995,
                "a3_mem_reduction_ratio": 0.95,
                "a3_resident_heap_mb": 1.8,
            },
            redteam_report={"C1_score": 10.0, "C2_score": 9.0, "C3_score": 9.0},
            e2e_seconds=180.0,
            cfg=self.cfg,
        )
        self.assertAlmostEqual(sc_damaged["A_performance"], round(32.0 * (0.5 ** 5), 2), places=1)
        self.assertLess(sc_damaged["B_detail"]["B2_time5"], 0.3)

    def test_b2_wall_clock_decay_and_white_paper_cap(self) -> None:
        self.assertAlmostEqual(metrics.score_b2_wall_clock(7.5, 5.0, 8.0, 22.0), 5.0)
        self.assertAlmostEqual(metrics.score_b2_wall_clock(30.0, 5.0, 8.0, 22.0), 2.5)

        sc_lazy = metrics.compute_objective_scores(
            b1_report={"total_checks": 100, "passed_checks": 100},
            perf_report={
                "a1_speedup_ratio": 1.0,
                "a2_rps_ratio": 1.0,
                "a2_concurrent_read_p95_ms": 500.0,
                "a2_concurrent_read_p99_ms": 600.0,
                "a2_probe_read_p80_ms": 120.0,
                "a2_cross_tenant_block_ratio": 8.0,
                "a2_error_rate": 0.0,
                "a3_sql_reduction_ratio": 0.0,
                "a3_mem_reduction_ratio": 0.0,
                "a3_resident_heap_mb": 0.5,
            },
            redteam_report={"C1_score": 0.0, "C2_score": 1.0, "C3_score": 0.0},
            e2e_seconds=5.0,
            cfg=self.cfg,
        )
        self.assertLess(sc_lazy["B_detail"]["B2_time5"], 0.3)
        self.assertLess(sc_lazy["total_objective_70"], 7.0)

    def test_review_log_append_and_realtime_rescore(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="st_ut_rev_"))
        try:
            log_file = tmp / "reviews.jsonl"
            review_log.append_review(
                log_file,
                {
                    "judge_id": "j1",
                    "judge_model": "judge-alpha",
                    "pack_id": "aabbccddeeff",
                    "case_id": "case-01",
                    "D1": 4.6,
                    "D2": 4.4,
                    "D3": 3.8,
                    "evidence": "initial review evidence",
                    "note": "mediocre lock",
                },
            )
            _, prior = review_log.append_review(
                log_file,
                {
                    "judge_id": "j1",
                    "judge_model": "judge-alpha",
                    "pack_id": "aabbccddeeff",
                    "case_id": "case-01",
                    "D1": 9.2,
                    "D2": 8.8,
                    "D3": 7.2,
                    "evidence": "updated verified evidence",
                    "note": "level 8.5 cap check",
                },
                reject_duplicate=False,
                return_prior_count=True,
            )
            self.assertEqual(prior, 1)
            all_revs = review_log.read_reviews(log_file)
            deduped, sup_cnt = review_log.dedupe_latest(all_revs)
            self.assertEqual(sup_cnt, 1)
            agg = review_log.aggregate_reviews(deduped, mode="mean")
            self.assertEqual(len(agg), 1)
            self.assertAlmostEqual(agg[0]["D"], 25.2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_objective_cache_tamper_and_blind_isolation(self) -> None:
        raw = {
            "A_performance": 30.5,
            "A_detail": {},
            "B_conservation_efficiency": 9.5,
            "B_detail": {},
            "C_redteam_security": 28.0,
            "C_detail": {},
            "total_objective_70": 68.0,
        }
        sealed = objective_cache.build_objective_record(
            raw,
            run_summary={"speedupRatio": 190.0},
            code_sha256="abc123def456",
            t0_source="process",
            b2_reliable=True,
            scoring_hash="shash_003",
            deliverables_hash="dhash_003",
        )
        ok, reason = objective_cache.verify_objective_cache(
            sealed,
            expected_code_sha256="abc123def456",
            scoring_hash="shash_003",
            deliverables_hash="dhash_003",
        )
        self.assertTrue(ok, reason)

        tampered = dict(sealed)
        tampered["A_performance"] = 32.0
        ok2, reason2 = objective_cache.verify_objective_cache(
            tampered,
            expected_code_sha256="abc123def456",
            scoring_hash="shash_003",
            deliverables_hash="dhash_003",
        )
        self.assertFalse(ok2)
        self.assertEqual(reason2, "tampered")

        contaminated = dict(sealed)
        contaminated["D"] = 28.0
        ok3, reason3 = objective_cache.verify_objective_cache(
            contaminated,
            expected_code_sha256="abc123def456",
            scoring_hash="shash_003",
            deliverables_hash="dhash_003",
        )
        self.assertFalse(ok3)
        self.assertEqual(reason3, "contains_blind_fields")

    def test_isolation_audit_catches_leaks_and_draft_leftovers(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="st_ut_iso_"))
        try:
            runs_d = tmp / "runs"
            blind_d = tmp / "blind"
            maps_d = tmp / "blind-maps"
            draft_d = tmp / "draft"
            draft_d.mkdir(parents=True)
            (draft_d / "temp_note.txt").write_text("leftover", encoding="utf-8")

            pdir = blind_d / "112233445566"
            (pdir / "case-01").mkdir(parents=True)
            (pdir / "OFFICIAL_LEVEL5_BASELINE.md").write_text("ref", encoding="utf-8")
            (pdir / "RUBRIC.md").write_text("rubric", encoding="utf-8")
            (pdir / "case-01" / "code_changes.diff").write_text("# leak model secret-gpt-x here", encoding="utf-8")
            maps_d.mkdir(parents=True)
            (maps_d / "secret-gpt-x.112233445566.blind-map.json").write_text(
                json.dumps({"model": "secret-gpt-x", "model_id": "secret-gpt-x", "pack_id": "112233445566", "cases": {"case-01": {"run": "secret-gpt-x"}}}),
                encoding="utf-8",
            )

            rep = isolation_audit.audit_isolation(
                runs_dir=runs_d,
                blind_dir=blind_d,
                blind_maps_dir=maps_d,
                draft_dir=draft_d,
            )
            self.assertFalse(rep["ok"])
            joined = "\n".join(rep["issues"])
            self.assertIn("draft/", joined)
            self.assertIn("secret-gpt-x", joined)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
