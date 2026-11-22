# -*- coding: utf-8 -*-
"""B1 高密度业务零失真对账器 + A1/A2/A3 大规模性能压测与 SQL/内存探针。

设计要点：
1. B1 零失真对账：在独立数据库副本上对参考原版与被测沙盒回放完全一致的 60+ 步多租户复杂读写操作序列，
   逐项比对状态码、风控评分、滑动窗口三项聚合值、合规检索排序序列、近似簇大小、审计滚动 SHA-256 与配额余量。
2. A1/A2/A3 实测压测：同机对比初始模板与被测代码的物理耗时、16 路并发混合读写 RPS 与 P95 延迟、
   跨租户全局大锁阻塞放大比、SQLite trace_callback 真实 SQL 执行条数及 tracemalloc 导出峰值内存。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import importlib
import json
import pathlib
import random
import shutil
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from typing import Any


class SQLCounterHook:
    """基于 sqlite3.Connection.set_trace_callback 的精确 SQL 执行计数器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.enabled = False
        self.count = 0
        self._orig_connect = sqlite3.connect

    def _trace(self, _statement: str) -> None:
        if self.enabled:
            with self._lock:
                self.count += 1

    def _wrapped_connect(self, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        conn = self._orig_connect(*args, **kwargs)
        conn.set_trace_callback(self._trace)
        return conn

    def install(self) -> None:
        sqlite3.connect = self._wrapped_connect  # type: ignore[assignment]

    def uninstall(self) -> None:
        sqlite3.connect = self._orig_connect  # type: ignore[assignment]

    def reset_and_start(self) -> None:
        with self._lock:
            self.count = 0
            self.enabled = True

    def stop(self) -> int:
        with self._lock:
            self.enabled = False
            return self.count


def load_app_from_workspace(workspace_dir: pathlib.Path) -> tuple[Any, Any]:
    """从指定沙盒目录清理旧模块缓存并动态加载 (db_mod, server_mod)。"""
    ws_str = str(workspace_dir.resolve())
    for mod_name in list(sys.modules.keys()):
        if mod_name == "aegis_app" or mod_name.startswith("aegis_app."):
            sys.modules.pop(mod_name, None)
    if ws_str in sys.path:
        sys.path.remove(ws_str)
    sys.path.insert(0, ws_str)
    importlib.invalidate_caches()
    db_mod = importlib.import_module("aegis_app.db")
    server_mod = importlib.import_module("aegis_app.server")
    return db_mod, server_mod


def _headers(tenant_id: str, user_info: dict[str, str]) -> dict[str, str]:
    return {
        "X-Aegis-Tenant": tenant_id,
        "X-Aegis-User": user_info["user_id"],
        "X-Aegis-Token": user_info["token"],
    }


def _collect_b1_outputs(workspace_dir: pathlib.Path, cfg: dict[str, Any]) -> list[tuple[str, Any]]:
    """在指定实现上运行 60+ 项高密度多租户正常业务操作序列，收集确定性输出快照。"""
    wl = cfg["workload"]
    seed = int(wl["seed"])
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="st_b1_"))
    try:
        db_path = tmp_dir / "b1.db"
        storage_dir = tmp_dir / "storage"
        db_mod, server_mod = load_app_from_workspace(workspace_dir)
        manifest = db_mod.seed_dataset(
            db_path,
            storage_dir,
            seed=seed,
            num_tenants=int(wl.get("b1_tenants", 3)),
            docs_per_tenant=int(wl.get("b1_docs_per_tenant", 45)),
            tx_per_tenant=int(wl.get("b1_tx_per_tenant", 160)),
            audit_rows_per_tenant=120,
        )
        gw = server_mod.create_gateway(db_path, storage_dir)
        base_ts = int(manifest["base_ts"])
        records: list[tuple[str, Any]] = []

        # 1. 健康探针
        st, _, h_body = gw.request("GET", "/api/v1/health")
        records.append(("health", (st, h_body.get("status"))))

        # 2. 多租户多角色多组合合规检索对账（24 组：覆盖词频打分、去重开启/关闭、分类/标签过滤、不同排序方向、分页偏移）
        queries = [
            ("wire transfer travel rule verification", "", "", "1", "score", "desc", 15, 0),
            ("wire transfer travel rule verification", "", "", "0", "score", "desc", 20, 0),
            ("sanctions blocked entity vessel screening", "SANCTIONS", "", "1", "risk_weight", "desc", 10, 0),
            ("encryption confidentiality resilience", "PRIVACY", "", "1", "updated_at", "asc", 12, 2),
            ("liquid assets stress scenario", "", "tag_liquidity_3", "1", "score", "desc", 10, 0),
            ("primary account masking cryptography", "CARD", "", "0", "risk_weight", "asc", 8, 1),
            ("settlement clearing nostro vostro", "", "", "1", "score", "desc", 12, 0),
            ("", "AML", "", "1", "updated_at", "desc", 10, 0),
        ]
        tenant_ids = sorted(manifest["tenants"].keys())
        role_cycle = ["admin", "auditor", "analyst", "viewer"]

        for q_idx, (q_str, cat, tag, dedup, s_by, s_dir, lim, off) in enumerate(queries):
            for t_i, tid in enumerate(tenant_ids):
                t_info = manifest["tenants"][tid]
                r_key = role_cycle[(q_idx + t_i) % len(role_cycle)]
                hdr = _headers(tid, t_info["users"][r_key])
                url = (
                    f"/api/v1/docs/search?q={q_str.replace(' ', '+')}"
                    f"&category={cat}&tag_filter={tag}&deduplicate={dedup}"
                    f"&sort_by={s_by}&sort_dir={s_dir}&limit={lim}&offset={off}"
                )
                st, _, res = gw.request("GET", url, headers=hdr)
                norm_items = [
                    (
                        it["doc_id"],
                        it["score"],
                        it["cluster_size"],
                        it["citation_count"],
                        it["clearance_level"],
                    )
                    for it in (res.get("items") or [])
                ]
                records.append(
                    (
                        f"search_{tid}_{r_key}_{q_idx}",
                        (st, res.get("total_matched"), res.get("returned_count"), norm_items),
                    )
                )

        # 3. 批量文档授权读取（3 租户管理员合法读取）
        for tid in tenant_ids:
            t_info = manifest["tenants"][tid]
            slug = t_info["slug"]
            doc_ids = [f"doc_{slug}_0001", f"doc_{slug}_0002", f"doc_{slug}_0005"]
            st, _, res = gw.request(
                "POST",
                "/api/v1/docs/batch-get",
                headers=_headers(tid, t_info["users"]["admin"]),
                body={"doc_ids": doc_ids},
            )
            got = [(d["doc_id"], d["risk_weight"], d["clearance_level"]) for d in (res.get("items") or [])]
            records.append((f"batch_get_{tid}", (st, res.get("found"), got)))

        # 4. 文档隔离 -> 立即检索验证不可见 -> 恢复 -> 立即检索验证恢复（3 租户）
        for tid in tenant_ids:
            t_info = manifest["tenants"][tid]
            slug = t_info["slug"]
            target_doc = f"doc_{slug}_0002"
            h_adm = _headers(tid, t_info["users"]["admin"])
            st_q1, _, _ = gw.request(
                "POST",
                "/api/v1/docs/quarantine",
                headers=h_adm,
                body={"doc_id": target_doc, "quarantined": True},
            )
            _, _, s_mid = gw.request(
                "GET",
                "/api/v1/docs/search?q=suspicious+activity+structuring&deduplicate=0&limit=50",
                headers=h_adm,
            )
            in_mid = any(d["doc_id"] == target_doc for d in (s_mid.get("items") or []))
            st_q2, _, _ = gw.request(
                "POST",
                "/api/v1/docs/quarantine",
                headers=h_adm,
                body={"doc_id": target_doc, "quarantined": False},
            )
            _, _, s_after = gw.request(
                "GET",
                "/api/v1/docs/search?q=suspicious+activity+structuring&deduplicate=0&limit=50",
                headers=h_adm,
            )
            in_after = any(d["doc_id"] == target_doc for d in (s_after.get("items") or []))
            records.append((f"quarantine_cycle_{tid}", (st_q1, in_mid, st_q2, in_after)))

        # 5. 策略更新 + 高密度同批次先序依赖滑动窗口风控评估（含临界 86400 秒边界）
        rng = random.Random(seed + 99)
        channels = ["WIRE_INTL", "CRYPTO_BRIDGE", "CARD_CNP", "ACH_BATCH", "POS_CHIP"]
        for t_i, tid in enumerate(tenant_ids):
            t_info = manifest["tenants"][tid]
            slug = t_info["slug"]
            h_adm = _headers(tid, t_info["users"]["admin"])
            h_aud = _headers(tid, t_info["users"]["auditor"])

            if t_i == 0:
                st_pol, _, pol_res = gw.request(
                    "PUT",
                    "/api/v1/policies",
                    headers=h_adm,
                    body={"velocity_tx_limit": 4, "review_threshold": 42},
                )
                records.append(("policy_update_alpha", (st_pol, pol_res.get("policy_version"), pol_res.get("review_threshold"))))

            batch_txs = []
            for k in range(18):
                acct = f"acct_{slug}_{(k % 3) + 1:03d}"
                batch_txs.append(
                    {
                        "tx_id": f"tx_b1_{slug}_{k + 1:03d}",
                        "account_id": acct,
                        "counterparty_id": f"cp_b1_{(k % 6) + 1:02d}",
                        "amount_cents": 85000 + rng.randint(1, 15) * 45000,
                        "currency": "USD",
                        "channel": channels[(k + t_i) % len(channels)],
                        "contact_email": f"ops.notify{k}@{slug}-bank.com",
                        "ts": base_ts + 60 + k * 45,
                        "metadata": {"region": "EU" if k % 2 == 0 else "US", "tier": k % 3},
                    }
                )
            st_ev, _, ev_res = gw.request(
                "POST",
                "/api/v1/risk/evaluate-batch",
                headers=h_aud,
                body={"batch_id": f"b1_batch_{slug}", "transactions": batch_txs},
            )
            ev_digest = [
                (
                    r["tx_id"],
                    r["risk_score"],
                    r["decision"],
                    r["window"]["tx_count"],
                    r["window"]["amount_cents"],
                    r["window"]["unique_counterparties"],
                    tuple(r["reasons"]),
                )
                for r in (ev_res.get("results") or [])
            ]
            records.append((f"eval_batch_{tid}", (st_ev, ev_res.get("decision_counts"), ev_digest)))

            # 查询单笔风控决策详情
            sample_dec = f"dec_tx_b1_{slug}_015"
            st_d, _, d_res = gw.request("GET", f"/api/v1/risk/decisions/{sample_dec}", headers=h_aud)
            records.append(
                (
                    f"decision_detail_{tid}",
                    (st_d, d_res.get("risk_score"), d_res.get("decision"), d_res.get("window")),
                )
            )

        # 6. 自定义布尔规则树试算（4 组复杂合法逻辑组合）
        t0 = manifest["tenants"][tenant_ids[0]]
        h0 = _headers(tenant_ids[0], t0["users"]["analyst"])
        rule_cases = [
            (
                {
                    "op": "AND",
                    "bonus_score": 10,
                    "reason": "R_ROOT",
                    "children": [
                        {"field": "amount_cents", "op": "GTE", "value": 100000},
                        {
                            "op": "OR",
                            "bonus_score": 5,
                            "reason": "R_SUB",
                            "children": [
                                {"field": "channel", "op": "IN", "value": ["WIRE_INTL", "CRYPTO_BRIDGE"]},
                                {"field": "metadata.country", "op": "EQ", "value": "CH"},
                            ],
                        },
                        {
                            "op": "NOT",
                            "children": [{"field": "currency", "op": "EQ", "value": "JPY"}],
                        },
                    ],
                },
                {"amount_cents": 150000, "channel": "WIRE_INTL", "currency": "USD", "contact_email": "a.b@c-d.org", "metadata": {"country": "SG"}},
            ),
            (
                {"field": "channel", "op": "CONTAINS", "value": "CRYPTO", "bonus_score": 19, "reason": "CONTAINS_CRYPTO"},
                {"amount_cents": 5000, "channel": "CRYPTO_BRIDGE", "contact_email": "x@y.io"},
            ),
        ]
        for rc_i, (rtree, stx) in enumerate(rule_cases):
            st_r, _, r_out = gw.request(
                "POST",
                "/api/v1/risk/simulate-rule",
                headers=h0,
                body={"rule_tree": rtree, "sample_tx": stx},
            )
            records.append((f"sim_rule_{rc_i}", (st_r, r_out.get("matched"), r_out.get("bonus_score"), tuple(r_out.get("reasons") or []))))

        # 7. 配额扣减、单次令牌核销、合法 Webhook 签名回调、审计摘要滚动哈希与归档快照读取
        for tid in tenant_ids:
            t_info = manifest["tenants"][tid]
            h_adm = _headers(tid, t_info["users"]["admin"])

            st_q, _, q_out = gw.request(
                "POST",
                "/api/v1/quotas/consume",
                headers=h_adm,
                body={"quota_type": "EMERGENCY_EXPORT", "amount": 3},
            )
            records.append((f"quota_ok_{tid}", (st_q, q_out.get("accepted"), q_out.get("remaining_quota"))))

            st_q_fail, _, q_fail_out = gw.request(
                "POST",
                "/api/v1/quotas/consume",
                headers=h_adm,
                body={"quota_type": "EMERGENCY_EXPORT", "amount": 4},
            )
            records.append((f"quota_exhaust_{tid}", (st_q_fail, q_fail_out.get("accepted"), q_fail_out.get("remaining_quota"))))

            st_ov, _, ov_out = gw.request(
                "POST",
                "/api/v1/risk/override-token/redeem",
                headers=h_adm,
                body={"token_id": t_info["override_token"], "tx_ref": "tx_ref_01"},
            )
            records.append((f"override_ok_{tid}", (st_ov, ov_out.get("redeemed"))))

            wh_body = json.dumps({"settlement_ref": f"stl_{tid}_01", "amount_cents": 256000}, separators=(",", ":"))
            wh_ts = base_ts + 500
            wh_nonce = f"nonce_b1_{tid}_001"
            sig = hmac.new(
                t_info["webhook_secret"].encode("utf-8"),
                f"{tid}.{wh_ts}.{wh_nonce}.{wh_body}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            st_wh, _, wh_out = gw.request(
                "POST",
                f"/api/v1/webhooks/settlement-callback?_now_ts={wh_ts + 15}",
                headers={
                    "X-Aegis-Tenant": tid,
                    "X-Aegis-Timestamp": str(wh_ts),
                    "X-Aegis-Nonce": wh_nonce,
                    "X-Aegis-Signature": f"sha256={sig}",
                },
                body=wh_body,
            )
            records.append((f"webhook_ok_{tid}", (st_wh, wh_out.get("acknowledged"), wh_out.get("amount_cents"))))

            st_au, _, au_out = gw.request(
                "GET",
                f"/api/v1/audit/export-digest?start_ts={base_ts - 90000}&end_ts={base_ts}&sample_limit=6",
                headers=h_adm,
            )
            records.append(
                (
                    f"audit_digest_{tid}",
                    (
                        st_au,
                        au_out.get("total_records"),
                        au_out.get("total_amount_cents"),
                        au_out.get("severity_breakdown"),
                        au_out.get("event_breakdown"),
                        au_out.get("rolling_sha256"),
                        len(au_out.get("samples") or []),
                    ),
                )
            )

            st_sn, _, sn_out = gw.request(
                "GET",
                "/api/v1/audit/snapshots?snapshot_name=2026-Q4.json",
                headers=h_adm,
            )
            records.append((f"snapshot_{tid}", (st_sn, sn_out.get("data"))))

        return records
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_b1_conservation_check(
    template_dir: pathlib.Path,
    candidate_dir: pathlib.Path,
    cfg: dict[str, Any],
) -> dict[str, Any]:
    """对比初始原版参考输出与选手沙盒输出，返回精确对账统计。"""
    expected = _collect_b1_outputs(template_dir, cfg)
    try:
        actual = _collect_b1_outputs(candidate_dir, cfg)
    except Exception as exc:
        return {
            "total_checks": len(expected),
            "passed_checks": 0,
            "accuracy": 0.0,
            "mismatches": [{"check": "FATAL_EXECUTION_ERROR", "error": str(exc)}],
        }

    actual_map = dict(actual)
    passed = 0
    mismatches = []
    for check_id, exp_val in expected:
        act_val = actual_map.get(check_id, "__MISSING__")
        if act_val == exp_val:
            passed += 1
        else:
            if len(mismatches) < 10:
                mismatches.append(
                    {
                        "check": check_id,
                        "expected_preview": str(exp_val)[:180],
                        "actual_preview": str(act_val)[:180],
                    }
                )

    total = len(expected)
    return {
        "total_checks": total,
        "passed_checks": passed,
        "accuracy": passed / max(1, total),
        "mismatches": mismatches,
    }


def _measure_single_workspace_perf(
    workspace_dir: pathlib.Path,
    template_dir: pathlib.Path,
    cfg: dict[str, Any],
) -> dict[str, Any]:
    """在标准高压数据集上测量单个工作区的 A1 耗时、A2 并发混合吞吐/尾延迟/跨租户锁退化比、A3 SQL数与内存峰值。"""
    wl = cfg["workload"]
    seed = int(wl["seed"]) + 777
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="st_perf_"))
    sql_hook = SQLCounterHook()
    sql_hook.install()

    try:
        db_path = tmp_dir / "perf.db"
        storage_dir = tmp_dir / "storage"

        # 始终使用官方模板的 seed_dataset 初始化完全一致的原始基准数据库文件（不含优化索引），
        # 再交由被测实现的 create_gateway 挂载，真实检验选手对存量库的索引与 WAL 加固效果！
        tpl_db_mod, _ = load_app_from_workspace(template_dir)
        manifest = tpl_db_mod.seed_dataset(
            db_path,
            storage_dir,
            seed=seed,
            num_tenants=int(wl["perf_tenants"]),
            docs_per_tenant=int(wl["perf_docs_per_tenant"]),
            tx_per_tenant=int(wl["perf_tx_per_tenant"]),
            audit_rows_per_tenant=int(wl["perf_audit_rows_per_tenant"]),
        )

        _, cand_server_mod = load_app_from_workspace(workspace_dir)
        gw = cand_server_mod.create_gateway(db_path, storage_dir)

        tenant_ids = sorted(manifest["tenants"].keys())
        base_ts = int(manifest["base_ts"])
        rng = random.Random(seed + 13)

        # 预热一次轻查询（让懒加载倒排索引在正式压测统计里共同体现多轮高频收益）
        t0_info = manifest["tenants"][tenant_ids[0]]
        gw.request("GET", "/api/v1/health")

        # ---------- A1 + A3(SQL)：复杂多关键词去重检索 + 批量实时风控窗口评估 ----------
        search_phrases = [
            "wire transfer beneficiary verification thresholds",
            "suspicious activity correspondent banking structuring",
            "blocked entity vessel embargo screening",
            "encryption confidentiality resilience integrity",
            "liquid assets thirty day outflows stress",
            "primary account masking cryptography rotation",
            "settlement clearing reconciliation escrow",
            "asset freeze designated indirect control",
            "outbound personal financial security contract",
        ]
        num_queries = int(wl["perf_search_queries"])
        batch_size = int(wl["perf_batch_eval_size"])
        channels = ["WIRE_INTL", "CRYPTO_BRIDGE", "CARD_CNP", "ACH_BATCH", "POS_CHIP"]

        batches_by_tenant: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        for b_idx, tid in enumerate(tenant_ids[:2]):
            t_info = manifest["tenants"][tid]
            slug = t_info["slug"]
            tx_list = []
            for k in range(batch_size):
                acct = f"acct_{slug}_{(k % 24) + 1:03d}"
                tx_list.append(
                    {
                        "tx_id": f"tx_perf_a1_{slug}_{b_idx}_{k:04d}",
                        "account_id": acct,
                        "counterparty_id": f"cp_p_{(k % 30) + 1:02d}",
                        "amount_cents": 50000 + ((k * 37 + b_idx * 19) % 40) * 25000,
                        "currency": "USD",
                        "channel": channels[k % len(channels)],
                        "contact_email": f"perf.acct{k % 50}@{slug}-fin.org",
                        "ts": base_ts + 100 + k * 10,
                        "metadata": {"region": "APAC", "seq": k},
                    }
                )
            batches_by_tenant.append(
                (tid, _headers(tid, t_info["users"]["auditor"]), {"batch_id": f"perf_b_{slug}", "transactions": tx_list})
            )

        sql_hook.reset_and_start()
        t_a1_start = time.perf_counter()

        for q_i in range(num_queries):
            tid = tenant_ids[q_i % len(tenant_ids)]
            t_info = manifest["tenants"][tid]
            role = "admin" if (q_i % 3 == 0) else ("auditor" if q_i % 3 == 1 else "analyst")
            phrase = search_phrases[q_i % len(search_phrases)]
            dedup = "1" if (q_i % 5 != 0) else "0"
            sort_f = "score" if (q_i % 2 == 0) else "risk_weight"
            st, _, _ = gw.request(
                "GET",
                f"/api/v1/docs/search?q={phrase.replace(' ', '+')}&deduplicate={dedup}&sort_by={sort_f}&limit=20",
                headers=_headers(tid, t_info["users"][role]),
            )
            if st != 200:
                raise RuntimeError(f"A1 search failed with status {st}")

        for _tid, hdr, b_body in batches_by_tenant:
            st, _, _ = gw.request("POST", "/api/v1/risk/evaluate-batch", headers=hdr, body=b_body)
            if st != 200:
                raise RuntimeError(f"A1 batch evaluate failed with status {st}")

        a1_elapsed_sec = max(1e-5, time.perf_counter() - t_a1_start)
        sql_executed_count = sql_hook.stop()

        # ---------- A3(Memory)：大规模审计报表流式摘要内存峰值探针 ----------
        # 先预热一次后再开启 tracemalloc 测量纯导出过程新增峰值分配字节
        t_mem_info = manifest["tenants"][tenant_ids[0]]
        h_mem = _headers(tenant_ids[0], t_mem_info["users"]["auditor"])
        tracemalloc.start()
        tracemalloc.reset_peak()
        for tid in tenant_ids:
            ti = manifest["tenants"][tid]
            st, _, _ = gw.request(
                "GET",
                "/api/v1/audit/export-digest?sample_limit=10",
                headers=_headers(tid, ti["users"]["auditor"]),
            )
            if st != 200:
                raise RuntimeError(f"A3 audit export failed with status {st}")
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_kb = peak_bytes / 1024.0

        # ---------- A2：16 路高并发读写混合吞吐、读 P95 尾延迟与跨租户全局大锁检测 ----------
        # 步骤 A2-1：测量无竞争下的跨租户轻量读基线延迟
        baseline_read_samples_ms: list[float] = []
        for i in range(16):
            tid = tenant_ids[i % 2]
            ti = manifest["tenants"][tid]
            phrase = search_phrases[i % len(search_phrases)].replace(" ", "+")
            t0_r = time.perf_counter()
            gw.request("GET", f"/api/v1/docs/search?q={phrase}&deduplicate=1&limit=15", headers=_headers(tid, ti["users"]["auditor"]))
            baseline_read_samples_ms.append((time.perf_counter() - t0_r) * 1000.0)
        solo_read_median_ms = max(0.15, statistics.median(baseline_read_samples_ms))

        # 步骤 A2-2：16 路并发混合读写（12 个读操作 + 4 个跨租户批次写事务混合）
        n_threads = int(wl["perf_concurrent_threads"])
        ops_per_thread = int(wl["perf_concurrent_ops_per_thread"])
        read_latencies_ms: list[float] = []
        lat_lock = threading.Lock()
        errors_cnt = 0
        start_barrier = threading.Barrier(n_threads)

        def _worker(w_id: int) -> int:
            nonlocal errors_cnt
            local_reads: list[float] = []
            local_ops = 0
            start_barrier.wait()
            for step in range(ops_per_thread):
                # 后 1/4 线程周期性向独立租户发起小批次写入，前 3/4 线程高频跨租户检索与查详情
                if w_id >= (n_threads * 3 // 4) and (step % 3 == 0):
                    w_tid = tenant_ids[(w_id + step) % len(tenant_ids)]
                    w_info = manifest["tenants"][w_tid]
                    w_slug = w_info["slug"]
                    mini_batch = [
                        {
                            "tx_id": f"tx_conc_{w_id}_{step}_{m}",
                            "account_id": f"acct_{w_slug}_{(m % 12) + 1:03d}",
                            "counterparty_id": f"cp_c_{(m % 10) + 1:02d}",
                            "amount_cents": 40000 + m * 10000,
                            "currency": "USD",
                            "channel": "CARD_CNP",
                            "contact_email": f"conc.{w_id}.{m}@{w_slug}.org",
                            "ts": base_ts + 2000 + step * 20 + m,
                            "metadata": {"w": w_id},
                        }
                        for m in range(8)
                    ]
                    st_w, _, _ = gw.request(
                        "POST",
                        "/api/v1/risk/evaluate-batch",
                        headers=_headers(w_tid, w_info["users"]["auditor"]),
                        body={"batch_id": f"cb_{w_id}_{step}", "transactions": mini_batch},
                    )
                    if st_w != 200:
                        with lat_lock:
                            errors_cnt += 1
                else:
                    r_tid = tenant_ids[(w_id + step) % 2]
                    r_info = manifest["tenants"][r_tid]
                    if step % 4 == 3:
                        t_s = time.perf_counter()
                        st_r, _, _ = gw.request(
                            "GET",
                            f"/api/v1/risk/decisions/{r_info['sample_decision_id']}",
                            headers=_headers(r_tid, r_info["users"]["analyst"]),
                        )
                        dt_ms = (time.perf_counter() - t_s) * 1000.0
                    else:
                        ph = search_phrases[(w_id * 3 + step) % len(search_phrases)].replace(" ", "+")
                        t_s = time.perf_counter()
                        st_r, _, _ = gw.request(
                            "GET",
                            f"/api/v1/docs/search?q={ph}&deduplicate=1&limit=15",
                            headers=_headers(r_tid, r_info["users"]["auditor"]),
                        )
                        dt_ms = (time.perf_counter() - t_s) * 1000.0
                    local_reads.append(dt_ms)
                    if st_r != 200:
                        with lat_lock:
                            errors_cnt += 1
                local_ops += 1

            with lat_lock:
                read_latencies_ms.extend(local_reads)
            return local_ops

        t_conc_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futs = [pool.submit(_worker, idx) for idx in range(n_threads)]
            total_ops = sum(f.result() for f in futs)
        conc_elapsed = max(1e-5, time.perf_counter() - t_conc_start)

        concurrent_rps = total_ops / conc_elapsed
        sorted_reads = sorted(read_latencies_ms) if read_latencies_ms else [999.0]
        p95_idx = min(len(sorted_reads) - 1, max(0, int(len(sorted_reads) * 0.95)))
        conc_read_p95_ms = sorted_reads[p95_idx]

        # 步骤 A2-3：专门检测“跨租户全局大锁串行退化”探针
        # 在 tenant_delta 上并发发起 3 个较重的写入批次（每个 85 笔），同时在 tenant_alpha 上测 12 次轻量读延迟中位数
        heavy_tid = tenant_ids[-1]
        heavy_info = manifest["tenants"][heavy_tid]
        heavy_slug = heavy_info["slug"]
        probe_bar = threading.Barrier(6)
        probe_read_ms: list[float] = []

        def _heavy_writer(hw_idx: int) -> None:
            txs = [
                {
                    "tx_id": f"tx_hlock_{hw_idx}_{m:03d}",
                    "account_id": f"acct_{heavy_slug}_{(m % 15) + 1:03d}",
                    "counterparty_id": f"cp_hl_{(m % 12) + 1:02d}",
                    "amount_cents": 60000 + m * 5000,
                    "currency": "USD",
                    "channel": "WIRE_INTL",
                    "contact_email": f"hl.{hw_idx}.{m}@{heavy_slug}.org",
                    "ts": base_ts + 9000 + hw_idx * 100 + m,
                    "metadata": {"probe": hw_idx},
                }
                for m in range(40)
            ]
            probe_bar.wait()
            gw.request(
                "POST",
                "/api/v1/risk/evaluate-batch",
                headers=_headers(heavy_tid, heavy_info["users"]["admin"]),
                body={"batch_id": f"hl_batch_{hw_idx}", "transactions": txs},
            )

        def _light_reader(lr_idx: int) -> None:
            light_tid = tenant_ids[0]
            light_info = manifest["tenants"][light_tid]
            hdr = _headers(light_tid, light_info["users"]["auditor"])
            probe_bar.wait()
            samples = []
            for s_i in range(4):
                ph = search_phrases[(lr_idx + s_i) % len(search_phrases)].replace(" ", "+")
                ts0 = time.perf_counter()
                gw.request("GET", f"/api/v1/docs/search?q={ph}&deduplicate=1&limit=10", headers=hdr)
                samples.append((time.perf_counter() - ts0) * 1000.0)
            with lat_lock:
                probe_read_ms.extend(samples)

        with ThreadPoolExecutor(max_workers=6) as p_pool:
            p_futs = [p_pool.submit(_heavy_writer, i) for i in range(3)] + [
                p_pool.submit(_light_reader, j) for j in range(3)
            ]
            for pf in p_futs:
                pf.result()

        probe_p80_ms = sorted(probe_read_ms)[int(len(probe_read_ms) * 0.80)] if probe_read_ms else solo_read_median_ms
        # 跨租户写干扰下的读延迟膨胀倍数（无全局锁时应接近 1.0~1.8；有全局锁时会被 3 个 90 笔大批次堵到数倍乃至十几倍）
        cross_block_ratio = probe_p80_ms / max(0.5, solo_read_median_ms)

        return {
            "a1_elapsed_sec": a1_elapsed_sec,
            "sql_count": sql_executed_count,
            "peak_kb": peak_kb,
            "concurrent_rps": concurrent_rps,
            "concurrent_read_p95_ms": conc_read_p95_ms,
            "solo_read_median_ms": solo_read_median_ms,
            "probe_read_p80_ms": probe_p80_ms,
            "cross_tenant_block_ratio": cross_block_ratio,
            "error_rate": errors_cnt / max(1, total_ops),
        }
    finally:
        sql_hook.uninstall()
        shutil.rmtree(tmp_dir, ignore_errors=True)


_CACHED_BASE_PERF: dict[str, dict[str, Any]] = {}


def run_performance_benchmark(
    template_dir: pathlib.Path,
    candidate_dir: pathlib.Path,
    cfg: dict[str, Any],
) -> dict[str, Any]:
    """同机测量初始未优化模板与被测沙盒的性能对比指标。"""
    cache_key = hashlib.sha256(json.dumps(cfg["workload"], sort_keys=True).encode("utf-8")).hexdigest()[:16]
    cal_file = pathlib.Path(tempfile.gettempdir()) / f"st_base_cal_{cache_key}.json"
    base_m = _CACHED_BASE_PERF.get(cache_key)
    if base_m is None and cal_file.is_file():
        try:
            saved = json.loads(cal_file.read_text(encoding="utf-8"))
            if time.time() - float(saved.get("ts", 0)) < 900.0:
                base_m = saved["metrics"]
                _CACHED_BASE_PERF[cache_key] = base_m
        except Exception:
            base_m = None

    if base_m is None:
        base_m = _measure_single_workspace_perf(template_dir, template_dir, cfg)
        _CACHED_BASE_PERF[cache_key] = base_m
        try:
            cal_file.write_text(json.dumps({"ts": time.time(), "metrics": base_m}), encoding="utf-8")
        except Exception:
            pass

    if candidate_dir.resolve() == template_dir.resolve():
        cand_m = _measure_single_workspace_perf(candidate_dir, template_dir, cfg)
    else:
        cand_m = _measure_single_workspace_perf(candidate_dir, template_dir, cfg)

    a1_speedup = base_m["a1_elapsed_sec"] / max(1e-6, cand_m["a1_elapsed_sec"])
    a2_rps_ratio = cand_m["concurrent_rps"] / max(1e-3, base_m["concurrent_rps"])
    sql_red = max(0.0, 1.0 - (cand_m["sql_count"] / max(1, base_m["sql_count"])))
    mem_red = max(0.0, 1.0 - (cand_m["peak_kb"] / max(1.0, base_m["peak_kb"])))

    return {
        "baseline_metrics": base_m,
        "candidate_metrics": cand_m,
        "a1_speedup_ratio": a1_speedup,
        "a2_rps_ratio": a2_rps_ratio,
        "a2_concurrent_read_p95_ms": cand_m["concurrent_read_p95_ms"],
        "a2_probe_read_p80_ms": cand_m["probe_read_p80_ms"],
        "a2_cross_tenant_block_ratio": cand_m["cross_tenant_block_ratio"],
        "a2_error_rate": cand_m["error_rate"],
        "a3_sql_reduction_ratio": sql_red,
        "a3_mem_reduction_ratio": mem_red,
    }
