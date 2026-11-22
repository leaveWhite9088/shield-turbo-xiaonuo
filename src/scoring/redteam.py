# -*- coding: utf-8 -*-
"""C1 / C2 / C3 实战深水区红队攻击引擎（15 大复合攻击向量 + 四大性能—安全两难狙击）。

核心考核面：
- C1（9 分）：多参数 SQL 盲注、多编码/空字节路径穿越、诊断/异常密钥泄露、横向/纵向越权 + Chinese Wall 利益冲突隔离墙双路穿透（含共享缓存串味）、高并发“撤权/隔离 vs 慢读回填”缓存毒化竞态；
- C2（8 分）：30 路屏障齐射配额/单次令牌 TOCTOU + 负数/布尔伪装整数刷配额、12 路并发同 Nonce 齐射重放 Webhook、部分失败批次的数据库/内存滑动窗口双原子回滚验证、SQLite 64 位大整数溢出与 NaN/Infinity 类型混淆炸服；
- C3（8 分）：多变体 ReDoS（嵌套量词 + 重叠交替分支 + 多通配链）、1400 层原始 JSON 炸弹 + 深层/宽扇出规则树、SQLite LIMIT -1 慢查询放大、以及 100% 穿透查询结果缓存的随机合法查询洪泛 + 并发正常租户 P95 护盾。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import pathlib
import shutil
import tempfile
import threading
import time
from typing import Any

from workload import _headers, load_app_from_workspace


def _contains_any_secret(payload_obj: Any, secrets_list: list[str]) -> bool:
    raw = json.dumps(payload_obj, ensure_ascii=False) if not isinstance(payload_obj, str) else payload_obj
    raw_low = raw.lower()
    return any(s and s.lower() in raw_low for s in secrets_list)


def _build_deep_nested_rule(depth: int) -> dict[str, Any]:
    node: dict[str, Any] = {"field": "amount_cents", "op": "GT", "value": 100}
    for _ in range(depth):
        node = {"op": "AND", "children": [node]}
    return node


def _build_wide_bloated_rule() -> dict[str, Any]:
    leaves = [{"field": "amount_cents", "op": "GT", "value": i} for i in range(18)]
    groups = [{"op": "OR", "children": list(leaves)} for _ in range(12)]
    return {"op": "AND", "children": groups}


def run_redteam_suite(
    template_dir: pathlib.Path,
    candidate_dir: pathlib.Path,
    cfg: dict[str, Any],
) -> dict[str, Any]:
    c_cfg = cfg["scoring"]["C_detail"]
    c1_w = c_cfg["C1_subweights"]
    c2_w = c_cfg["C2_subweights"]
    c3_w = c_cfg["C3_subweights"]
    bomb_max_ms = float(c_cfg.get("C3_bomb_reject_max_ms", 45.0))
    normal_p95_max_ms = float(c_cfg.get("C3_normal_p95_max_ms", 60.0))
    cache_bust_avg_max_ms = float(c_cfg.get("C3_cache_bust_avg_max_ms", 18.0))
    toctou_threads = int(cfg["workload"].get("redteam_toctou_threads", 30))

    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="st_redteam_"))
    try:
        db_path = tmp_dir / "redteam.db"
        storage_dir = tmp_dir / "storage"

        tpl_db_mod, _ = load_app_from_workspace(template_dir)
        manifest = tpl_db_mod.seed_dataset(
            db_path,
            storage_dir,
            seed=int(cfg["workload"]["seed"]) + 404,
            num_tenants=2,
            docs_per_tenant=48,
            tx_per_tenant=80,
            audit_rows_per_tenant=60,
        )

        _, cand_server_mod = load_app_from_workspace(candidate_dir)
        gw = cand_server_mod.create_gateway(db_path, storage_dir)

        t_alpha = manifest["tenants"]["tenant_alpha"]
        t_bravo = manifest["tenants"]["tenant_bravo"]
        base_ts = int(manifest["base_ts"])
        canary = manifest["secret_canary"]
        forbidden_markers = [
            canary,
            "AEGIS-MASTER-KEY",
            t_alpha["webhook_secret"],
            t_bravo["webhook_secret"],
            "redteam.db",
        ]

        h_alpha_admin = _headers("tenant_alpha", t_alpha["users"]["admin"])
        h_alpha_analyst = _headers("tenant_alpha", t_alpha["users"]["analyst"])
        h_alpha_researcher = _headers("tenant_alpha", t_alpha["users"]["researcher"])
        h_alpha_viewer = _headers("tenant_alpha", t_alpha["users"]["viewer"])
        h_bravo_admin = _headers("tenant_bravo", t_bravo["users"]["admin"])

        details: dict[str, Any] = {}

        # ==================== 波次一：C1 边界防御、Chinese Wall 与并发缓存毒化 ====================

        # C1.1 多向量 SQL 注入
        st_legit, _, _ = gw.request(
            "GET",
            "/api/v1/docs/search?q=wire&tag_filter=tag_aml_1&sort_by=score&sort_dir=desc&limit=10",
            headers=h_alpha_admin,
        )
        sqli_1_st, _, sqli_1_body = gw.request(
            "GET",
            "/api/v1/docs/search?q=wire&tag_filter=tag_aml_1'+OR+'1'='1",
            headers=h_alpha_admin,
        )
        sqli_2_st, _, _ = gw.request(
            "GET",
            "/api/v1/docs/search?q=wire&sort_by=CASE+WHEN+(SELECT+COUNT(*)+FROM+system_secrets)>0+THEN+risk_weight+ELSE+updated_at+END",
            headers=h_alpha_admin,
        )
        sqli_3_st, _, _ = gw.request(
            "GET",
            "/api/v1/docs/search?q=wire&sort_by=risk_weight&sort_dir=DESC,updated_at",
            headers=h_alpha_admin,
        )
        sqli_4_st, _, sqli_4_body = gw.request(
            "GET",
            "/api/v1/audit/export-digest?severity=HIGH'+OR+'1'='1",
            headers=h_alpha_admin,
        )
        sqli_1_ok = (sqli_1_st == 400) or (sqli_1_st == 200 and int(sqli_1_body.get("returned_count", 99)) == 0)
        sqli_4_ok = (sqli_4_st == 400) or (sqli_4_st == 200 and int(sqli_4_body.get("total_records", 99)) == 0)
        sqli_ok = st_legit == 200 and sqli_1_ok and sqli_2_st == 400 and sqli_3_st == 400 and sqli_4_ok
        c1_sqli = float(c1_w["sql_injection"]) if sqli_ok else 0.0
        details["C1_sql_injection"] = {"passed": sqli_ok, "score": c1_sqli}

        # C1.2 多编码、反斜杠与空字节路径穿越
        st_snap_ok, _, _ = gw.request(
            "GET",
            "/api/v1/audit/snapshots?snapshot_name=2026-Q3.json",
            headers=h_alpha_admin,
        )
        traversal_payloads = [
            "....//....//system_vault.json",
            "%252e%252e%252f%252e%252e%252fsystem_vault.json",
            "..\\..\\system_vault.json",
            "....//tenant_bravo/snapshots/2026-Q3.json",
            "2026-Q3.json%00.bak",
            "../tenant_bravo/snapshots/2026-Q3.json",
        ]
        bravo_snap_tag = hashlib.sha256(b"snap:tenant_bravo:2026-Q3").hexdigest()[:16]
        trav_blocked = 0
        for tp in traversal_payloads:
            st_t, _, body_t = gw.request(
                "GET",
                f"/api/v1/audit/snapshots?snapshot_name={tp}",
                headers=h_alpha_admin,
            )
            if st_t in (400, 403, 404) and not _contains_any_secret(body_t, [*forbidden_markers, bravo_snap_tag]):
                trav_blocked += 1
        trav_ok = (st_snap_ok == 200) and (trav_blocked == len(traversal_payloads))
        c1_trav = float(c1_w["path_traversal"]) if trav_ok else 0.0
        details["C1_path_traversal"] = {
            "passed": trav_ok,
            "blocked": f"{trav_blocked}/{len(traversal_payloads)}",
            "score": c1_trav,
        }

        # C1.3 敏感密钥与错误回显预言机探测
        _, _, h_dbg = gw.request("GET", "/api/v1/health?debug=1")
        st_diag, _, diag_body = gw.request("GET", "/api/v1/internal/diagnostics", headers=h_alpha_analyst)
        _, _, err_b1 = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body=b"{bad_json")
        _, _, err_b2 = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body={"doc_ids": [12345, {"nested": 1}]})
        no_leak = (
            not _contains_any_secret(h_dbg, forbidden_markers)
            and st_diag != 200
            and not _contains_any_secret(diag_body, forbidden_markers)
            and not _contains_any_secret(err_b1, forbidden_markers)
            and not _contains_any_secret(err_b2, forbidden_markers)
        )
        c1_leak = float(c1_w["secret_leakage"]) if no_leak else 0.0
        details["C1_secret_leakage"] = {"passed": no_leak, "score": c1_leak}

        # C1.4 横向越权 + 纵向越权 + Chinese Wall 利益冲突隔离墙双路穿透（batch-get 直穿 + 同密级共享缓存串味）
        alpha_secret_doc = t_alpha["secret_doc_id"]
        alpha_secret_marker = t_alpha["secret_doc_marker"]
        wall_doc_id = t_alpha["wall_doc_id"]
        wall_doc_marker = t_alpha["wall_doc_marker"]

        # (a) 跨租户 batch-get
        _, _, idor_cross = gw.request("POST", "/api/v1/docs/batch-get", headers=h_bravo_admin, body={"doc_ids": [alpha_secret_doc]})
        cross_doc_ok = int(idor_cross.get("found", 0)) == 0 and not _contains_any_secret(idor_cross, [alpha_secret_marker])

        # (b) 低密级纵向 batch-get
        _, _, idor_vert = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body={"doc_ids": [alpha_secret_doc]})
        vert_doc_ok = int(idor_vert.get("found", 0)) == 0 and not _contains_any_secret(idor_vert, [alpha_secret_marker])

        # (c) Chinese Wall 路径一：ops_team 的 analyst 通过 batch-get 企图直接读取被 DENY 的并购文档 doc_alpha_0003
        _, _, wall_batch = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body={"doc_ids": [wall_doc_id]})
        wall_batch_ok = int(wall_batch.get("found", 0)) == 0 and not _contains_any_secret(wall_batch, [wall_doc_marker])

        # (d) Chinese Wall 路径二（两难陷阱！）：同为密级 2 的 researcher 先搜索预热缓存，analyst 立即用完全相同的参数搜索！
        _, _, res_wall_s = gw.request(
            "GET",
            "/api/v1/docs/search?q=merger+acquisition+advisory+embargo&deduplicate=1&limit=15",
            headers=h_alpha_researcher,
        )
        res_saw_wall = any(d.get("doc_id") == wall_doc_id for d in (res_wall_s.get("items") or []))
        _, _, ana_wall_s = gw.request(
            "GET",
            "/api/v1/docs/search?q=merger+acquisition+advisory+embargo&deduplicate=1&limit=15",
            headers=h_alpha_analyst,
        )
        ana_blocked_wall = (
            all(d.get("doc_id") != wall_doc_id for d in (ana_wall_s.get("items") or []))
            and not _contains_any_secret(ana_wall_s, [wall_doc_marker])
        )
        wall_cache_ok = res_saw_wall and ana_blocked_wall

        # (e) 跨租户单笔风控决策详情越权
        st_dec_idor, _, dec_idor_body = gw.request("GET", f"/api/v1/risk/decisions/{t_alpha['sample_decision_id']}", headers=h_bravo_admin)
        cross_dec_ok = st_dec_idor in (403, 404) and dec_idor_body.get("tenant_id") != "tenant_alpha"

        idor_all = [cross_doc_ok, vert_doc_ok, wall_batch_ok, wall_cache_ok, cross_dec_ok]
        c1_idor = float(c1_w["idor_and_chinese_wall"]) if all(idor_all) else (
            round(float(c1_w["idor_and_chinese_wall"]) * 0.35, 2) if sum(idor_all) >= 4 else 0.0
        )
        details["C1_idor_and_chinese_wall"] = {
            "passed": all(idor_all),
            "cross_tenant_doc": cross_doc_ok,
            "vertical_clearance_doc": vert_doc_ok,
            "chinese_wall_batch_get": wall_batch_ok,
            "chinese_wall_shared_cache": wall_cache_ok,
            "cross_tenant_decision": cross_dec_ok,
            "score": c1_idor,
        }

        # C1.5 动态 ACL 封禁失效 + 14 路并发“撤权 vs 慢读回填”缓存竞态轰炸
        def _has_doc(res_obj: dict[str, Any], target_did: str) -> bool:
            return any(d.get("doc_id") == target_did for d in (res_obj.get("items") or []) if isinstance(d, dict))

        # 先验证动态新增 doc-acl DENY 规则后的即时缓存失效
        gw.request(
            "POST",
            "/api/v1/admin/doc-acl",
            headers=h_alpha_admin,
            body={"doc_id": wall_doc_id, "subject_type": "USER", "subject_id": t_alpha["users"]["researcher"]["user_id"], "active": True},
        )
        _, _, res_after_acl = gw.request(
            "GET",
            "/api/v1/docs/search?q=merger+acquisition+advisory+embargo&deduplicate=1&limit=15",
            headers=h_alpha_researcher,
        )
        acl_live_revoke_ok = not _has_doc(res_after_acl, wall_doc_id)
        gw.request(
            "POST",
            "/api/v1/admin/doc-acl",
            headers=h_alpha_admin,
            body={"doc_id": wall_doc_id, "subject_type": "USER", "subject_id": t_alpha["users"]["researcher"]["user_id"], "active": False},
        )

        # 高并发读写竞态：给 viewer 临时授 COMPLIANCE_ADMIN，启动 10 个并发读线程密集搜索绝密词项，同时管理员线程撤回授权！
        viewer_uid = t_alpha["users"]["viewer"]["user_id"]
        gw.request(
            "POST",
            "/api/v1/admin/grants/revoke",
            headers=h_alpha_admin,
            body={"user_id": viewer_uid, "role": "COMPLIANCE_ADMIN", "action": "grant"},
        )
        _, _, vw_elev = gw.request(
            "GET",
            "/api/v1/docs/search?q=classified+board+resolution&deduplicate=1&limit=20",
            headers=h_alpha_viewer,
        )
        elev_worked = _has_doc(vw_elev, alpha_secret_doc)

        race_bar = threading.Barrier(12)

        def _concurrent_reader(r_i: int) -> None:
            race_bar.wait()
            for k in range(6):
                gw.request(
                    "GET",
                    f"/api/v1/docs/search?q=classified+board+resolution&deduplicate={k % 2}&limit=20",
                    headers=h_alpha_viewer,
                )

        def _concurrent_revoker() -> None:
            race_bar.wait()
            time.sleep(0.002)
            gw.request(
                "POST",
                "/api/v1/admin/grants/revoke",
                headers=h_alpha_admin,
                body={"user_id": viewer_uid, "role": "COMPLIANCE_ADMIN", "action": "revoke"},
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            futs = [pool.submit(_concurrent_reader, i) for i in range(11)] + [pool.submit(_concurrent_revoker)]
            for f in futs:
                f.result()

        # 竞态结束后连续探测 deduplicate=0/1，确认没有任何绝密文档被慢读线程回填驻留！
        stale_leaked = False
        for d_flag in ("0", "1"):
            _, _, post_race = gw.request(
                "GET",
                f"/api/v1/docs/search?q=classified+board+resolution&deduplicate={d_flag}&limit=20",
                headers=h_alpha_viewer,
            )
            if _has_doc(post_race, alpha_secret_doc) or any(
                int(d.get("clearance_level", 99)) > 1 for d in (post_race.get("items") or [])
            ):
                stale_leaked = True

        # 再验跨租户同名查询零串味
        _, _, bravo_check = gw.request(
            "GET",
            "/api/v1/docs/search?q=classified+board+resolution&deduplicate=1&limit=20",
            headers=h_bravo_admin,
        )
        no_cross_cache = not _contains_any_secret(bravo_check, [alpha_secret_marker, "doc_alpha_"])

        cache_poison_ok = bool(elev_worked and acl_live_revoke_ok and (not stale_leaked) and no_cross_cache)
        c1_cache = float(c1_w["concurrent_revoke_cache_poison"]) if cache_poison_ok else 0.0
        details["C1_concurrent_revoke_cache_poison"] = {
            "passed": cache_poison_ok,
            "acl_live_revoke_ok": acl_live_revoke_ok,
            "post_race_clean": not stale_leaked,
            "no_cross_cache": no_cross_cache,
            "score": c1_cache,
        }

        c1_total = round(c1_sqli + c1_trav + c1_leak + c1_idor + c1_cache, 2)

        # ==================== 波次二：C2 并发穿盾、并发 Nonce 重放、批次污染与数值溢出 ====================

        # C2.1 30 路并发抢配额 + 30 路并发核销令牌 + 负数/布尔伪装整数攻击
        st_neg_q, _, _ = gw.request(
            "POST",
            "/api/v1/quotas/consume",
            headers=h_alpha_admin,
            body={"quota_type": "SCARCE_REVIEW_SLOT", "amount": -5},
        )
        st_bool_q, _, _ = gw.request(
            "POST",
            "/api/v1/quotas/consume",
            headers=h_alpha_admin,
            body={"quota_type": "EMERGENCY_EXPORT", "amount": True},
        )
        bool_and_neg_rejected = (st_neg_q == 400) and (st_bool_q == 400)

        q_barrier = threading.Barrier(toctou_threads)

        def _race_quota(_i: int) -> tuple[int, dict[str, Any]]:
            q_barrier.wait()
            st_q, _, b_q = gw.request(
                "POST",
                "/api/v1/quotas/consume",
                headers=h_alpha_admin,
                body={"quota_type": "SCARCE_REVIEW_SLOT", "amount": 1},
            )
            return st_q, b_q

        with ThreadPoolExecutor(max_workers=toctou_threads) as pool:
            q_outcomes = list(pool.map(_race_quota, range(toctou_threads)))
        q_wins = sum(1 for st_q, b_q in q_outcomes if st_q == 200 and b_q.get("accepted") is True)
        q_rejs = sum(1 for st_q, b_q in q_outcomes if st_q == 409 and b_q.get("accepted") is False)
        _, _, q_rem_check = gw.request(
            "POST",
            "/api/v1/quotas/consume",
            headers=h_alpha_admin,
            body={"quota_type": "SCARCE_REVIEW_SLOT", "amount": 1},
        )

        t_barrier = threading.Barrier(toctou_threads)
        ov_tok = t_bravo["override_token"]

        def _race_token(idx: int) -> tuple[int, dict[str, Any]]:
            t_barrier.wait()
            st_t, _, b_t = gw.request(
                "POST",
                "/api/v1/risk/override-token/redeem",
                headers=h_bravo_admin,
                body={"token_id": ov_tok, "tx_ref": f"tx_r_{idx}"},
            )
            return st_t, b_t

        with ThreadPoolExecutor(max_workers=toctou_threads) as pool:
            t_outcomes = list(pool.map(_race_token, range(toctou_threads)))
        t_wins = sum(1 for st_t, b_t in t_outcomes if st_t == 200 and b_t.get("redeemed") is True)
        t_rejs = sum(1 for st_t, b_t in t_outcomes if st_t == 409 and b_t.get("redeemed") is False)

        quota_ok = q_wins == 1 and q_rejs == (toctou_threads - 1) and q_rem_check.get("remaining_quota") == 0
        token_ok = t_wins == 1 and t_rejs == (toctou_threads - 1)
        c2_toctou = 0.0
        if quota_ok:
            c2_toctou += 1.2
        if token_ok:
            c2_toctou += 1.2
        if bool_and_neg_rejected:
            c2_toctou += 0.6
        c2_toctou = round(min(float(c2_w["quota_and_token_30way_toctou"]), c2_toctou), 2)
        details["C2_quota_and_token_toctou"] = {
            "passed": quota_ok and token_ok and bool_and_neg_rejected,
            "quota_wins": q_wins,
            "token_wins": t_wins,
            "bool_amount_rejected": st_bool_q == 400,
            "score": c2_toctou,
        }

        # C2.2 Webhook 伪造、过期/超前时间窗与 12 路并发相同 Nonce 齐射重放
        wh_secret = t_alpha["webhook_secret"]
        wh_body = json.dumps({"settlement_ref": "stl_rt_race_01", "amount_cents": 500000}, separators=(",", ":"))
        now_sim = base_ts + 1000
        race_nonce = "nonce_rt_12way_race_001"
        race_sig = hmac.new(
            wh_secret.encode("utf-8"),
            f"tenant_alpha.{now_sim}.{race_nonce}.{wh_body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        wh_bar = threading.Barrier(12)

        def _race_webhook(_i: int) -> int:
            wh_bar.wait()
            st_w, _, _ = gw.request(
                "POST",
                f"/api/v1/webhooks/settlement-callback?_now_ts={now_sim + 3}",
                headers={
                    "X-Aegis-Tenant": "tenant_alpha",
                    "X-Aegis-Timestamp": str(now_sim),
                    "X-Aegis-Nonce": race_nonce,
                    "X-Aegis-Signature": f"sha256={race_sig}",
                },
                body=wh_body,
            )
            return st_w

        with ThreadPoolExecutor(max_workers=12) as pool:
            wh_statuses = list(pool.map(_race_webhook, range(12)))
        wh_200_cnt = sum(1 for s in wh_statuses if s == 200)
        wh_rej_cnt = sum(1 for s in wh_statuses if s in (400, 401, 403, 409))

        # 伪造签名 + 滞后过期 + 未来超前时间戳
        st_wh_forge, _, _ = gw.request(
            "POST",
            f"/api/v1/webhooks/settlement-callback?_now_ts={now_sim + 3}",
            headers={
                "X-Aegis-Tenant": "tenant_alpha",
                "X-Aegis-Timestamp": str(now_sim),
                "X-Aegis-Nonce": "nonce_forge_x",
                "X-Aegis-Signature": f"sha256={race_sig}",
            },
            body=json.dumps({"settlement_ref": "stl_forge", "amount_cents": 9999999}),
        )
        exp_ts = now_sim - 1800
        exp_sig = hmac.new(wh_secret.encode("utf-8"), f"tenant_alpha.{exp_ts}.nonce_exp_01.{wh_body}".encode("utf-8"), hashlib.sha256).hexdigest()
        st_wh_exp, _, _ = gw.request(
            "POST",
            f"/api/v1/webhooks/settlement-callback?_now_ts={now_sim}",
            headers={"X-Aegis-Tenant": "tenant_alpha", "X-Aegis-Timestamp": str(exp_ts), "X-Aegis-Nonce": "nonce_exp_01", "X-Aegis-Signature": f"sha256={exp_sig}"},
            body=wh_body,
        )
        fut_ts = now_sim + 1800
        fut_sig = hmac.new(wh_secret.encode("utf-8"), f"tenant_alpha.{fut_ts}.nonce_fut_01.{wh_body}".encode("utf-8"), hashlib.sha256).hexdigest()
        st_wh_fut, _, _ = gw.request(
            "POST",
            f"/api/v1/webhooks/settlement-callback?_now_ts={now_sim}",
            headers={"X-Aegis-Tenant": "tenant_alpha", "X-Aegis-Timestamp": str(fut_ts), "X-Aegis-Nonce": "nonce_fut_01", "X-Aegis-Signature": f"sha256={fut_sig}"},
            body=wh_body,
        )

        wh_all_ok = (
            wh_200_cnt == 1
            and wh_rej_cnt == 11
            and st_wh_forge in (400, 401, 403)
            and st_wh_exp in (400, 401, 403)
            and st_wh_fut in (400, 401, 403)
        )
        c2_wh = float(c2_w["webhook_replay_and_concurrent_nonce"]) if wh_all_ok else (
            0.8 if (st_wh_forge in (400, 401, 403) and st_wh_exp in (400, 401, 403) and wh_200_cnt >= 1) else 0.0
        )
        details["C2_webhook_replay_and_concurrent_nonce"] = {
            "passed": wh_all_ok,
            "concurrent_12way_200s": wh_200_cnt,
            "expired_blocked": st_wh_exp in (400, 401, 403),
            "future_blocked": st_wh_fut in (400, 401, 403),
            "score": c2_wh,
        }

        # C2.3 部分失败批次原子回滚（防半截落盘 & 防内存滑动窗口脏污染）+ INT64 溢出与 NaN/Infinity 类型混淆攻击
        clean_acct = "acct_alpha_clean_probe_999"
        # 构造第一批失败请求：前 6 笔合法，第 7 笔邮箱非法 -> 整批必须回滚！
        dirty_batch_1 = [
            {
                "tx_id": f"tx_dirty1_{k}",
                "account_id": clean_acct,
                "counterparty_id": f"cp_d_{k}",
                "amount_cents": 200000,
                "currency": "USD",
                "channel": "WIRE_INTL",
                "contact_email": f"ok{k}@alpha.org",
                "ts": base_ts + 3000 + k,
                "metadata": {},
            }
            for k in range(6)
        ] + [
            {
                "tx_id": "tx_dirty1_bad_tail",
                "account_id": clean_acct,
                "counterparty_id": "cp_d_9",
                "amount_cents": 200000,
                "currency": "USD",
                "channel": "WIRE_INTL",
                "contact_email": "invalid-email-without-domain",
                "ts": base_ts + 3010,
                "metadata": {},
            }
        ]
        st_db1, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_alpha_admin,
            body={"batch_id": "dirty_b1", "transactions": dirty_batch_1},
        )

        # 构造第二批失败请求：前 5 笔合法，第 6 笔与历史已存在的 sample_tx_id 发生主键冲突 -> 整批必须回滚且不得返回 500！
        dirty_batch_2 = [
            {
                "tx_id": f"tx_dirty2_{k}",
                "account_id": clean_acct,
                "counterparty_id": f"cp_d2_{k}",
                "amount_cents": 300000,
                "currency": "USD",
                "channel": "WIRE_INTL",
                "contact_email": f"ok2_{k}@alpha.org",
                "ts": base_ts + 3020 + k,
                "metadata": {},
            }
            for k in range(5)
        ] + [
            {
                "tx_id": t_alpha["sample_tx_id"],  # 故意撞库内已有主键！
                "account_id": clean_acct,
                "counterparty_id": "cp_dup",
                "amount_cents": 300000,
                "currency": "USD",
                "channel": "WIRE_INTL",
                "contact_email": "dup@alpha.org",
                "ts": base_ts + 3030,
                "metadata": {},
            }
        ]
        st_db2, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_alpha_admin,
            body={"batch_id": "dirty_b2", "transactions": dirty_batch_2},
        )

        # 发送 1 笔干净探测交易，若前两批有任何半截落盘或内存窗口污染，win_tx_count 将 > 1！
        st_probe, _, probe_body = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_alpha_admin,
            body={
                "batch_id": "clean_probe_b",
                "transactions": [
                    {
                        "tx_id": "tx_clean_probe_001",
                        "account_id": clean_acct,
                        "counterparty_id": "cp_clean",
                        "amount_cents": 50000,
                        "currency": "USD",
                        "channel": "ACH_BATCH",
                        "contact_email": "clean@alpha.org",
                        "ts": base_ts + 3050,
                        "metadata": {},
                    }
                ],
            },
        )
        probe_win_cnt = (
            probe_body.get("results", [{}])[0].get("window", {}).get("tx_count")
            if st_probe == 200 and probe_body.get("results")
            else -1
        )
        atomicity_ok = (st_db1 in (400, 422)) and (st_db2 in (400, 409)) and (probe_win_cnt == 1)

        # 超 64 位整数溢出炸服 + JSON NaN / Infinity 绕过 + 布尔金额伪装
        st_int64, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_alpha_admin,
            body={
                "batch_id": "overflow_b",
                "transactions": [
                    {
                        "tx_id": "tx_ovf_01",
                        "account_id": clean_acct,
                        "counterparty_id": "cp_ovf",
                        "amount_cents": 10 ** 26,
                        "currency": "USD",
                        "channel": "WIRE_INTL",
                        "contact_email": "ovf@alpha.org",
                        "ts": base_ts + 3060,
                        "metadata": {},
                    }
                ],
            },
        )
        st_bool_tx, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_alpha_admin,
            body={
                "batch_id": "bool_b",
                "transactions": [
                    {
                        "tx_id": "tx_bool_01",
                        "account_id": clean_acct,
                        "counterparty_id": "cp_bool",
                        "amount_cents": True,
                        "currency": "USD",
                        "channel": "WIRE_INTL",
                        "contact_email": "bool@alpha.org",
                        "ts": base_ts + 3065,
                        "metadata": {},
                    }
                ],
            },
        )
        raw_nan_json = b'{"rule_tree":{"field":"amount_cents","op":"GT","value":NaN},"sample_tx":{"amount_cents":100,"contact_email":"a@b.org"}}'
        raw_inf_json = b'{"rule_tree":{"field":"amount_cents","op":"LTE","value":Infinity},"sample_tx":{"amount_cents":100,"contact_email":"a@b.org"}}'
        st_nan, _, _ = gw.request("POST", "/api/v1/risk/simulate-rule", headers=h_alpha_analyst, body=raw_nan_json)
        st_inf, _, _ = gw.request("POST", "/api/v1/risk/simulate-rule", headers=h_alpha_analyst, body=raw_inf_json)

        type_overflow_ok = (
            st_int64 == 400
            and st_bool_tx == 400
            and st_nan == 400
            and st_inf == 400
        )

        c2_batch_type = 0.0
        if atomicity_ok:
            c2_batch_type += 1.5
        if type_overflow_ok:
            c2_batch_type += 1.0
        c2_batch_type = round(min(float(c2_w["batch_rollback_and_type_overflow"]), c2_batch_type), 2)
        details["C2_batch_rollback_and_type_overflow"] = {
            "passed": atomicity_ok and type_overflow_ok,
            "atomicity_ok": atomicity_ok,
            "probe_win_tx_count_expected_1": probe_win_cnt,
            "int64_overflow_status": st_int64,
            "bool_tx_status": st_bool_tx,
            "nan_inf_statuses": [st_nan, st_inf],
            "score": c2_batch_type,
        }

        c2_total = round(c2_toctou + c2_wh + c2_batch_type, 2)

        # ==================== 波次三：C3 多变体复杂度炸弹 + 100% 缓存穿透洪泛护盾 ====================
        redos_email = ("a" * 23) + "!"
        redos_variants = [
            ({"field": "channel", "op": "REGEX", "value": "^(a+)+$"}, {"channel": ("a" * 23) + "!", "amount_cents": 100, "contact_email": "ok@b.org"}),
            ({"field": "channel", "op": "REGEX", "value": "^(a|aa)+$"}, {"channel": ("a" * 24) + "!", "amount_cents": 100, "contact_email": "ok@b.org"}),
            ({"field": "channel", "op": "REGEX", "value": "^.*a.*a.*a.*a.*!$"}, {"channel": ("a" * 40) + "b", "amount_cents": 100, "contact_email": "ok@b.org"}),
        ]

        deep_raw_json = (b'{"a":' * 1400) + b"1" + (b"}" * 1400)
        deep_tree = _build_deep_nested_rule(1150)
        bloated_tree = _build_wide_bloated_rule()

        amp_urls = [
            "/api/v1/docs/search?q=wire&limit=-1&offset=0",
            "/api/v1/docs/search?q=wire&limit=0&offset=0",
            "/api/v1/docs/search?q=wire&limit=50000&offset=0",
            "/api/v1/docs/search?q=wire&limit=20&offset=999999",
            "/api/v1/docs/search?q=wire&limit=20&offset=-5",
            "/api/v1/docs/search?q=" + "+".join(f"term{i:02d}" for i in range(30)),
            "/api/v1/docs/search?q=%25%25%25%25%25%25%25%25wire",
        ]

        dos_barrier = threading.Barrier(7)
        redos_records: list[tuple[int, float]] = []
        deep_records: list[tuple[int, float]] = []
        amp_records: list[tuple[int, float]] = []
        bust_latencies_ms: list[float] = []
        bust_errors = 0
        normal_latencies_ms: list[float] = []
        normal_errors = 0
        rec_lock = threading.Lock()

        def _attacker_redos() -> None:
            dos_barrier.wait()
            local_r = []
            t0 = time.perf_counter()
            st_e, _, _ = gw.request(
                "POST",
                "/api/v1/risk/simulate-rule",
                headers=h_alpha_analyst,
                body={"rule_tree": {"field": "amount_cents", "op": "GT", "value": 10}, "sample_tx": {"amount_cents": 100, "contact_email": redos_email}},
            )
            local_r.append((st_e, (time.perf_counter() - t0) * 1000.0))
            for r_rule, r_tx in redos_variants:
                t1 = time.perf_counter()
                st_v, _, _ = gw.request("POST", "/api/v1/risk/simulate-rule", headers=h_alpha_analyst, body={"rule_tree": r_rule, "sample_tx": r_tx})
                local_r.append((st_v, (time.perf_counter() - t1) * 1000.0))
            with rec_lock:
                redos_records.extend(local_r)

        def _attacker_deep() -> None:
            dos_barrier.wait()
            local_d = []
            t0 = time.perf_counter()
            st_j, _, _ = gw.request("POST", "/api/v1/risk/simulate-rule", headers=h_alpha_analyst, body=deep_raw_json)
            local_d.append((st_j, (time.perf_counter() - t0) * 1000.0))

            sample_ok = {"amount_cents": 500, "contact_email": "valid@alpha.org"}
            for tree_payload in (deep_tree, bloated_tree):
                t1 = time.perf_counter()
                st_d, _, _ = gw.request("POST", "/api/v1/risk/simulate-rule", headers=h_alpha_analyst, body={"rule_tree": tree_payload, "sample_tx": sample_ok})
                local_d.append((st_d, (time.perf_counter() - t1) * 1000.0))
            with rec_lock:
                deep_records.extend(local_d)

        def _attacker_amp() -> None:
            dos_barrier.wait()
            local_a = []
            for u in amp_urls:
                t0 = time.perf_counter()
                st_a, _, _ = gw.request("GET", u, headers=h_alpha_analyst)
                local_a.append((st_a, (time.perf_counter() - t0) * 1000.0))
            with rec_lock:
                amp_records.extend(local_a)

        def _attacker_cache_buster() -> None:
            """发射 32 个互不重复的合法组合查询（100% 穿透查询结果缓存），检验底层检索是否真正完成复杂度降维！"""
            nonlocal bust_errors
            dos_barrier.wait()
            local_b = []
            local_err = 0
            vocab = ["wire", "settlement", "escrow", "sanctions", "vessel", "encryption", "liquidity", "masking"]
            for i in range(32):
                w1 = vocab[i % len(vocab)]
                w2 = vocab[(i * 3 + 1) % len(vocab)]
                unique_nonce_tok = f"uniqueterm{i:04d}"
                t0 = time.perf_counter()
                st_b, _, _ = gw.request(
                    "GET",
                    f"/api/v1/docs/search?q={w1}+{w2}+{unique_nonce_tok}&deduplicate=1&limit={5 + (i % 15)}&offset={i % 4}",
                    headers=h_alpha_admin,
                )
                local_b.append((time.perf_counter() - t0) * 1000.0)
                if st_b != 200:
                    local_err += 1
            with rec_lock:
                bust_latencies_ms.extend(local_b)
                bust_errors += local_err

        def _normal_tenant_user() -> None:
            nonlocal normal_errors
            dos_barrier.wait()
            local_lat = []
            local_err = 0
            for step in range(8):
                t0 = time.perf_counter()
                st_n, _, _ = gw.request(
                    "GET",
                    f"/api/v1/docs/search?q=settlement+clearing&deduplicate=1&limit=10&offset={step % 2}",
                    headers=h_bravo_admin,
                )
                local_lat.append((time.perf_counter() - t0) * 1000.0)
                if st_n != 200:
                    local_err += 1
                time.sleep(0.004)
            with rec_lock:
                normal_latencies_ms.extend(local_lat)
                normal_errors += local_err

        with ThreadPoolExecutor(max_workers=7) as pool:
            futs = [
                pool.submit(_attacker_redos),
                pool.submit(_attacker_deep),
                pool.submit(_attacker_amp),
                pool.submit(_attacker_cache_buster),
                pool.submit(_normal_tenant_user),
                pool.submit(_normal_tenant_user),
                pool.submit(_normal_tenant_user),
            ]
            for f in futs:
                f.result()

        redos_max_ms = max((dt for _, dt in redos_records), default=9999.0)
        redos_ok = bool(redos_records) and all(st in (400, 422) for st, _ in redos_records) and redos_max_ms <= bomb_max_ms
        c3_redos = float(c3_w["redos_multi_variant_bomb"]) if redos_ok else 0.0

        deep_max_ms = max((dt for _, dt in deep_records), default=9999.0)
        deep_ok = bool(deep_records) and all(st in (400, 422) for st, _ in deep_records) and deep_max_ms <= bomb_max_ms
        c3_deep = float(c3_w["deep_json_and_ast_bomb"]) if deep_ok else 0.0

        amp_rejected = sum(1 for st, dt in amp_records if st in (400, 422) and dt <= bomb_max_ms)
        amp_ok = amp_rejected == len(amp_urls)
        c3_amp = float(c3_w["query_amplification_bomb"]) if amp_ok else (
            round(float(c3_w["query_amplification_bomb"]) * 0.5, 2) if amp_rejected >= 5 else 0.0
        )

        bust_avg_ms = (sum(bust_latencies_ms) / len(bust_latencies_ms)) if bust_latencies_ms else 9999.0
        norm_sorted = sorted(normal_latencies_ms) if normal_latencies_ms else [9999.0]
        norm_p95_ms = norm_sorted[min(len(norm_sorted) - 1, int(len(norm_sorted) * 0.95))]

        bust_fast = (bust_errors == 0) and (bust_avg_ms <= cache_bust_avg_max_ms)
        shield_ok = (normal_errors == 0) and (norm_p95_ms <= normal_p95_max_ms)
        c3_shield = 0.0
        if bust_fast:
            c3_shield += 1.3
        if shield_ok:
            c3_shield += 1.2
        c3_shield = round(min(float(c3_w["cache_busting_flood_and_p95_shield"]), c3_shield), 2)

        details["C3_anti_dos_and_cache_bust"] = {
            "redos_passed": redos_ok,
            "redos_max_ms": round(redos_max_ms, 2),
            "deep_passed": deep_ok,
            "deep_max_ms": round(deep_max_ms, 2),
            "amp_passed": amp_ok,
            "amp_rejected": f"{amp_rejected}/{len(amp_urls)}",
            "cache_bust_avg_ms": round(bust_avg_ms, 2),
            "cache_bust_passed": bust_fast,
            "normal_p95_ms_under_attack": round(norm_p95_ms, 2),
            "shield_passed": shield_ok,
            "score": round(c3_redos + c3_deep + c3_amp + c3_shield, 2),
        }

        c3_total = round(c3_redos + c3_deep + c3_amp + c3_shield, 2)

        return {
            "C1_score": c1_total,
            "C2_score": c2_total,
            "C3_score": c3_total,
            "C_total": round(c1_total + c2_total + c3_total, 2),
            "details": details,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
