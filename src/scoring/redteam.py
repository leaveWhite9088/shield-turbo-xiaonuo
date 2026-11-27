# -*- coding: utf-8 -*-
"""C1 / C2 / C3 地狱级实战红队攻击引擎（xiaonuo-v3.0 二十路跨链路复合攻击向量 · 满分 28 分）。

核心考核面（xiaonuo-v3.0）：
- C1（10.0 分）：
  1) 一阶多参数 SQL 盲注 + 双通道跨模块二阶持久化 SQL 注入（report-template -> render-report 及 docs/upsert citations -> docs/search）；
  2) 双重 URL 编码、混合编码、嵌套折叠、反斜杠与空字节路径穿越；
  3) 诊断/异常密钥预言机 + Python .format() 属性/下标反射窃密与超宽格式说明符（:0>200000）内存放大；
  4) 横向/纵向越权 + 三级利益冲突隔离墙（batch-get 直穿 + 同密级共享缓存串味）+ 跨租户内部文档引用存在性侧信道预言机；
  5) 1~2 跳借调窗口越界绕过 + 上游一级借调自然到期（零写操作）下游缓存即时降级 + 第 3 跳阻断 + 源头撤权级联失效 + 14 路并发撤权回填竞态；
- C2（9.0 分）：
  1) 32 路屏障齐射配额/单次令牌 TOCTOU + 负数/布尔伪装整数刷配额；
  2) 28 路跨模块交叉写竞争（20 路双向 quotas/transfer + 8 路含高危 REJECT 交易 evaluate-batch 抢扣 REALTIME_ALERT_POOL）死锁探测与全局配额总额守恒；
  3) 16 路并发同 Nonce 齐射重放 Webhook + 伪造签名 + 滞后/超前时间窗 + 回调载荷布尔类型混淆；
  4) 半批失败四位一体强原子回滚（数据库记录 + 滑窗统计 + 三跳制裁传染图 + REALTIME_ALERT_POOL 告警配额零泄漏）+ 超 64 位整数溢出与 NaN/Infinity 拦截；
- C3（9.0 分）：
  1) 多变体 ReDoS（嵌套量词 + 重叠分支 + 多通配链 + 花括号超大有界量词 + 反向引用）+ 借调委托有向环路递归/死循环炸弹；
  2) 1400 层原始 JSON 栈溢出炸弹 + 1150 层深层规则树 + 宽扇出膨胀树 + 超长 IN 列表 + 2000 条文档引用洪水炸弹；
  3) SQLite LIMIT -1 慢查询放大、超界分页、超多词项与纯通配符洪水；
  4) 穿插实时文档 Upsert 与动态 doc-acl 隔离墙切换的 36 路 100% 缓存穿透随机查询洪泛 + 并发正常租户 P95 护盾。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, wait as futures_wait
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
    normal_p95_max_ms = float(c_cfg.get("C3_normal_p95_max_ms", 50.0))
    cache_bust_avg_max_ms = float(c_cfg.get("C3_cache_bust_avg_max_ms", 15.0))
    toctou_threads = int(cfg["workload"].get("redteam_toctou_threads", 32))
    transfer_threads = int(cfg["workload"].get("redteam_transfer_threads", 20))
    batch_race_threads = int(cfg["workload"].get("redteam_batch_race_threads", 8))

    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="st_redteam_v3_"))
    try:
        db_path = tmp_dir / "redteam.db"
        storage_dir = tmp_dir / "storage"

        tpl_db_mod, _ = load_app_from_workspace(template_dir)
        manifest = tpl_db_mod.seed_dataset(
            db_path,
            storage_dir,
            seed=int(cfg["workload"]["seed"]) + 404,
            num_tenants=2,
            docs_per_tenant=50,
            tx_per_tenant=80,
            audit_rows_per_tenant=60,
        )

        _, cand_server_mod = load_app_from_workspace(candidate_dir)
        gw = cand_server_mod.create_gateway(db_path, storage_dir)
        recover_seq = 0

        def _recover_gateway_after_deadlock() -> Any:
            nonlocal db_path, gw, recover_seq
            recover_seq += 1
            new_db = tmp_dir / f"redteam_rec_{recover_seq}.db"
            shutil.copy2(db_path, new_db)
            for ext in ("-wal", "-shm"):
                src_ext = pathlib.Path(str(db_path) + ext)
                if src_ext.is_file():
                    shutil.copy2(src_ext, pathlib.Path(str(new_db) + ext))
            db_path = new_db
            gw = cand_server_mod.create_gateway(db_path, storage_dir)
            return gw

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
        h_alpha_auditor = _headers("tenant_alpha", t_alpha["users"]["auditor"])
        h_alpha_analyst = _headers("tenant_alpha", t_alpha["users"]["analyst"])
        h_alpha_specialist = _headers("tenant_alpha", t_alpha["users"]["specialist"])
        h_alpha_researcher = _headers("tenant_alpha", t_alpha["users"]["researcher"])
        h_alpha_viewer = _headers("tenant_alpha", t_alpha["users"]["viewer"])
        h_bravo_admin = _headers("tenant_bravo", t_bravo["users"]["admin"])
        h_bravo_analyst = _headers("tenant_bravo", t_bravo["users"]["analyst"])
        h_bravo_specialist = _headers("tenant_bravo", t_bravo["users"]["specialist"])

        details: dict[str, Any] = {}

        # ==================== 波次一：C1 双通道二阶注入、反射放大、跨租户侧信道与二级委托竞态 ====================

        # C1.1 一阶多参数盲注 + 双通道二阶持久化 SQL 注入（报表模板 + 文档内部引用）
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
        first_order_sqli_ok = (
            st_legit == 200
            and ((sqli_1_st == 400) or (sqli_1_st == 200 and int(sqli_1_body.get("returned_count", 99)) == 0))
            and sqli_2_st == 400
            and sqli_3_st == 400
            and ((sqli_4_st == 400) or (sqli_4_st == 200 and int(sqli_4_body.get("total_records", 99)) == 0))
        )

        # 二阶通道 1：report-template -> render-report
        tpl_sqli_payloads = [
            "RISK_EVAL' OR tenant_id='tenant_bravo' OR '1'='1",
            "NONE' UNION SELECT 999999,'tenant_alpha','x',secret_value,'CRITICAL',999,secret_key,1760000000,'{}' FROM system_secrets--",
        ]
        tpl_sqli_blocked = 0
        for s_idx, s_flt in enumerate(tpl_sqli_payloads):
            tpl_name = f"tpl_sqli_2nd_{s_idx}"
            st_put, _, _ = gw.request(
                "PUT",
                "/api/v1/audit/report-template",
                headers=h_alpha_auditor,
                body={
                    "template_id": tpl_name,
                    "title_format": "[{tenant_id}] Report ({total_records})",
                    "extra_event_filter": s_flt,
                    "sample_limit": 20,
                },
            )
            if st_put == 400:
                tpl_sqli_blocked += 1
            elif st_put == 200:
                st_ren, _, ren_body = gw.request(
                    "GET",
                    f"/api/v1/audit/render-report?template_id={tpl_name}",
                    headers=h_alpha_auditor,
                )
                ren_total = int((ren_body.get("digest") or {}).get("total_records", 999))
                if (
                    (st_ren == 400 or (st_ren == 200 and ren_total == 0))
                    and not _contains_any_secret(ren_body, forbidden_markers)
                ):
                    tpl_sqli_blocked += 1
        second_order_tpl_ok = tpl_sqli_blocked == len(tpl_sqli_payloads)

        # 二阶通道 2：docs/upsert 埋入恶意 doc_ 引用 -> docs/search 触发引用解析 SQL 注入
        cite_sqli_payloads = [
            "doc_missing_999' OR status='ACTIVE' --",
            "doc_missing_998' UNION SELECT 'ACTIVE', 0 FROM system_secrets WHERE secret_key LIKE 'VAULT%' --",
        ]
        cite_sqli_blocked = 0
        for c_idx, c_ref in enumerate(cite_sqli_payloads):
            probe_did = f"doc_alpha_csqli_{c_idx}"
            uniq_kw = f"citationsqliprobe{c_idx}zz"
            st_cu, _, _ = gw.request(
                "POST",
                f"/api/v1/docs/upsert?_now_ts={base_ts + 12 + c_idx}",
                headers=h_alpha_auditor,
                body={
                    "doc_id": probe_did,
                    "category": "AML",
                    "regulation_code": "FATF-R16",
                    "clearance_level": 2,
                    "risk_weight": 15,
                    "custom_tag": "tag_aml_1",
                    "title": f"Citation SQLi Probe {c_idx}",
                    "body": f"compliance verification {uniq_kw} check.",
                    "citations": [c_ref],
                },
            )
            if st_cu == 400:
                cite_sqli_blocked += 1
            elif st_cu == 200:
                st_cs, _, cs_body = gw.request(
                    "GET",
                    f"/api/v1/docs/search?q={uniq_kw}&deduplicate=0&_now_ts={base_ts + 15}",
                    headers=h_alpha_auditor,
                )
                matched_doc = next(
                    (it for it in (cs_body.get("items") or []) if it.get("doc_id") == probe_did),
                    None,
                )
                gw.request(
                    "POST",
                    f"/api/v1/docs/retire?_now_ts={base_ts + 16}",
                    headers=h_alpha_admin,
                    body={"doc_id": probe_did},
                )
                if (
                    st_cs == 200
                    and matched_doc is not None
                    and int(matched_doc.get("citation_count", 99)) == 0
                    and not _contains_any_secret(cs_body, forbidden_markers)
                ):
                    cite_sqli_blocked += 1
        second_order_cite_ok = cite_sqli_blocked == len(cite_sqli_payloads)

        c1_sqli_max = float(c1_w["sql_injection_first_and_second_order"])
        if first_order_sqli_ok and second_order_tpl_ok and second_order_cite_ok:
            c1_sqli = c1_sqli_max
        elif first_order_sqli_ok and (second_order_tpl_ok or second_order_cite_ok):
            c1_sqli = round(c1_sqli_max * 0.55, 2)
        elif first_order_sqli_ok:
            c1_sqli = round(c1_sqli_max * 0.30, 2)
        else:
            c1_sqli = 0.0
        details["C1_sql_injection_first_and_second_order"] = {
            "passed": first_order_sqli_ok and second_order_tpl_ok and second_order_cite_ok,
            "first_order_ok": first_order_sqli_ok,
            "second_order_template_ok": second_order_tpl_ok,
            "second_order_citation_ok": second_order_cite_ok,
            "score": c1_sqli,
        }

        # C1.2 多编码、混合编码、反斜杠与空字节路径穿越
        st_snap_ok, _, _ = gw.request(
            "GET",
            "/api/v1/audit/snapshots?snapshot_name=2026-Q3.json",
            headers=h_alpha_admin,
        )
        traversal_payloads = [
            "....//....//system_vault.json",
            "%252e%252e%252f%252e%252e%252fsystem_vault.json",
            "..%2f..%2fsystem_vault.json",
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

        # C1.3 诊断/异常回显脱敏 + Python .format() 属性/下标反射与超宽格式说明符放大攻击
        _, _, h_dbg = gw.request("GET", "/api/v1/health?debug=1")
        st_diag, _, diag_body = gw.request("GET", "/api/v1/internal/diagnostics", headers=h_alpha_analyst)
        _, _, err_b1 = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body=b"{bad_json")
        _, _, err_b2 = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body={"doc_ids": [12345, {"nested": 1}]})
        diag_and_err_clean = (
            not _contains_any_secret(h_dbg, forbidden_markers)
            and st_diag != 200
            and not _contains_any_secret(diag_body, forbidden_markers)
            and not _contains_any_secret(err_b1, forbidden_markers)
            and not _contains_any_secret(err_b2, forbidden_markers)
        )

        fmt_attack_payloads = [
            "Leak={env.master_pepper}",
            "Dict={env.__dict__}",
            "Cls={tenant_id.__class__.__mro__}",
            "Pos={0}",
            "Wide={tenant_id:0>200000}",
        ]
        fmt_blocked = 0
        for f_idx, f_title in enumerate(fmt_attack_payloads):
            ftpl = f"tpl_fmt_leak_{f_idx}"
            st_fp, _, _ = gw.request(
                "PUT",
                "/api/v1/audit/report-template",
                headers=h_alpha_auditor,
                body={
                    "template_id": ftpl,
                    "title_format": f_title,
                    "extra_event_filter": "",
                    "sample_limit": 2,
                },
            )
            if st_fp == 400:
                fmt_blocked += 1
            elif st_fp == 200:
                st_fr, _, fr_body = gw.request(
                    "GET",
                    f"/api/v1/audit/render-report?template_id={ftpl}",
                    headers=h_alpha_auditor,
                )
                r_title = str(fr_body.get("rendered_title") or "")
                if (
                    st_fr == 400
                    or (
                        len(r_title) <= 400
                        and not _contains_any_secret(fr_body, [*forbidden_markers, "RuntimeEnvSettings", "object", "type", "master_pepper"])
                        and "AEGIS-MASTER-KEY" not in r_title
                    )
                ):
                    fmt_blocked += 1
        format_reflection_clean = fmt_blocked == len(fmt_attack_payloads)

        c1_leak = 0.0
        if diag_and_err_clean and format_reflection_clean:
            c1_leak = float(c1_w["secret_and_format_reflection_leak"])
        elif diag_and_err_clean:
            c1_leak = round(float(c1_w["secret_and_format_reflection_leak"]) * 0.35, 2)
        details["C1_secret_and_format_reflection_leak"] = {
            "passed": diag_and_err_clean and format_reflection_clean,
            "diag_and_err_clean": diag_and_err_clean,
            "format_reflection_and_width_clean": format_reflection_clean,
            "score": c1_leak,
        }

        # C1.4 横向/纵向越权 + 三级利益冲突隔离墙 + 跨租户内部文档引用存在性侧信道预言机
        alpha_secret_doc = t_alpha["secret_doc_id"]
        alpha_secret_marker = t_alpha["secret_doc_marker"]
        wall_doc_id = t_alpha["wall_doc_id"]
        wall_doc_marker = t_alpha["wall_doc_marker"]

        _, _, idor_cross = gw.request("POST", "/api/v1/docs/batch-get", headers=h_bravo_admin, body={"doc_ids": [alpha_secret_doc]})
        cross_doc_ok = int(idor_cross.get("found", 0)) == 0 and not _contains_any_secret(idor_cross, [alpha_secret_marker])

        _, _, idor_vert = gw.request("POST", "/api/v1/docs/batch-get", headers=h_alpha_analyst, body={"doc_ids": [alpha_secret_doc]})
        vert_doc_ok = int(idor_vert.get("found", 0)) == 0 and not _contains_any_secret(idor_vert, [alpha_secret_marker])

        _, _, wall_batch_ana = gw.request(
            "POST",
            f"/api/v1/docs/batch-get?_now_ts={base_ts + 20}",
            headers=h_alpha_analyst,
            body={"doc_ids": [wall_doc_id]},
        )
        _, _, wall_batch_spc = gw.request(
            "POST",
            f"/api/v1/docs/batch-get?_now_ts={base_ts + 20}",
            headers=h_alpha_specialist,
            body={"doc_ids": [wall_doc_id]},
        )
        wall_batch_ok = (
            int(wall_batch_ana.get("found", 0)) == 0
            and not _contains_any_secret(wall_batch_ana, [wall_doc_marker])
            and int(wall_batch_spc.get("found", 0)) == 1
        )

        _, _, spc_wall_s = gw.request(
            "GET",
            f"/api/v1/docs/search?q=merger+acquisition+advisory+embargo&deduplicate=1&limit=15&_now_ts={base_ts + 20}",
            headers=h_alpha_specialist,
        )
        spc_saw_wall = any(d.get("doc_id") == wall_doc_id for d in (spc_wall_s.get("items") or []))
        _, _, ana_wall_s = gw.request(
            "GET",
            f"/api/v1/docs/search?q=merger+acquisition+advisory+embargo&deduplicate=1&limit=15&_now_ts={base_ts + 20}",
            headers=h_alpha_analyst,
        )
        ana_blocked_wall = (
            all(d.get("doc_id") != wall_doc_id for d in (ana_wall_s.get("items") or []))
            and not _contains_any_secret(ana_wall_s, [wall_doc_marker])
        )
        wall_cache_ok = spc_saw_wall and ana_blocked_wall

        st_dec_idor, _, dec_idor_body = gw.request("GET", f"/api/v1/risk/decisions/{t_alpha['sample_decision_id']}", headers=h_bravo_admin)
        cross_dec_ok = st_dec_idor in (403, 404) and dec_idor_body.get("tenant_id") != "tenant_alpha"

        # 跨租户内部文档引用存在性侧信道探测：tenant_alpha 尝试引用 tenant_bravo 的机密文档 doc_bravo_0001
        xcite_doc_id = "doc_alpha_xcite_oracle_01"
        st_xc, _, _ = gw.request(
            "POST",
            f"/api/v1/docs/upsert?_now_ts={base_ts + 22}",
            headers=h_alpha_admin,
            body={
                "doc_id": xcite_doc_id,
                "category": "AML",
                "regulation_code": "FATF-R16",
                "clearance_level": 2,
                "risk_weight": 10,
                "custom_tag": "tag_aml_1",
                "title": "Cross Tenant Citation Probe",
                "body": "xtenantcitationoracleprobeunique verification clause.",
                "citations": [t_bravo["secret_doc_id"]],
            },
        )
        cross_cite_oracle_blocked = False
        if st_xc in (400, 403):
            cross_cite_oracle_blocked = True
        elif st_xc == 200:
            _, _, xcite_srch = gw.request(
                "GET",
                f"/api/v1/docs/search?q=xtenantcitationoracleprobeunique&deduplicate=0&_now_ts={base_ts + 23}",
                headers=h_alpha_admin,
            )
            xc_item = next(
                (it for it in (xcite_srch.get("items") or []) if it.get("doc_id") == xcite_doc_id),
                None,
            )
            gw.request(
                "POST",
                f"/api/v1/docs/retire?_now_ts={base_ts + 24}",
                headers=h_alpha_admin,
                body={"doc_id": xcite_doc_id},
            )
            if xc_item is not None and int(xc_item.get("citation_count", 99)) == 0:
                cross_cite_oracle_blocked = True

        idor_all = [cross_doc_ok, vert_doc_ok, wall_batch_ok, wall_cache_ok, cross_dec_ok, cross_cite_oracle_blocked]
        c1_idor = float(c1_w["idor_and_3tier_chinese_wall"]) if all(idor_all) else (
            round(float(c1_w["idor_and_3tier_chinese_wall"]) * 0.45, 2) if sum(idor_all) >= 5 else 0.0
        )
        details["C1_idor_and_3tier_chinese_wall"] = {
            "passed": all(idor_all),
            "cross_tenant_doc": cross_doc_ok,
            "vertical_clearance_doc": vert_doc_ok,
            "3tier_wall_batch_get": wall_batch_ok,
            "3tier_wall_shared_cache": wall_cache_ok,
            "cross_tenant_decision": cross_dec_ok,
            "cross_tenant_citation_oracle_blocked": cross_cite_oracle_blocked,
            "score": c1_idor,
        }

        # C1.5 二级受控借调链、上游窗口自然到期（零写）缓存降级、第3跳阻断、源头撤权级联与 14 路并发竞态
        def _has_doc(res_obj: dict[str, Any], target_did: str) -> bool:
            return any(d.get("doc_id") == target_did for d in (res_obj.get("items") or []) if isinstance(d, dict))

        def _max_returned_clearance(res_obj: dict[str, Any]) -> int:
            return max((int(d.get("clearance_level", 0)) for d in (res_obj.get("items") or []) if isinstance(d, dict)), default=0)

        del_query = "/api/v1/docs/search?q=confidential+internal+audit+exception&deduplicate=1&limit=20"
        _, _, res_in_win = gw.request("GET", f"{del_query}&_now_ts={base_ts + 100}", headers=h_alpha_researcher)
        in_win_cl = _max_returned_clearance(res_in_win)
        _, _, res_past_win = gw.request("GET", f"{del_query}&_now_ts={base_ts + 8000}", headers=h_alpha_researcher)
        past_win_cl = _max_returned_clearance(res_past_win)
        _, _, res_before_win = gw.request("GET", f"{del_query}&_now_ts={base_ts - 9000}", headers=h_alpha_researcher)
        before_win_cl = _max_returned_clearance(res_before_win)
        delegation_window_cache_ok = (in_win_cl == 3) and (past_win_cl <= 2) and (before_win_cl <= 2)

        # 二级转借调双窗口交集 + 第 3 跳阻断 + 上游一级窗口自然到期无写自动降级测试
        auditor_uid = t_alpha["users"]["auditor"]["user_id"]
        analyst_uid = t_alpha["users"]["analyst"]["user_id"]
        viewer_uid = t_alpha["users"]["viewer"]["user_id"]
        specialist_uid = t_alpha["users"]["specialist"]["user_id"]

        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 45}",
            headers=h_alpha_auditor,
            body={
                "grantor_user_id": auditor_uid,
                "grantee_user_id": analyst_uid,
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts + 50,
                "expires_at": base_ts + 900,
                "action": "create",
            },
        )
        st_2hop_c, _, _ = gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 60}",
            headers=h_alpha_analyst,
            body={
                "grantor_user_id": analyst_uid,
                "grantee_user_id": viewer_uid,
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts + 70,
                "expires_at": base_ts + 6000,
                "action": "create",
            },
        )
        # viewer 已是第 2 跳受托人，尝试向 specialist 发起第 3 跳（应在创建时拒绝或对受托人不生效）
        st_3hop_c, _, _ = gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 80}",
            headers=h_alpha_viewer,
            body={
                "grantor_user_id": viewer_uid,
                "grantee_user_id": specialist_uid,
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts + 80,
                "expires_at": base_ts + 180,
                "action": "create",
            },
        )
        hop3_blocked = st_3hop_c in (400, 403)
        if st_3hop_c == 200:
            _, _, spc_at_100 = gw.request("GET", f"{del_query}&_now_ts={base_ts + 100}", headers=h_alpha_specialist)
            hop3_blocked = _max_returned_clearance(spc_at_100) <= 2
            gw.request(
                "POST",
                f"/api/v1/admin/delegations?_now_ts={base_ts + 105}",
                headers=h_alpha_viewer,
                body={
                    "grantor_user_id": viewer_uid,
                    "grantee_user_id": specialist_uid,
                    "delegated_role": "SENIOR_AUDITOR",
                    "starts_at": base_ts + 80,
                    "expires_at": base_ts + 180,
                    "action": "revoke",
                },
            )

        # viewer 在双窗口交集内（base_ts + 120）预热密级 3 检索缓存，随后在 base_ts + 1200（上游一级已于 +900 到期，零写操作！）同参数重搜
        _, _, vw_in_2hop = gw.request("GET", f"{del_query}&_now_ts={base_ts + 120}", headers=h_alpha_viewer)
        _, _, vw_after_up_exp = gw.request("GET", f"{del_query}&_now_ts={base_ts + 1200}", headers=h_alpha_viewer)
        transitive_2hop_and_upstream_expiry_ok = (
            st_2hop_c == 200
            and hop3_blocked
            and (_max_returned_clearance(vw_in_2hop) == 3)
            and (_max_returned_clearance(vw_after_up_exp) <= 1)
        )
        # 清理本组二级借调边
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 1210}",
            headers=h_alpha_admin,
            body={"grantor_user_id": analyst_uid, "grantee_user_id": viewer_uid, "delegated_role": "SENIOR_AUDITOR", "starts_at": base_ts + 70, "expires_at": base_ts + 6000, "action": "revoke"},
        )
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 1211}",
            headers=h_alpha_admin,
            body={"grantor_user_id": auditor_uid, "grantee_user_id": analyst_uid, "delegated_role": "SENIOR_AUDITOR", "starts_at": base_ts + 50, "expires_at": base_ts + 900, "action": "revoke"},
        )

        # 源头原生角色撤回 -> 受托人即时级联失效
        gw.request(
            "POST",
            f"/api/v1/admin/grants/revoke?_now_ts={base_ts + 1310}",
            headers=h_alpha_admin,
            body={"user_id": analyst_uid, "role": "SENIOR_AUDITOR", "action": "grant"},
        )
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 1315}",
            headers=h_alpha_analyst,
            body={
                "grantor_user_id": analyst_uid,
                "grantee_user_id": viewer_uid,
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts,
                "expires_at": base_ts + 5000,
                "action": "create",
            },
        )
        _, _, vw_via_del = gw.request("GET", f"{del_query}&_now_ts={base_ts + 1320}", headers=h_alpha_viewer)
        vw_got_del = _max_returned_clearance(vw_via_del) == 3
        gw.request(
            "POST",
            f"/api/v1/admin/grants/revoke?_now_ts={base_ts + 1325}",
            headers=h_alpha_admin,
            body={"user_id": analyst_uid, "role": "SENIOR_AUDITOR", "action": "revoke"},
        )
        _, _, vw_after_grantor_rev = gw.request("GET", f"{del_query}&_now_ts={base_ts + 1330}", headers=h_alpha_viewer)
        cascade_revoke_ok = vw_got_del and (_max_returned_clearance(vw_after_grantor_rev) <= 1)

        # 动态 ACL 封禁即时缓存失效 + 14 路并发“撤权 vs 慢读回填”竞态
        gw.request(
            "POST",
            f"/api/v1/admin/doc-acl?_now_ts={base_ts + 20}",
            headers=h_alpha_admin,
            body={"doc_id": wall_doc_id, "subject_type": "USER", "subject_id": specialist_uid, "effect": "DENY", "active": True},
        )
        _, _, spc_after_acl = gw.request(
            "GET",
            f"/api/v1/docs/search?q=merger+acquisition+advisory+embargo&deduplicate=1&limit=15&_now_ts={base_ts + 20}",
            headers=h_alpha_specialist,
        )
        acl_live_revoke_ok = not _has_doc(spc_after_acl, wall_doc_id)
        gw.request(
            "POST",
            f"/api/v1/admin/doc-acl?_now_ts={base_ts + 21}",
            headers=h_alpha_admin,
            body={"doc_id": wall_doc_id, "subject_type": "USER", "subject_id": specialist_uid, "effect": "DENY", "active": False},
        )

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

        race_bar = threading.Barrier(14)

        def _concurrent_reader(_r_i: int) -> None:
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

        pool_c15 = ThreadPoolExecutor(max_workers=14)
        futs_c15 = [pool_c15.submit(_concurrent_reader, i) for i in range(13)] + [pool_c15.submit(_concurrent_revoker)]
        _, c15_not_done = futures_wait(futs_c15, timeout=10.0)
        pool_c15.shutdown(wait=False, cancel_futures=True)
        c15_timed_out = bool(c15_not_done)
        if c15_timed_out:
            _recover_gateway_after_deadlock()
        else:
            for f in futs_c15:
                f.result()

        stale_leaked = c15_timed_out
        for d_flag in ("0", "1"):
            _, _, post_race = gw.request(
                "GET",
                f"/api/v1/docs/search?q=classified+board+resolution&deduplicate={d_flag}&limit=20",
                headers=h_alpha_viewer,
            )
            if _has_doc(post_race, alpha_secret_doc) or _max_returned_clearance(post_race) > 1:
                stale_leaked = True

        cache_all_ok = bool(
            delegation_window_cache_ok
            and transitive_2hop_and_upstream_expiry_ok
            and cascade_revoke_ok
            and acl_live_revoke_ok
            and elev_worked
            and (not stale_leaked)
        )
        c1_cache = float(c1_w["delegation_cascade_and_revoke_race"]) if cache_all_ok else 0.0
        details["C1_delegation_cascade_and_revoke_race"] = {
            "passed": cache_all_ok,
            "delegation_1hop_window_ok": delegation_window_cache_ok,
            "transitive_2hop_and_upstream_expiry_ok": transitive_2hop_and_upstream_expiry_ok,
            "cascade_grantor_revoke_ok": cascade_revoke_ok,
            "acl_live_revoke_ok": acl_live_revoke_ok,
            "post_race_clean": not stale_leaked,
            "score": c1_cache,
        }

        c1_total = round(c1_sqli + c1_trav + c1_leak + c1_idor + c1_cache, 2)

        # ==================== 波次二：C2 并发穿盾、跨模块调拨+风控交叉死锁、Nonce 齐射与四位一体回滚 ====================

        # C2.1 32 路并发抢配额 + 32 路并发核销令牌 + 负数/布尔伪装整数攻击
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

        pool_q = ThreadPoolExecutor(max_workers=toctou_threads)
        q_futs = [pool_q.submit(_race_quota, i) for i in range(toctou_threads)]
        q_done, q_not_done = futures_wait(q_futs, timeout=10.0)
        pool_q.shutdown(wait=False, cancel_futures=True)
        q_timed_out = bool(q_not_done)
        if q_timed_out:
            _recover_gateway_after_deadlock()
        q_outcomes = [f.result() for f in q_done if not f.exception()] if not q_timed_out else []
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

        pool_t = ThreadPoolExecutor(max_workers=toctou_threads)
        t_futs = [pool_t.submit(_race_token, i) for i in range(toctou_threads)]
        t_done, t_not_done = futures_wait(t_futs, timeout=10.0)
        pool_t.shutdown(wait=False, cancel_futures=True)
        t_timed_out = bool(t_not_done)
        if t_timed_out:
            _recover_gateway_after_deadlock()
        t_outcomes = [f.result() for f in t_done if not f.exception()] if not t_timed_out else []
        t_wins = sum(1 for st_t, b_t in t_outcomes if st_t == 200 and b_t.get("redeemed") is True)
        t_rejs = sum(1 for st_t, b_t in t_outcomes if st_t == 409 and b_t.get("redeemed") is False)

        quota_ok = q_wins == 1 and q_rejs == (toctou_threads - 1) and q_rem_check.get("remaining_quota") == 0
        token_ok = t_wins == 1 and t_rejs == (toctou_threads - 1)
        c2_toctou_max = float(c2_w["quota_and_token_30way_toctou"])
        c2_toctou = 0.0
        if quota_ok:
            c2_toctou += 0.9
        if token_ok:
            c2_toctou += 0.9
        if bool_and_neg_rejected:
            c2_toctou += 0.4
        else:
            c2_toctou *= 0.5
        c2_toctou = round(min(c2_toctou_max, c2_toctou), 2)
        details["C2_quota_and_token_toctou"] = {
            "passed": quota_ok and token_ok and bool_and_neg_rejected,
            "quota_wins": q_wins,
            "token_wins": t_wins,
            "bool_amount_rejected": st_bool_q == 400,
            "score": c2_toctou,
        }

        # C2.2 28 路高并发跨模块交叉竞争（20 路双向 quotas/transfer + 8 路含 REJECT 批次风控抢扣 REALTIME_ALERT_POOL）死锁探测与全局守恒
        st_bool_tr, _, _ = gw.request(
            "POST",
            "/api/v1/quotas/transfer",
            headers=h_alpha_admin,
            body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": True},
        )
        cross_total_workers = transfer_threads + batch_race_threads
        tr_bar = threading.Barrier(cross_total_workers)

        def _bidi_transfer(idx: int) -> tuple[str, list[tuple[int, dict[str, Any]]]]:
            tr_bar.wait()
            out_list = []
            for r_step in range(3):
                if (idx + r_step) % 2 == 0:
                    fq, tq, amt = "RESERVE_BUFFER_POOL", "REALTIME_ALERT_POOL", 6
                else:
                    fq, tq, amt = "REALTIME_ALERT_POOL", "RESERVE_BUFFER_POOL", 6
                st_x, _, bx = gw.request(
                    "POST",
                    "/api/v1/quotas/transfer",
                    headers=h_alpha_admin,
                    body={"from_quota": fq, "to_quota": tq, "amount": amt},
                )
                out_list.append((st_x, bx))
            return ("transfer", out_list)

        def _concurrent_reject_batch(b_idx: int) -> tuple[str, list[tuple[int, dict[str, Any]]]]:
            tr_bar.wait()
            out_list = []
            for r_step in range(2):
                txs = [
                    {
                        "tx_id": f"tx_rt_xrace_{b_idx}_{r_step}_{m}",
                        "account_id": f"acct_alpha_xr_{b_idx}",
                        "counterparty_id": t_alpha["sanctioned_entity"],
                        "amount_cents": 680000 + m * 10000,
                        "currency": "USD",
                        "channel": "CRYPTO_BRIDGE",
                        "contact_email": f"xrace.{b_idx}.{r_step}.{m}@alpha.org",
                        "ts": base_ts + 2100 + r_step * 10 + m,
                        "metadata": {},
                    }
                    for m in range(2)
                ]
                st_b, _, bb = gw.request(
                    "POST",
                    "/api/v1/risk/evaluate-batch",
                    headers=h_alpha_auditor,
                    body={"batch_id": f"rt_xb_{b_idx}_{r_step}", "transactions": txs},
                )
                out_list.append((st_b, bb))
            return ("batch", out_list)

        t_tr_start = time.perf_counter()
        deadlocked_or_500 = False
        tr_all_results: list[tuple[int, dict[str, Any]]] = []
        batch_all_results: list[tuple[int, dict[str, Any]]] = []
        pool_tr = ThreadPoolExecutor(max_workers=cross_total_workers)
        try:
            tr_futs = [pool_tr.submit(_bidi_transfer, i) for i in range(transfer_threads)] + [
                pool_tr.submit(_concurrent_reject_batch, j) for j in range(batch_race_threads)
            ]
            done_tr, not_done_tr = futures_wait(tr_futs, timeout=10.0)
            if not_done_tr:
                deadlocked_or_500 = True
            else:
                for tf in done_tr:
                    kind, items = tf.result()
                    if kind == "transfer":
                        tr_all_results.extend(items)
                    else:
                        batch_all_results.extend(items)
        except (FuturesTimeoutError, Exception):
            deadlocked_or_500 = True
        finally:
            pool_tr.shutdown(wait=False, cancel_futures=True)

        if deadlocked_or_500:
            _recover_gateway_after_deadlock()
        tr_elapsed_ms = (time.perf_counter() - t_tr_start) * 1000.0

        if any(st_x not in (200, 409) for st_x, _ in tr_all_results):
            deadlocked_or_500 = True
        if any(st_b != 200 for st_b, _ in batch_all_results):
            deadlocked_or_500 = True
        if any(
            int(bx.get("from_remaining", 0)) < 0 or int(bx.get("to_remaining", 0)) < 0
            for _, bx in tr_all_results
            if isinstance(bx, dict)
        ):
            deadlocked_or_500 = True

        dispatched_alerts = 0
        for st_b, bb in batch_all_results:
            if st_b == 200 and isinstance(bb, dict):
                for r_item in bb.get("results") or []:
                    if isinstance(r_item, dict) and r_item.get("alert_dispatched") is True:
                        dispatched_alerts += 1

        # 核查两池最终剩余额度 + 成功派发告警扣减次数严格等于初始 50 + 50 = 100！
        _, _, probe_tr = gw.request(
            "POST",
            "/api/v1/quotas/transfer",
            headers=h_alpha_admin,
            body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": 99999},
        )
        rem_reserve = int(probe_tr.get("from_remaining", -999))
        rem_alert = int(probe_tr.get("to_remaining", -999))
        conserved_total = rem_reserve + rem_alert + dispatched_alerts
        transfer_conserved = (
            (not deadlocked_or_500)
            and rem_reserve >= 0
            and rem_alert >= 0
            and (conserved_total == 100)
            and (tr_elapsed_ms < 6000.0)
        )
        transfer_full_ok = transfer_conserved and (st_bool_tr == 400)
        c2_transfer = (
            float(c2_w["bidirectional_transfer_deadlock_and_conservation"])
            if transfer_full_ok
            else (
                round(float(c2_w["bidirectional_transfer_deadlock_and_conservation"]) * 0.50, 2)
                if transfer_conserved
                else 0.0
            )
        )
        details["C2_bidirectional_transfer_deadlock_and_conservation"] = {
            "passed": transfer_full_ok,
            "deadlocked_or_500": deadlocked_or_500,
            "conserved_total_expected_100": conserved_total,
            "dispatched_alerts": dispatched_alerts,
            "bool_transfer_rejected": st_bool_tr == 400,
            "elapsed_ms": round(tr_elapsed_ms, 2),
            "score": c2_transfer,
        }

        # C2.3 Webhook 伪造、过期/超前时间窗、布尔金额混淆与 16 路并发相同 Nonce 齐射重放
        wh_secret = t_alpha["webhook_secret"]
        wh_body = json.dumps({"settlement_ref": "stl_rt_race_01", "amount_cents": 500000}, separators=(",", ":"))
        now_sim = base_ts + 1000
        race_nonce = "nonce_rt_16way_race_001"
        race_sig = hmac.new(
            wh_secret.encode("utf-8"),
            f"tenant_alpha.{now_sim}.{race_nonce}.{wh_body}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        wh_bar = threading.Barrier(16)

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

        pool_wh = ThreadPoolExecutor(max_workers=16)
        wh_futs = [pool_wh.submit(_race_webhook, i) for i in range(16)]
        wh_done, wh_not_done = futures_wait(wh_futs, timeout=10.0)
        pool_wh.shutdown(wait=False, cancel_futures=True)
        if wh_not_done:
            _recover_gateway_after_deadlock()
        wh_statuses = [f.result() for f in wh_done if not f.exception()] if not wh_not_done else []
        wh_200_cnt = sum(1 for s in wh_statuses if s == 200)
        wh_rej_cnt = sum(1 for s in wh_statuses if s in (400, 401, 403, 409))

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
        bool_wh_body = json.dumps({"settlement_ref": "stl_bool_01", "amount_cents": True}, separators=(",", ":"))
        bool_wh_sig = hmac.new(wh_secret.encode("utf-8"), f"tenant_alpha.{now_sim}.nonce_bool_01.{bool_wh_body}".encode("utf-8"), hashlib.sha256).hexdigest()
        st_wh_bool, _, _ = gw.request(
            "POST",
            f"/api/v1/webhooks/settlement-callback?_now_ts={now_sim + 1}",
            headers={"X-Aegis-Tenant": "tenant_alpha", "X-Aegis-Timestamp": str(now_sim), "X-Aegis-Nonce": "nonce_bool_01", "X-Aegis-Signature": f"sha256={bool_wh_sig}"},
            body=bool_wh_body,
        )

        wh_all_ok = (
            wh_200_cnt == 1
            and wh_rej_cnt == 15
            and st_wh_forge in (400, 401, 403)
            and st_wh_exp in (400, 401, 403)
            and st_wh_fut in (400, 401, 403)
            and st_wh_bool == 400
        )
        c2_wh = float(c2_w["webhook_replay_and_concurrent_nonce"]) if wh_all_ok else (
            0.5 if (st_wh_forge in (400, 401, 403) and st_wh_exp in (400, 401, 403) and wh_200_cnt >= 1) else 0.0
        )
        details["C2_webhook_replay_and_concurrent_nonce"] = {
            "passed": wh_all_ok,
            "concurrent_16way_200s": wh_200_cnt,
            "expired_blocked": st_wh_exp in (400, 401, 403),
            "future_blocked": st_wh_fut in (400, 401, 403),
            "bool_payload_rejected": st_wh_bool == 400,
            "score": c2_wh,
        }

        # C2.4 半批失败四位一体强原子回滚（在 tenant_bravo 上同时校验数据库、滑窗、三跳传染图边与 REALTIME_ALERT_POOL 告警配额零泄漏）+ 数值边界
        _, _, bravo_alert_probe_0 = gw.request(
            "POST",
            "/api/v1/quotas/consume",
            headers=h_bravo_admin,
            body={"quota_type": "REALTIME_ALERT_POOL", "amount": 99999},
        )
        bravo_alert_before = int(bravo_alert_probe_0.get("remaining_quota", -1))

        clean_acct = "acct_bravo_clean_probe_999"
        phantom_bridge = "cp_phantom_sanc_bridge_999"
        dirty_batch_1 = [
            {
                "tx_id": f"tx_dirty1_b_{k}",
                "account_id": clean_acct,
                "counterparty_id": t_bravo["sanctioned_entity"],
                "amount_cents": 750000,
                "currency": "USD",
                "channel": "CRYPTO_BRIDGE",
                "contact_email": f"ok{k}@bravo.org",
                "ts": base_ts + 3000 + k,
                "metadata": {},
            }
            for k in range(3)
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
            headers=h_bravo_admin,
            body={"batch_id": "dirty_b1", "transactions": dirty_batch_1},
        )

        dirty_batch_2 = [
            {
                "tx_id": "tx_dirty2_sanc_link",
                "account_id": phantom_bridge,
                "counterparty_id": t_bravo["sanctioned_entity"],
                "amount_cents": 780000,
                "currency": "USD",
                "channel": "CRYPTO_BRIDGE",
                "contact_email": "ok2_0@bravo.org",
                "ts": base_ts + 3020,
                "metadata": {},
            },
            {
                "tx_id": "tx_dirty2_clean_acct",
                "account_id": clean_acct,
                "counterparty_id": "cp_d2_1",
                "amount_cents": 300000,
                "currency": "USD",
                "channel": "WIRE_INTL",
                "contact_email": "ok2_1@bravo.org",
                "ts": base_ts + 3021,
                "metadata": {},
            },
            {
                "tx_id": t_bravo["sample_tx_id"],
                "account_id": clean_acct,
                "counterparty_id": "cp_dup",
                "amount_cents": 300000,
                "currency": "USD",
                "channel": "WIRE_INTL",
                "contact_email": "dup@bravo.org",
                "ts": base_ts + 3030,
                "metadata": {},
            },
        ]
        st_db2, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_bravo_admin,
            body={"batch_id": "dirty_b2", "transactions": dirty_batch_2},
        )

        st_probe, _, probe_body = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_bravo_admin,
            body={
                "batch_id": "clean_probe_b",
                "transactions": [
                    {
                        "tx_id": "tx_clean_probe_001",
                        "account_id": clean_acct,
                        "counterparty_id": phantom_bridge,
                        "amount_cents": 50000,
                        "currency": "USD",
                        "channel": "ACH_BATCH",
                        "contact_email": "clean@bravo.org",
                        "ts": base_ts + 3050,
                        "metadata": {},
                    }
                ],
            },
        )
        _, _, bravo_alert_probe_1 = gw.request(
            "POST",
            "/api/v1/quotas/consume",
            headers=h_bravo_admin,
            body={"quota_type": "REALTIME_ALERT_POOL", "amount": 99999},
        )
        bravo_alert_after = int(bravo_alert_probe_1.get("remaining_quota", -99))

        probe_res0 = probe_body.get("results", [{}])[0] if (st_probe == 200 and probe_body.get("results")) else {}
        probe_win_cnt = (probe_res0.get("window") or {}).get("tx_count", -1)
        probe_sanc_hop = probe_res0.get("sanction_hop", -1)
        alert_quota_rollback_ok = (bravo_alert_before == 50) and (bravo_alert_after == bravo_alert_before)
        atomicity_ok = (
            (st_db1 in (400, 422))
            and (st_db2 in (400, 409))
            and (probe_win_cnt == 1)
            and (probe_sanc_hop == 0)
            and alert_quota_rollback_ok
        )

        st_int64, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_bravo_admin,
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
                        "contact_email": "ovf@bravo.org",
                        "ts": base_ts + 3060,
                        "metadata": {},
                    }
                ],
            },
        )
        st_bool_tx, _, _ = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_bravo_admin,
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
                        "contact_email": "bool@bravo.org",
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

        type_overflow_ok = st_int64 == 400 and st_bool_tx == 400 and st_nan == 400 and st_inf == 400
        c2_bt_max = float(c2_w["batch_rollback_and_type_overflow"])
        c2_batch_type = 0.0
        if atomicity_ok:
            c2_batch_type += 1.4
        if st_int64 == 400:
            c2_batch_type += 0.4
        if st_bool_tx == 400:
            c2_batch_type += 0.35
        if st_nan == 400 and st_inf == 400:
            c2_batch_type += 0.35
        if 500 in (st_db1, st_db2, st_int64, st_bool_tx, st_nan, st_inf):
            c2_batch_type *= 0.25
        c2_batch_type = round(min(c2_bt_max, c2_batch_type), 2)
        details["C2_batch_rollback_and_type_overflow"] = {
            "passed": atomicity_ok and type_overflow_ok,
            "atomicity_graph_and_alert_quota_clean": atomicity_ok,
            "alert_quota_before_after": [bravo_alert_before, bravo_alert_after],
            "probe_win_tx_count_expected_1": probe_win_cnt,
            "probe_sanction_hop_expected_0": probe_sanc_hop,
            "int64_overflow_status": st_int64,
            "bool_tx_status": st_bool_tx,
            "nan_inf_statuses": [st_nan, st_inf],
            "score": c2_batch_type,
        }

        c2_total = round(c2_toctou + c2_transfer + c2_wh + c2_batch_type, 2)

        # ==================== 波次三：C3 全变体复杂度/环路炸弹 + 混写/动态ACL缓存穿透洪泛护盾 ====================

        # 先在独立超时守护池中测试“借调委托有向环路炸弹”（防止无限循环阻塞后续并发探针）
        bravo_ana_uid = t_bravo["users"]["analyst"]["user_id"]
        bravo_spc_uid = t_bravo["users"]["specialist"]["user_id"]
        gw.request(
            "POST",
            f"/api/v1/admin/grants/revoke?_now_ts={base_ts + 40}",
            headers=h_bravo_admin,
            body={"user_id": bravo_ana_uid, "role": "SENIOR_AUDITOR", "action": "grant"},
        )
        gw.request(
            "POST",
            f"/api/v1/admin/grants/revoke?_now_ts={base_ts + 41}",
            headers=h_bravo_admin,
            body={"user_id": bravo_spc_uid, "role": "SENIOR_AUDITOR", "action": "grant"},
        )
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 42}",
            headers=h_bravo_analyst,
            body={
                "grantor_user_id": bravo_ana_uid,
                "grantee_user_id": bravo_spc_uid,
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts,
                "expires_at": base_ts + 5000,
                "action": "create",
            },
        )
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 43}",
            headers=h_bravo_specialist,
            body={
                "grantor_user_id": bravo_spc_uid,
                "grantee_user_id": bravo_ana_uid,
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts,
                "expires_at": base_ts + 5000,
                "action": "create",
            },
        )
        # 撤回两人直接原生授权后，数据库内仅剩 bravo_ana <-> bravo_spc 有向环路！
        gw.request(
            "POST",
            f"/api/v1/admin/grants/revoke?_now_ts={base_ts + 44}",
            headers=h_bravo_admin,
            body={"user_id": bravo_ana_uid, "role": "SENIOR_AUDITOR", "action": "revoke"},
        )
        gw.request(
            "POST",
            f"/api/v1/admin/grants/revoke?_now_ts={base_ts + 45}",
            headers=h_bravo_admin,
            body={"user_id": bravo_spc_uid, "role": "SENIOR_AUDITOR", "action": "revoke"},
        )

        def _probe_delegation_cycle() -> tuple[int, dict[str, Any], float]:
            tc0 = time.perf_counter()
            st_c, _, b_c = gw.request(
                "GET",
                f"/api/v1/docs/search?q=confidential+internal+audit+exception&deduplicate=0&_now_ts={base_ts + 50}",
                headers=h_bravo_analyst,
            )
            return st_c, b_c, (time.perf_counter() - tc0) * 1000.0

        pool_cyc = ThreadPoolExecutor(max_workers=1)
        fut_cyc = pool_cyc.submit(_probe_delegation_cycle)
        done_cyc, not_done_cyc = futures_wait([fut_cyc], timeout=3.5)
        pool_cyc.shutdown(wait=False, cancel_futures=True)
        if not_done_cyc:
            cycle_bomb_ok = False
            cycle_ms = 3500.0
            _recover_gateway_after_deadlock()
        else:
            st_cyc, body_cyc, cycle_ms = fut_cyc.result()
            cyc_max_cl = max((int(d.get("clearance_level", 0)) for d in (body_cyc.get("items") or []) if isinstance(d, dict)), default=0)
            cycle_bomb_ok = (st_cyc == 200) and (cyc_max_cl <= 2) and (cycle_ms <= bomb_max_ms)

        # 清理环路委托边
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 55}",
            headers=h_bravo_admin,
            body={"grantor_user_id": bravo_ana_uid, "grantee_user_id": bravo_spc_uid, "delegated_role": "SENIOR_AUDITOR", "starts_at": base_ts, "expires_at": base_ts + 5000, "action": "revoke"},
        )
        gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 56}",
            headers=h_bravo_admin,
            body={"grantor_user_id": bravo_spc_uid, "grantee_user_id": bravo_ana_uid, "delegated_role": "SENIOR_AUDITOR", "starts_at": base_ts, "expires_at": base_ts + 5000, "action": "revoke"},
        )

        redos_email = ("a" * 23) + "!"
        redos_variants = [
            ({"field": "channel", "op": "REGEX", "value": "^(a+)+$"}, {"channel": ("a" * 23) + "!", "amount_cents": 100, "contact_email": "ok@b.org"}),
            ({"field": "channel", "op": "REGEX", "value": "^(a|aa)+$"}, {"channel": ("a" * 24) + "!", "amount_cents": 100, "contact_email": "ok@b.org"}),
            ({"field": "channel", "op": "REGEX", "value": "^.*a.*a.*a.*a.*!$"}, {"channel": ("a" * 40) + "b", "amount_cents": 100, "contact_email": "ok@b.org"}),
            ({"field": "channel", "op": "REGEX", "value": "^[A-Z0-9_]{50000}$"}, {"channel": "WIRE_INTL", "amount_cents": 100, "contact_email": "ok@b.org"}),
            ({"field": "channel", "op": "REGEX", "value": r"^(a+)\1+$"}, {"channel": ("a" * 30) + "!", "amount_cents": 100, "contact_email": "ok@b.org"}),
        ]

        deep_raw_json = (b'{"a":' * 1400) + b"1" + (b"}" * 1400)
        deep_tree = _build_deep_nested_rule(1150)
        bloated_tree = _build_wide_bloated_rule()
        huge_in_tree = {"field": "channel", "op": "IN", "value": [f"CH_{i}" for i in range(500)]}
        huge_citations_doc = {
            "doc_id": "doc_alpha_cite_flood_999",
            "category": "AML",
            "regulation_code": "FATF-R16",
            "clearance_level": 2,
            "risk_weight": 15,
            "custom_tag": "tag_aml_1",
            "title": "Citation Flood Bomb",
            "body": "citation amplification flood test payload.",
            "citations": [f"ref_flood_{i}" for i in range(2000)],
        }

        amp_urls = [
            "/api/v1/docs/search?q=wire&limit=-1&offset=0",
            "/api/v1/docs/search?q=wire&limit=0&offset=0",
            "/api/v1/docs/search?q=wire&limit=50000&offset=0",
            "/api/v1/docs/search?q=wire&limit=20&offset=999999",
            "/api/v1/docs/search?q=wire&limit=20&offset=-5",
            "/api/v1/docs/search?q=" + "+".join(f"term{i:02d}" for i in range(40)),
            "/api/v1/docs/search?q=***%25%25%25",
        ]

        gw.request("GET", "/api/v1/docs/search?q=settlement+clearing&deduplicate=1&limit=5", headers=h_alpha_admin)
        gw.request("GET", "/api/v1/docs/search?q=settlement+clearing&deduplicate=1&limit=5", headers=h_bravo_admin)

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
            for tree_payload in (deep_tree, bloated_tree, huge_in_tree):
                t1 = time.perf_counter()
                st_d, _, _ = gw.request("POST", "/api/v1/risk/simulate-rule", headers=h_alpha_analyst, body={"rule_tree": tree_payload, "sample_tx": sample_ok})
                local_d.append((st_d, (time.perf_counter() - t1) * 1000.0))

            t2 = time.perf_counter()
            st_cf, _, _ = gw.request("POST", "/api/v1/docs/upsert", headers=h_alpha_auditor, body=huge_citations_doc)
            local_d.append((st_cf, (time.perf_counter() - t2) * 1000.0))
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

        def _attacker_cache_buster_with_upserts_and_acl() -> None:
            """发射 36 个互不重复查询并穿插 4 次实时文档 Upsert 与 4 次 doc-acl 切换，同时检验增量倒排与纪元解耦！"""
            nonlocal bust_errors
            dos_barrier.wait()
            local_b = []
            local_err = 0
            vocab = ["wire", "settlement", "escrow", "sanctions", "vessel", "encryption", "liquidity", "masking"]
            for i in range(36):
                if i in (5, 14, 23, 32):
                    gw.request(
                        "POST",
                        f"/api/v1/docs/upsert?_now_ts={base_ts + 4000 + i}",
                        headers=h_alpha_admin,
                        body={
                            "doc_id": f"doc_alpha_rt_bust_{i:02d}",
                            "category": "AML",
                            "regulation_code": "FATF-R16",
                            "clearance_level": 2,
                            "risk_weight": 15,
                            "custom_tag": "tag_aml_1",
                            "title": f"Live Flood Revision {i}",
                            "body": "wire settlement escrow verification thresholds live incremental check.",
                            "updated_at": base_ts + 4000 + i,
                            "citations": ["doc_alpha_0002"],
                        },
                    )
                elif i in (9, 18, 27, 34):
                    gw.request(
                        "POST",
                        f"/api/v1/admin/doc-acl?_now_ts={base_ts + 4100 + i}",
                        headers=h_alpha_admin,
                        body={
                            "doc_id": "doc_alpha_0005",
                            "subject_type": "USER",
                            "subject_id": viewer_uid,
                            "effect": "DENY",
                            "active": bool(i % 2 == 1),
                        },
                    )
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
            for step in range(9):
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

        pool_c3 = ThreadPoolExecutor(max_workers=7)
        futs_c3 = [
            pool_c3.submit(_attacker_redos),
            pool_c3.submit(_attacker_deep),
            pool_c3.submit(_attacker_amp),
            pool_c3.submit(_attacker_cache_buster_with_upserts_and_acl),
            pool_c3.submit(_normal_tenant_user),
            pool_c3.submit(_normal_tenant_user),
            pool_c3.submit(_normal_tenant_user),
        ]
        _, c3_not_done = futures_wait(futs_c3, timeout=25.0)
        pool_c3.shutdown(wait=False, cancel_futures=True)
        if c3_not_done:
            normal_errors += 999
        else:
            for f in futs_c3:
                f.result()

        redos_max_ms = max((dt for _, dt in redos_records), default=9999.0)
        redos_all_400 = all(st == 400 for st, _ in redos_records) and len(redos_records) == 6
        redos_ok = redos_all_400 and (redos_max_ms <= bomb_max_ms) and cycle_bomb_ok
        c3_redos_max = float(c3_w["redos_and_quantifier_bomb"])
        if redos_ok:
            c3_redos = c3_redos_max
        elif redos_all_400 and (redos_max_ms <= bomb_max_ms):
            c3_redos = round(c3_redos_max * 0.65, 2)
        elif cycle_bomb_ok and sum(1 for st, _ in redos_records if st == 400) >= 4:
            c3_redos = round(c3_redos_max * 0.45, 2)
        else:
            c3_redos = 0.0
        details["C3_redos_and_quantifier_bomb"] = {
            "passed": redos_ok,
            "all_regex_rejected_400": redos_all_400,
            "delegation_cycle_bomb_ok": cycle_bomb_ok,
            "delegation_cycle_ms": round(cycle_ms, 2),
            "regex_max_ms": round(redos_max_ms, 2),
            "score": c3_redos,
        }

        deep_max_ms = max((dt for _, dt in deep_records), default=9999.0)
        deep_all_400 = all(st in (400, 413, 422) for st, _ in deep_records) and len(deep_records) == 5
        deep_ok = deep_all_400 and (deep_max_ms <= bomb_max_ms)
        c3_deep = float(c3_w["deep_json_and_ast_bomb"]) if deep_ok else 0.0
        details["C3_deep_json_and_ast_bomb"] = {
            "passed": deep_ok,
            "statuses": [st for st, _ in deep_records],
            "max_ms": round(deep_max_ms, 2),
            "score": c3_deep,
        }

        amp_all_400 = all(st == 400 for st, _ in amp_records) and len(amp_records) == len(amp_urls)
        amp_max_ms = max((dt for _, dt in amp_records), default=9999.0)
        amp_ok = amp_all_400 and (amp_max_ms <= bomb_max_ms)
        c3_amp = float(c3_w["query_amplification_bomb"]) if amp_ok else 0.0
        details["C3_query_amplification_bomb"] = {
            "passed": amp_ok,
            "rejected_count": f"{sum(1 for st, _ in amp_records if st == 400)}/{len(amp_urls)}",
            "max_ms": round(amp_max_ms, 2),
            "score": c3_amp,
        }

        sorted_norm = sorted(normal_latencies_ms) if normal_latencies_ms else [9999.0]
        norm_p95 = sorted_norm[min(len(sorted_norm) - 1, int(len(sorted_norm) * 0.95))]
        bust_avg_ms = (sum(bust_latencies_ms) / len(bust_latencies_ms)) if bust_latencies_ms else 9999.0

        shield_ok = (normal_errors == 0) and (norm_p95 <= normal_p95_max_ms)
        bust_fast_ok = (bust_errors == 0) and (bust_avg_ms <= cache_bust_avg_max_ms)
        c3_shield = 0.0
        if shield_ok and bust_fast_ok:
            c3_shield = float(c3_w["interleaved_upsert_cache_bust_and_p95_shield"])
        elif shield_ok:
            c3_shield = round(float(c3_w["interleaved_upsert_cache_bust_and_p95_shield"]) * 0.4, 2)
        details["C3_interleaved_upsert_cache_bust_and_p95_shield"] = {
            "passed": shield_ok and bust_fast_ok,
            "normal_p95_ms": round(norm_p95, 2),
            "cache_bust_avg_ms": round(bust_avg_ms, 2),
            "normal_errors": normal_errors,
            "bust_errors": bust_errors,
            "score": c3_shield,
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
