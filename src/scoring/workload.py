# -*- coding: utf-8 -*-
"""B1 高密度业务零失真对账器（80+ 项全契约核验）+ A1/A2/A3 混合读写高压压测与常驻内存探针。

设计要点（xiaonuo-v2.0）：
1. B1 零失真对账：在独立数据库副本上对参考原版与被测沙盒回放完全一致的 80+ 步多租户复杂读写操作序列，
   覆盖短语词距邻近度加成、历史双轨法规号折叠、三级利益冲突隔离墙（含最近组织节点与个人豁免优先级）、
   带时效借调委托、文档实时 Upsert/Retire、1~3 跳受制裁资金传染、滑动窗口精确动态中位数、
   主权央行清算兼容豁免、跨配额池调拨、自定义报表模板渲染与审计滚动 SHA-256。
2. A1/A2/A3 实测压测：
   - A1 穿插高频文档实时写入（Upsert）与多词邻近度去重检索 + 批量三跳传染与滑窗中位数评估（惩罚每次写入全量重建索引的偷懒方案）；
   - A2 12 路混合读写（含实时 Upsert 与跨池配额调拨）并发吞吐、P95 与硬性 P99 尾延迟、跨租户全局大锁阻塞探针；
   - A3 SQLite trace_callback 真实 SQL 削减率、流式导出峰值削减率，以及常驻堆内存增量（Resident Heap Delta）预算核查！
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gc
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
    """在指定实现上运行 80+ 项高密度多租户正常业务操作序列，收集确定性输出快照。"""
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
            docs_per_tenant=int(wl.get("b1_docs_per_tenant", 34)),
            tx_per_tenant=int(wl.get("b1_tx_per_tenant", 100)),
            audit_rows_per_tenant=120,
        )
        gw = server_mod.create_gateway(db_path, storage_dir)
        base_ts = int(manifest["base_ts"])
        records: list[tuple[str, Any]] = []

        # 1. 健康探针
        st, _, h_body = gw.request("GET", "/api/v1/health")
        records.append(("health", (st, h_body.get("status"))))

        # 2. 多租户多角色检索对账（含相邻词距邻近度加分、双轨法规别名簇折叠、三级隔离墙 specialist vs analyst、有效期内借调 researcher）
        queries = [
            ("wire transfer originator beneficiary travel rule", "", "", "1", "score", "desc", 15, 0),
            ("wire transfer travel rule verification", "", "", "0", "score", "desc", 20, 0),
            ("blocked entity ownership aggregation embargo", "SANCTIONS", "", "1", "score", "desc", 12, 0),
            ("encryption confidentiality resilience", "PRIVACY", "", "1", "updated_at", "asc", 12, 2),
            ("high quality liquid assets net cash outflows", "", "", "1", "score", "desc", 10, 0),
            ("primary account number masking cryptography", "CARD", "", "0", "risk_weight", "asc", 8, 1),
            ("merger acquisition target valuation advisory embargo", "", "", "1", "score", "desc", 12, 0),
            ("", "AML", "", "1", "updated_at", "desc", 10, 0),
        ]
        tenant_ids = sorted(manifest["tenants"].keys())
        role_cycle = ["admin", "auditor", "specialist", "analyst", "researcher", "viewer"]

        for q_idx, (q_str, cat, tag, dedup, s_by, s_dir, lim, off) in enumerate(queries):
            for t_i, tid in enumerate(tenant_ids):
                t_info = manifest["tenants"][tid]
                r_key = role_cycle[(q_idx + t_i) % len(role_cycle)]
                hdr = _headers(tid, t_info["users"][r_key])
                url = (
                    f"/api/v1/docs/search?q={q_str.replace(' ', '+')}"
                    f"&category={cat}&tag_filter={tag}&deduplicate={dedup}"
                    f"&sort_by={s_by}&sort_dir={s_dir}&limit={lim}&offset={off}"
                    f"&_now_ts={base_ts + 60}"
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

        # 3. 验证借调委托窗口外自动降级 & 动态创建借调委托 + USER ALLOW 个人豁免覆盖部门 DENY
        t0_id = tenant_ids[0]
        t0_info = manifest["tenants"][t0_id]
        t0_slug = t0_info["slug"]
        h0_adm = _headers(t0_id, t0_info["users"]["admin"])
        h0_aud = _headers(t0_id, t0_info["users"]["auditor"])
        h0_res = _headers(t0_id, t0_info["users"]["researcher"])
        h0_ana = _headers(t0_id, t0_info["users"]["analyst"])
        h0_spc = _headers(t0_id, t0_info["users"]["specialist"])

        # researcher 在委托过期后（base_ts + 9500 > base_ts + 7200）搜索 CONFIDENTIAL(3) 专属词项应无法看到密级 3 文档
        st_exp_d, _, exp_d_res = gw.request(
            "GET",
            f"/api/v1/docs/search?q=confidential+internal+audit+exception+remediation&deduplicate=0&_now_ts={base_ts + 9500}",
            headers=h0_res,
        )
        records.append(("delegation_expired_researcher", (st_exp_d, exp_d_res.get("returned_count"))))

        # auditor 将 SENIOR_AUDITOR 在 [base_ts + 300, base_ts + 1500] 借调给 specialist
        st_del_c, _, del_c_res = gw.request(
            "POST",
            f"/api/v1/admin/delegations?_now_ts={base_ts + 250}",
            headers=h0_aud,
            body={
                "grantor_user_id": t0_info["users"]["auditor"]["user_id"],
                "grantee_user_id": t0_info["users"]["specialist"]["user_id"],
                "delegated_role": "SENIOR_AUDITOR",
                "starts_at": base_ts + 300,
                "expires_at": base_ts + 1500,
                "action": "create",
            },
        )
        st_spc_in, _, spc_in_res = gw.request(
            "GET",
            f"/api/v1/docs/search?q=remediation+action+plan&deduplicate=0&_now_ts={base_ts + 600}",
            headers=h0_spc,
        )
        records.append(
            (
                "delegation_active_specialist",
                (st_del_c, del_c_res.get("affected"), st_spc_in, spc_in_res.get("returned_count")),
            )
        )

        # 给 ops_team 的 analyst 授予针对 wall_doc_id 的 USER ALLOW 个人豁免，验证三级隔离墙最高优先级放行
        st_acl_allow, _, _ = gw.request(
            "POST",
            f"/api/v1/admin/doc-acl?_now_ts={base_ts + 260}",
            headers=h0_adm,
            body={
                "doc_id": t0_info["wall_doc_id"],
                "subject_type": "USER",
                "subject_id": t0_info["users"]["analyst"]["user_id"],
                "effect": "ALLOW",
                "active": True,
            },
        )
        st_ana_allow, _, ana_allow_res = gw.request(
            "GET",
            f"/api/v1/docs/search?q=target+valuation+advisory&deduplicate=1&_now_ts={base_ts + 265}",
            headers=h0_ana,
        )
        saw_wall_after_allow = any(
            d["doc_id"] == t0_info["wall_doc_id"] for d in (ana_allow_res.get("items") or [])
        )
        gw.request(
            "POST",
            f"/api/v1/admin/doc-acl?_now_ts={base_ts + 270}",
            headers=h0_adm,
            body={
                "doc_id": t0_info["wall_doc_id"],
                "subject_type": "USER",
                "subject_id": t0_info["users"]["analyst"]["user_id"],
                "effect": "ALLOW",
                "active": False,
            },
        )
        records.append(("wall_user_allow_override", (st_acl_allow, st_ana_allow, saw_wall_after_allow)))

        # 4. 文档实时流式 Upsert（新增双轨别名文档 + 二次修订正文与引用）与 Retire 退役闭环
        for tid in tenant_ids[:2]:
            ti = manifest["tenants"][tid]
            sl = ti["slug"]
            ha = _headers(tid, ti["users"]["admin"])
            live_doc_id = f"doc_{sl}_live_0901"
            st_up1, _, up1 = gw.request(
                "POST",
                f"/api/v1/docs/upsert?_now_ts={base_ts + 300}",
                headers=ha,
                body={
                    "doc_id": live_doc_id,
                    "category": "AML",
                    "regulation_code": "FATF-R16-2012",
                    "clearance_level": 2,
                    "risk_weight": 26,
                    "custom_tag": "tag_aml_live",
                    "title": "[FATF-R16-2012] Live Wire Originator Beneficiary Addendum",
                    "body": (
                        f"public regulatory guidance. Tenant {sl} policy directive for FATF-R16. "
                        "Core mandate: wire transfer originator beneficiary travel rule verification thresholds. "
                        "Operational scope: settlement clearing nostro vostro escrow chargeback velocity beneficiary."
                    ),
                    "updated_at": base_ts + 300,
                    "citations": ["ref_live_1", "ref_live_2"],
                },
            )
            _, _, s_up1 = gw.request(
                "GET",
                f"/api/v1/docs/search?q=originator+beneficiary+addendum&deduplicate=1&_now_ts={base_ts + 305}",
                headers=ha,
            )
            up1_items = [(d["doc_id"], d["score"], d["cluster_size"], d["citation_count"]) for d in (s_up1.get("items") or [])]

            # 二次修订同一篇文档并追加引用
            st_up2, _, up2 = gw.request(
                "POST",
                f"/api/v1/docs/upsert?_now_ts={base_ts + 310}",
                headers=ha,
                body={
                    "doc_id": live_doc_id,
                    "category": "AML",
                    "regulation_code": "FATF-R16-2012",
                    "clearance_level": 2,
                    "risk_weight": 34,
                    "custom_tag": "tag_aml_live",
                    "title": "[FATF-R16-2012] Revised Wire Originator Beneficiary Standard",
                    "body": "revised live wire originator beneficiary verification addendum controls.",
                    "updated_at": base_ts + 310,
                    "citations": ["ref_live_3"],
                },
            )
            _, _, s_up2 = gw.request(
                "GET",
                f"/api/v1/docs/search?q=revised+live+wire+originator&deduplicate=0&_now_ts={base_ts + 315}",
                headers=ha,
            )
            up2_items = [(d["doc_id"], d["score"], d["citation_count"]) for d in (s_up2.get("items") or [])]

            # Retire 退役该文档并确认不可检索、不可 batch-get
            st_ret, _, _ = gw.request(
                "POST",
                f"/api/v1/docs/retire?_now_ts={base_ts + 320}",
                headers=ha,
                body={"doc_id": live_doc_id},
            )
            _, _, s_ret = gw.request(
                "GET",
                f"/api/v1/docs/search?q=revised+live+wire+originator&deduplicate=0&_now_ts={base_ts + 325}",
                headers=ha,
            )
            _, _, bg_ret = gw.request(
                "POST",
                f"/api/v1/docs/batch-get?_now_ts={base_ts + 325}",
                headers=ha,
                body={"doc_ids": [live_doc_id, f"doc_{sl}_0001"]},
            )
            records.append(
                (
                    f"doc_lifecycle_{tid}",
                    (
                        st_up1,
                        up1.get("operation"),
                        up1_items,
                        st_up2,
                        up2.get("operation"),
                        up2_items,
                        st_ret,
                        s_ret.get("returned_count"),
                        bg_ret.get("found"),
                    ),
                )
            )

        # 5. 文档隔离与恢复闭环（3 租户）
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
                "/api/v1/docs/search?q=legacy+cross+border&deduplicate=0&limit=50",
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
                "/api/v1/docs/search?q=legacy+cross+border&deduplicate=0&limit=50",
                headers=h_adm,
            )
            in_after = any(d["doc_id"] == target_doc for d in (s_after.get("items") or []))
            records.append((f"quarantine_cycle_{tid}", (st_q1, in_mid, st_q2, in_after)))

        # 6. 策略更新 + 动态制裁名单维护 + 融合 1/2/3 跳传染、动态滑窗中位数突变、主权央行清算豁免的批次风控评估
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

                # 动态新增一个受制裁实体 ent_dyn_sanc_99
                st_sanc, _, sanc_res = gw.request(
                    "POST",
                    "/api/v1/admin/sanctions",
                    headers=h_adm,
                    body={"entity_id": f"ent_{slug}_dyn_99", "list_source": "EU_CONSOLIDATED", "active": True},
                )
                records.append(("sanction_add_alpha", (st_sanc, sanc_res.get("active"))))

            batch_txs = []
            # 精心构造前 6 笔覆盖：1跳直接命中、2跳桥接传染、3跳二级跳板传染、同批次内新边传染、滑窗中位数 3 倍突变、SOV_CB_ 主权央行豁免！
            special_txs = [
                # 1跳直接命中预置受制裁实体
                {
                    "tx_id": f"tx_b1_{slug}_sp1",
                    "account_id": f"acct_{slug}_med_01",
                    "counterparty_id": t_info["sanctioned_entity"],
                    "amount_cents": 40000,
                    "currency": "USD",
                    "channel": "WIRE_INTL",
                    "contact_email": f"sp1@{slug}-bank.com",
                    "ts": base_ts + 400,
                    "metadata": {"case": "hop1"},
                },
                # 2跳传染（对手方 bridge_{slug}_h1 在窗口内与受制裁实体交易过）
                {
                    "tx_id": f"tx_b1_{slug}_sp2",
                    "account_id": f"acct_{slug}_med_01",
                    "counterparty_id": f"bridge_{slug}_h1",
                    "amount_cents": 44000,
                    "currency": "USD",
                    "channel": "ACH_BATCH",
                    "contact_email": f"sp2@{slug}-bank.com",
                    "ts": base_ts + 410,
                    "metadata": {"case": "hop2"},
                },
                # 第 3 笔触发滑窗中位数 3 倍突变（前两笔 40000、44000，本笔 300000 -> 中位数 44000，300000 >= 3 * 44000！）且对手方 acct_{slug}_002 触发 3 跳传染！
                {
                    "tx_id": f"tx_b1_{slug}_sp3",
                    "account_id": f"acct_{slug}_med_01",
                    "counterparty_id": f"acct_{slug}_002",
                    "amount_cents": 300000,
                    "currency": "USD",
                    "channel": "CARD_CNP",
                    "contact_email": f"sp3@{slug}-bank.com",
                    "ts": base_ts + 420,
                    "metadata": {"case": "hop3_and_median_spike"},
                },
                # 第 4~6 笔构造多对手方扇出后，测试 SOV_CB_ 主权央行清算渠道减半与扇出豁免契约
                {
                    "tx_id": f"tx_b1_{slug}_sp4",
                    "account_id": f"acct_{slug}_med_01",
                    "counterparty_id": "cp_fan_a",
                    "amount_cents": 50000,
                    "currency": "EUR",
                    "channel": "WIRE_INTL",
                    "contact_email": f"sp4@{slug}-bank.com",
                    "ts": base_ts + 430,
                    "metadata": {},
                },
                {
                    "tx_id": f"tx_b1_{slug}_sp5",
                    "account_id": f"acct_{slug}_med_01",
                    "counterparty_id": "SOV_CB_ECB_SETTLE",
                    "amount_cents": 180000,
                    "currency": "EUR",
                    "channel": "WIRE_INTL",
                    "contact_email": f"sp5@{slug}-bank.com",
                    "ts": base_ts + 440,
                    "metadata": {"case": "sovereign_exempt"},
                },
            ]
            batch_txs.extend(special_txs)

            for k in range(14):
                acct = f"acct_{slug}_{(k % 3) + 1:03d}"
                batch_txs.append(
                    {
                        "tx_id": f"tx_b1_{slug}_{k + 1:03d}",
                        "account_id": acct,
                        "counterparty_id": f"cp_b1_{(k % 6) + 1:02d}",
                        "amount_cents": 65000 + rng.randint(1, 15) * 45000,
                        "currency": "USD",
                        "channel": channels[(k + t_i) % len(channels)],
                        "contact_email": f"ops.notify{k}@{slug}-bank.com",
                        "ts": base_ts + 500 + k * 35,
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
                    r["sanction_hop"],
                    r["window"]["tx_count"],
                    r["window"]["amount_cents"],
                    r["window"]["unique_counterparties"],
                    r["window"]["median_cents"],
                    tuple(r["reasons"]),
                )
                for r in (ev_res.get("results") or [])
            ]
            records.append((f"eval_batch_{tid}", (st_ev, ev_res.get("decision_counts"), ev_digest)))

            sample_dec = f"dec_tx_b1_{slug}_sp3"
            st_d, _, d_res = gw.request("GET", f"/api/v1/risk/decisions/{sample_dec}", headers=h_aud)
            records.append(
                (
                    f"decision_detail_{tid}",
                    (
                        st_d,
                        d_res.get("risk_score"),
                        d_res.get("decision"),
                        d_res.get("sanction_hop"),
                        d_res.get("window"),
                    ),
                )
            )

        # 7. 自定义布尔规则树试算
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
                {"field": "channel", "op": "REGEX", "value": "^CRYPTO_[A-Z]{2,10}$", "bonus_score": 19, "reason": "REGEX_CRYPTO"},
                {"amount_cents": 5000, "channel": "CRYPTO_BRIDGE", "contact_email": "x@y.io"},
            ),
        ]
        for rc_i, (rtree, stx) in enumerate(rule_cases):
            st_r, _, r_out = gw.request(
                "POST",
                "/api/v1/risk/simulate-rule",
                headers=h0_ana,
                body={"rule_tree": rtree, "sample_tx": stx},
            )
            records.append((f"sim_rule_{rc_i}", (st_r, r_out.get("matched"), r_out.get("bonus_score"), tuple(r_out.get("reasons") or []))))

        # 8. 配额扣减、跨池调拨（quotas/transfer）、单次令牌核销、Webhook 回调、报表模板保存与渲染、审计摘要与快照读取
        for tid in tenant_ids:
            t_info = manifest["tenants"][tid]
            h_adm = _headers(tid, t_info["users"]["admin"])

            st_q, _, q_out = gw.request(
                "POST",
                f"/api/v1/quotas/consume?_now_ts={base_ts + 700}",
                headers=h_adm,
                body={"quota_type": "EMERGENCY_EXPORT", "amount": 3},
            )
            records.append((f"quota_ok_{tid}", (st_q, q_out.get("accepted"), q_out.get("remaining_quota"))))

            st_tr_ok, _, tr_ok = gw.request(
                "POST",
                f"/api/v1/quotas/transfer?_now_ts={base_ts + 705}",
                headers=h_adm,
                body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": 18},
            )
            st_tr_no, _, tr_no = gw.request(
                "POST",
                f"/api/v1/quotas/transfer?_now_ts={base_ts + 706}",
                headers=h_adm,
                body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": 40},
            )
            records.append(
                (
                    f"quota_transfer_{tid}",
                    (
                        st_tr_ok,
                        tr_ok.get("transferred"),
                        tr_ok.get("from_remaining"),
                        tr_ok.get("to_remaining"),
                        st_tr_no,
                        tr_no.get("transferred"),
                    ),
                )
            )

            st_ov, _, ov_out = gw.request(
                "POST",
                f"/api/v1/risk/override-token/redeem?_now_ts={base_ts + 710}",
                headers=h_adm,
                body={"token_id": t_info["override_token"], "tx_ref": "tx_ref_01"},
            )
            records.append((f"override_ok_{tid}", (st_ov, ov_out.get("redeemed"))))

            wh_body = json.dumps({"settlement_ref": f"stl_{tid}_01", "amount_cents": 256000}, separators=(",", ":"))
            wh_ts = base_ts + 800
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

            st_tpl, _, _ = gw.request(
                "PUT",
                f"/api/v1/audit/report-template?_now_ts={base_ts + 720}",
                headers=h_adm,
                body={
                    "template_id": "tpl_risk_eval_check",
                    "title_format": "Tenant={tenant_id} Count={total_records} Sum={total_amount_cents}",
                    "extra_event_filter": "RISK_EVAL",
                    "sample_limit": 4,
                },
            )
            st_rep, _, rep_out = gw.request(
                "GET",
                f"/api/v1/audit/render-report?template_id=tpl_risk_eval_check&start_ts={base_ts - 90000}&end_ts={base_ts}",
                headers=h_adm,
            )
            rep_dig = rep_out.get("digest") or {}
            records.append(
                (
                    f"render_report_{tid}",
                    (
                        st_tpl,
                        st_rep,
                        rep_out.get("rendered_title"),
                        rep_dig.get("total_records"),
                        rep_dig.get("rolling_sha256"),
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
                        "expected_preview": str(exp_val)[:200],
                        "actual_preview": str(act_val)[:200],
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
    """测量单个工作区的 A1（混写+多维检索+三跳滑窗批评估）、A2（并发混合读写 P95/P99/全局锁检测）、A3（SQL/导出峰值/常驻堆预算）。"""
    wl = cfg["workload"]
    seed = int(wl["seed"]) + 777
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix="st_perf_"))
    sql_hook = SQLCounterHook()
    sql_hook.install()

    try:
        db_path = tmp_dir / "perf.db"
        storage_dir = tmp_dir / "storage"

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

        # 预热各租户一次轻量读取，消除首次打开 WAL 共享内存页的系统抖动，公平考核稳态与增量写入架构
        gw.request("GET", "/api/v1/health")
        for tid in tenant_ids:
            ti = manifest["tenants"][tid]
            gw.request(
                "GET",
                f"/api/v1/docs/search?q=wire&deduplicate=0&limit=5&_now_ts={base_ts + 40}",
                headers=_headers(tid, ti["users"]["auditor"]),
            )

        # ---------- 阶段一（关闭 tracemalloc 零钩子开销）：测量真实物理耗时 A1 / A2 与 SQL 执行计数 ----------
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
        num_upserts = int(wl.get("perf_interleaved_upserts", 6))
        upsert_every = max(2, num_queries // max(1, num_upserts))
        batch_size = int(wl["perf_batch_eval_size"])
        channels = ["WIRE_INTL", "CRYPTO_BRIDGE", "CARD_CNP", "ACH_BATCH", "POS_CHIP"]

        batches_by_tenant: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        for b_idx, tid in enumerate(tenant_ids[:2]):
            t_info = manifest["tenants"][tid]
            slug = t_info["slug"]
            tx_list = []
            for k in range(batch_size):
                acct = f"acct_{slug}_{(k % 20) + 1:03d}"
                cp = f"bridge_{slug}_h1" if (k % 9 == 0) else (
                    f"SOV_CB_BIS_{k % 3}" if (k % 11 == 0) else f"cp_p_{(k % 30) + 1:02d}"
                )
                tx_list.append(
                    {
                        "tx_id": f"tx_perf_a1_{slug}_{b_idx}_{k:04d}",
                        "account_id": acct,
                        "counterparty_id": cp,
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

        upsert_seq = 0
        for q_i in range(num_queries):
            tid = tenant_ids[q_i % len(tenant_ids)]
            t_info = manifest["tenants"][tid]
            slug = t_info["slug"]

            if q_i > 0 and (q_i % upsert_every == 0) and upsert_seq < num_upserts:
                upsert_seq += 1
                st_u, _, _ = gw.request(
                    "POST",
                    f"/api/v1/docs/upsert?_now_ts={base_ts + 50 + upsert_seq}",
                    headers=_headers(tid, t_info["users"]["admin"]),
                    body={
                        "doc_id": f"doc_{slug}_a1_live_{upsert_seq:03d}",
                        "category": "AML",
                        "regulation_code": "FATF-REC-16",
                        "clearance_level": 2,
                        "risk_weight": 22 + upsert_seq,
                        "custom_tag": "tag_aml_1",
                        "title": f"[FATF-REC-16] Live Directive Update {upsert_seq}",
                        "body": (
                            f"wire transfer beneficiary verification thresholds settlement clearing "
                            f"escrow reconciliation live revision {upsert_seq}."
                        ),
                        "updated_at": base_ts + 50 + upsert_seq,
                    },
                )
                if st_u != 200:
                    raise RuntimeError(f"A1 interleaved upsert failed with status {st_u}")

            role = "admin" if (q_i % 4 == 0) else ("auditor" if q_i % 4 == 1 else ("specialist" if q_i % 4 == 2 else "analyst"))
            phrase = search_phrases[q_i % len(search_phrases)]
            dedup = "1" if (q_i % 5 != 0) else "0"
            sort_f = "score" if (q_i % 2 == 0) else "risk_weight"
            st, _, _ = gw.request(
                "GET",
                f"/api/v1/docs/search?q={phrase.replace(' ', '+')}&deduplicate={dedup}&sort_by={sort_f}&limit=20&_now_ts={base_ts + 80}",
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

        # ---------- A2：12 路高并发混合读写（含实时 Upsert 与双向配额调拨）、P95/P99 尾延迟与跨租户全局大锁检测 ----------
        baseline_read_samples_ms: list[float] = []
        for i in range(16):
            tid = tenant_ids[i % 2]
            ti = manifest["tenants"][tid]
            phrase = search_phrases[i % len(search_phrases)].replace(" ", "+")
            t0_r = time.perf_counter()
            gw.request(
                "GET",
                f"/api/v1/docs/search?q={phrase}&deduplicate=1&limit=15&_now_ts={base_ts + 90}",
                headers=_headers(tid, ti["users"]["auditor"]),
            )
            baseline_read_samples_ms.append((time.perf_counter() - t0_r) * 1000.0)
        solo_read_median_ms = max(0.15, statistics.median(baseline_read_samples_ms))

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
                w_tid = tenant_ids[(w_id + step) % len(tenant_ids)]
                w_info = manifest["tenants"][w_tid]
                w_slug = w_info["slug"]

                if w_id >= (n_threads * 3 // 4) and (step % 3 == 0):
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
                        for m in range(6)
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
                elif w_id >= (n_threads * 3 // 4) and (step % 3 == 1):
                    # 混合实时文档修订与跨池调拨
                    if step % 2 == 1:
                        st_u, _, _ = gw.request(
                            "POST",
                            f"/api/v1/docs/upsert?_now_ts={base_ts + 2500 + step}",
                            headers=_headers(w_tid, w_info["users"]["admin"]),
                            body={
                                "doc_id": f"doc_{w_slug}_conc_{w_id}_{step}",
                                "category": "SANCTIONS",
                                "regulation_code": "OFAC-50PCT",
                                "clearance_level": 2,
                                "risk_weight": 20,
                                "custom_tag": "tag_sanctions_1",
                                "title": f"Concurrent Sanctions Notice {w_id}-{step}",
                                "body": "blocked entity vessel embargo screening live concurrent update.",
                                "updated_at": base_ts + 2500 + step,
                            },
                        )
                        if st_u != 200:
                            with lat_lock:
                                errors_cnt += 1
                    else:
                        src_q, dst_q = (
                            ("RESERVE_BUFFER_POOL", "REALTIME_ALERT_POOL")
                            if w_id % 2 == 0
                            else ("REALTIME_ALERT_POOL", "RESERVE_BUFFER_POOL")
                        )
                        st_tr, _, _ = gw.request(
                            "POST",
                            "/api/v1/quotas/transfer",
                            headers=_headers(w_tid, w_info["users"]["admin"]),
                            body={"from_quota": src_q, "to_quota": dst_q, "amount": 2},
                        )
                        if st_tr not in (200, 409):
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
                            f"/api/v1/docs/search?q={ph}&deduplicate=1&limit=15&_now_ts={base_ts + 95}",
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
        p99_idx = min(len(sorted_reads) - 1, max(0, int(len(sorted_reads) * 0.99)))
        conc_read_p95_ms = sorted_reads[p95_idx]
        conc_read_p99_ms = sorted_reads[p99_idx]

        # 步骤 A2-3：跨租户全局大锁串行退化探针
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
                gw.request(
                    "GET",
                    f"/api/v1/docs/search?q={ph}&deduplicate=1&limit=10&_now_ts={base_ts + 95}",
                    headers=hdr,
                )
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
        cross_block_ratio = probe_p80_ms / max(0.5, solo_read_median_ms)

        # ---------- 阶段二（独立开启 tracemalloc 测量常驻堆内存预算与流式导出峰值，绝不干扰阶段一计时） ----------
        del gw
        _, cand_server_fresh = load_app_from_workspace(workspace_dir)
        gc.collect()
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        tracemalloc.start()

        gw_mem = cand_server_fresh.create_gateway(db_path, storage_dir)
        for tid in tenant_ids:
            ti = manifest["tenants"][tid]
            gw_mem.request(
                "GET",
                f"/api/v1/docs/search?q=wire+transfer+beneficiary&deduplicate=1&limit=15&_now_ts={base_ts + 95}",
                headers=_headers(tid, ti["users"]["auditor"]),
            )
        gc.collect()
        retained_bytes, _ = tracemalloc.get_traced_memory()
        resident_heap_mb = retained_bytes / (1024.0 * 1024.0)

        pre_export_bytes, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        for tid in tenant_ids:
            ti = manifest["tenants"][tid]
            st1, _, _ = gw_mem.request(
                "GET",
                "/api/v1/audit/export-digest?sample_limit=10",
                headers=_headers(tid, ti["users"]["auditor"]),
            )
            st2, _, _ = gw_mem.request(
                "GET",
                "/api/v1/audit/render-report?template_id=tpl_default_q4",
                headers=_headers(tid, ti["users"]["auditor"]),
            )
            if st1 != 200 or st2 != 200:
                raise RuntimeError(f"A3 audit export/render failed with statuses {st1}, {st2}")
        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_kb = max(1.0, (peak_bytes - pre_export_bytes) / 1024.0)

        return {
            "a1_elapsed_sec": a1_elapsed_sec,
            "sql_count": sql_executed_count,
            "peak_kb": peak_kb,
            "resident_heap_mb": resident_heap_mb,
            "concurrent_rps": concurrent_rps,
            "concurrent_read_p95_ms": conc_read_p95_ms,
            "concurrent_read_p99_ms": conc_read_p99_ms,
            "solo_read_median_ms": solo_read_median_ms,
            "probe_read_p80_ms": probe_p80_ms,
            "cross_tenant_block_ratio": cross_block_ratio,
            "error_rate": errors_cnt / max(1, total_ops),
        }
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        sql_hook.uninstall()
        shutil.rmtree(tmp_dir, ignore_errors=True)


_CACHED_BASE_PERF: dict[str, dict[str, Any]] = {}


def run_performance_benchmark(
    template_dir: pathlib.Path,
    candidate_dir: pathlib.Path,
    cfg: dict[str, Any],
) -> dict[str, Any]:
    """同机测量初始未优化模板与被测沙盒的性能对比指标。"""
    tpl_sig = hashlib.sha256((template_dir / "aegis_app" / "server.py").read_bytes()).hexdigest()[:12]
    cache_key = hashlib.sha256(
        (tpl_sig + ":" + json.dumps(cfg["workload"], sort_keys=True)).encode("utf-8")
    ).hexdigest()[:16]
    cal_file = pathlib.Path(tempfile.gettempdir()) / f"st_base_cal_v22_{cache_key}.json"
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

    gc.collect()
    time.sleep(0.05)
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
        "a2_concurrent_read_p99_ms": cand_m["concurrent_read_p99_ms"],
        "a2_probe_read_p80_ms": cand_m["probe_read_p80_ms"],
        "a2_cross_tenant_block_ratio": cand_m["cross_tenant_block_ratio"],
        "a2_error_rate": cand_m["error_rate"],
        "a3_sql_reduction_ratio": sql_red,
        "a3_mem_reduction_ratio": mem_red,
        "a3_resident_heap_mb": cand_m["resident_heap_mb"],
    }
