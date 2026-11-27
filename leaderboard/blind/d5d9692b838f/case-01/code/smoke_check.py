#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公开基础业务功能回归冒烟测试（smoke_check.py · v3.0）。

说明：仅在小规模样本上检验核心业务路由与跨模块契约的基础功能正确性，不包含高压性能压测与红队安全攻防载荷。
"""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import threading
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from aegis_app.db import seed_dataset  # noqa: E402
from aegis_app.server import build_http_server, create_gateway  # noqa: E402


def _auth_headers(tenant_id: str, user_info: dict[str, str]) -> dict[str, str]:
    return {
        "X-Aegis-Tenant": tenant_id,
        "X-Aegis-User": user_info["user_id"],
        "X-Aegis-Token": user_info["token"],
    }


def run_smoke() -> int:
    tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="aegis_smoke_v3_"))
    try:
        db_path = tmp_root / "smoke.db"
        storage_dir = tmp_root / "storage"
        manifest = seed_dataset(
            db_path,
            storage_dir,
            seed=20261126,
            num_tenants=2,
            docs_per_tenant=16,
            tx_per_tenant=24,
            audit_rows_per_tenant=30,
        )
        base_ts = int(manifest["base_ts"])
        gw = create_gateway(db_path, storage_dir)

        st, _, body = gw.request("GET", "/api/v1/health")
        assert st == 200 and body.get("status") == "ok"

        t_alpha = manifest["tenants"]["tenant_alpha"]
        h_admin = _auth_headers("tenant_alpha", t_alpha["users"]["admin"])
        h_auditor = _auth_headers("tenant_alpha", t_alpha["users"]["auditor"])
        h_analyst = _auth_headers("tenant_alpha", t_alpha["users"]["analyst"])
        h_specialist = _auth_headers("tenant_alpha", t_alpha["users"]["specialist"])
        h_researcher = _auth_headers("tenant_alpha", t_alpha["users"]["researcher"])

        # 1. 合规检索、词距邻近度与三级隔离墙（ops_team DENY，子部门 ops_special ALLOW）
        wall_doc_id = t_alpha["wall_doc_id"]
        _, _, s_spec = gw.request(
            "GET",
            f"/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0&_now_ts={base_ts + 10}",
            headers=h_specialist,
        )
        _, _, s_ana = gw.request(
            "GET",
            f"/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0&_now_ts={base_ts + 10}",
            headers=h_analyst,
        )
        assert any(d["doc_id"] == wall_doc_id for d in s_spec["items"]), "Sub-unit ALLOW should override parent DENY"
        assert all(d["doc_id"] != wall_doc_id for d in s_ana["items"]), "Parent ops_team DENY should block analyst"

        # 2. 实时文档 Upsert、跨文档有效引用联动（隔离源文档自动剥离引用）与二级转借调时效窗口核验
        st_up, _, up_res = gw.request(
            "POST",
            f"/api/v1/docs/upsert?_now_ts={base_ts + 20}",
            headers=h_auditor,
            body={
                "doc_id": "doc_alpha_live_01",
                "category": "AML",
                "regulation_code": "FATF-R16",
                "clearance_level": 3,
                "risk_weight": 20,
                "custom_tag": "tag_live",
                "title": "Live Streaming AML Guidance",
                "body": "wire transfer travel rule live streaming incremental index verification",
                "citations": ["ref_live_1", "doc_alpha_0002"],
            },
        )
        assert st_up == 200 and up_res["operation"] == "created"

        # researcher（1跳借调）与 specialist（在 base_ts+300 处于 2跳有效借调窗内）均能检索密级 3 文档且包含 2 条有效引用
        _, _, s_del1 = gw.request(
            "GET",
            f"/api/v1/docs/search?q=incremental+index+verification&deduplicate=0&_now_ts={base_ts + 30}",
            headers=h_researcher,
        )
        live_hit_1 = [d for d in s_del1["items"] if d["doc_id"] == "doc_alpha_live_01"]
        assert len(live_hit_1) == 1 and live_hit_1[0]["citation_count"] == 2

        _, _, s_del2 = gw.request(
            "GET",
            f"/api/v1/docs/search?q=incremental+index+verification&deduplicate=0&_now_ts={base_ts + 300}",
            headers=h_specialist,
        )
        assert any(d["doc_id"] == "doc_alpha_live_01" for d in s_del2["items"]), "2-hop transitive delegation should grant clearance 3"

        # 在 base_ts+7500 时，虽然 specialist 自身二级借调窗 [+200, +9000) 未到期，但上游 researcher 一级借调窗 [-3600, +7200) 已到期，须自动降级
        _, _, s_del2_exp = gw.request(
            "GET",
            f"/api/v1/docs/search?q=live+streaming+incremental+index&deduplicate=1&_now_ts={base_ts + 7500}",
            headers=h_specialist,
        )
        assert all(d["doc_id"] != "doc_alpha_live_01" for d in s_del2_exp["items"]), "Expired upstream hop-1 must invalidate hop-2"

        # 隔离内部引用源 doc_alpha_0002 后，doc_alpha_live_01 的有效引用计数须立即从 2 降为 1；解封后恢复为 2
        gw.request(
            "POST",
            f"/api/v1/docs/quarantine?_now_ts={base_ts + 35}",
            headers=h_admin,
            body={"doc_id": "doc_alpha_0002", "quarantined": True},
        )
        _, _, s_q_on = gw.request(
            "GET",
            f"/api/v1/docs/search?q=incremental+index+verification&deduplicate=0&_now_ts={base_ts + 36}",
            headers=h_auditor,
        )
        assert [d for d in s_q_on["items"] if d["doc_id"] == "doc_alpha_live_01"][0]["citation_count"] == 1

        gw.request(
            "POST",
            f"/api/v1/docs/quarantine?_now_ts={base_ts + 37}",
            headers=h_admin,
            body={"doc_id": "doc_alpha_0002", "quarantined": False},
        )
        st_ret, _, _ = gw.request(
            "POST",
            f"/api/v1/docs/retire?_now_ts={base_ts + 40}",
            headers=h_admin,
            body={"doc_id": "doc_alpha_live_01"},
        )
        assert st_ret == 200

        # 3. 实时风控批次评估（含精确中位数、三跳受制裁传染、主权豁免与高危 REJECT 实时告警配额联动）
        batch_payload = {
            "batch_id": "batch_smoke_v3",
            "transactions": [
                {
                    "tx_id": "tx_smk_1",
                    "account_id": "acct_alpha_002",
                    "counterparty_id": "cp_901",
                    "amount_cents": 120000,
                    "currency": "USD",
                    "channel": "WIRE_INTL",
                    "contact_email": "treasury.ops@alpha-corp.com",
                    "ts": base_ts + 120,
                    "metadata": {"region": "US"},
                },
                {
                    "tx_id": "tx_smk_2",
                    "account_id": "acct_alpha_001",
                    "counterparty_id": "SOV_CB_BIS_01",
                    "amount_cents": 300000,
                    "currency": "EUR",
                    "channel": "WIRE_INTL",
                    "contact_email": "cb.desk@alpha-corp.com",
                    "ts": base_ts + 150,
                    "metadata": {"region": "EU"},
                },
                {
                    "tx_id": "tx_smk_3_reject",
                    "account_id": "acct_alpha_001",
                    "counterparty_id": t_alpha["sanctioned_entity"],
                    "amount_cents": 600000,
                    "currency": "USD",
                    "channel": "CRYPTO_BRIDGE",
                    "contact_email": "alert.desk@alpha-corp.com",
                    "ts": base_ts + 160,
                    "metadata": {"region": "US"},
                },
            ],
        }
        st_ev, _, ev_res = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_auditor,
            body=batch_payload,
        )
        assert st_ev == 200 and ev_res["evaluated_count"] == 3
        assert ev_res["results"][0]["sanction_hop"] == 3 and ev_res["results"][0]["alert_dispatched"] is False
        assert "LEGACY_SOVEREIGN_EXEMPT" in ev_res["results"][1]["reasons"]
        assert ev_res["results"][2]["decision"] == "REJECT" and ev_res["results"][2]["alert_dispatched"] is True
        assert "ALERT_QUOTA_CONSUMED" in ev_res["results"][2]["reasons"]
        assert "median_cents" in ev_res["results"][0]["window"]

        # 4. 跨池配额调拨（REALTIME_ALERT_POOL 刚才被 REJECT 扣了 1 点剩 49，调入 10 点后为 59）
        st_tr, _, tr_res = gw.request(
            "POST",
            "/api/v1/quotas/transfer",
            headers=h_admin,
            body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": 10},
        )
        assert st_tr == 200 and tr_res["transferred"] is True and tr_res["from_remaining"] == 40 and tr_res["to_remaining"] == 59

        # 5. 自定义审计报表模板保存与渲染
        st_tp, _, _ = gw.request(
            "PUT",
            "/api/v1/audit/report-template",
            headers=h_auditor,
            body={
                "template_id": "tpl_smoke_1",
                "title_format": "Report for {tenant_id}: {total_records} logs",
                "extra_event_filter": "RISK_EVAL",
                "sample_limit": 3,
            },
        )
        assert st_tp == 200
        st_rn, _, rn_res = gw.request(
            "GET",
            "/api/v1/audit/render-report?template_id=tpl_smoke_1",
            headers=h_auditor,
        )
        assert st_rn == 200 and rn_res["rendered_title"].startswith("Report for tenant_alpha:")

        # 6. HTTP Socket 端到端联通验证
        srv = build_http_server(gw, host="127.0.0.1", port=0)
        port = srv.server_address[1]
        t_srv = threading.Thread(target=srv.serve_forever, daemon=True)
        t_srv.start()
        try:
            req = urllib.request.Request(f"htt<REDACTED_PATH>", method="GET")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                http_data = json.loads(resp.read().decode("utf-8"))
                assert resp.status == 200 and http_data.get("status") == "ok"
        finally:
            srv.shutdown()
            srv.server_close()

        print("[PASS] AegisGate v3.0 基础业务功能冒烟自检全部通过。")
        return 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(run_smoke())
