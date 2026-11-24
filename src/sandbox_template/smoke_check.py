#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公开基础业务功能回归冒烟测试（smoke_check.py · v2.0）。

说明：仅在小规模样本上检验核心业务路由的基础功能正确性，不包含高压性能压测与红队安全攻防载荷。
"""
from __future__ import annotations

import hashlib
import hmac
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
    tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="aegis_smoke_v2_"))
    try:
        db_path = tmp_root / "smoke.db"
        storage_dir = tmp_root / "storage"
        manifest = seed_dataset(
            db_path,
            storage_dir,
            seed=20261122,
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

        # 合规检索、词距邻近度与三级隔离墙（ops_team DENY，子部门 ops_special ALLOW）
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

        # 实时文档 Upsert 与 Retire
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
                "citations": ["ref_live_1"],
            },
        )
        assert st_up == 200 and up_res["operation"] == "created"
        # researcher 在有效借调期内拥有 SENIOR_AUDITOR(3)，应当能搜到这篇密级 3 文档
        _, _, s_del = gw.request(
            "GET",
            f"/api/v1/docs/search?q=incremental+index+verification&_now_ts={base_ts + 30}",
            headers=h_researcher,
        )
        assert any(d["doc_id"] == "doc_alpha_live_01" for d in s_del["items"])

        st_ret, _, _ = gw.request(
            "POST",
            f"/api/v1/docs/retire?_now_ts={base_ts + 40}",
            headers=h_admin,
            body={"doc_id": "doc_alpha_live_01"},
        )
        assert st_ret == 200

        # 实时风控批次评估（含精确中位数、三跳受制裁实体传染与主权豁免）
        batch_payload = {
            "batch_id": "batch_smoke_v2",
            "transactions": [
                {
                    "tx_id": "tx_smk_1",
                    "account_id": "acct_alpha_002",  # 种子中距离制裁实体 2 跳 -> 本笔交易关联后应命中跳数传染
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
            ],
        }
        st_ev, _, ev_res = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_auditor,
            body=batch_payload,
        )
        assert st_ev == 200 and ev_res["evaluated_count"] == 2
        assert ev_res["results"][0]["sanction_hop"] == 3
        assert "LEGACY_SOVEREIGN_EXEMPT" in ev_res["results"][1]["reasons"]
        assert "median_cents" in ev_res["results"][0]["window"]

        # 跨池配额调拨
        st_tr, _, tr_res = gw.request(
            "POST",
            "/api/v1/quotas/transfer",
            headers=h_admin,
            body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": 10},
        )
        assert st_tr == 200 and tr_res["transferred"] is True and tr_res["from_remaining"] == 40 and tr_res["to_remaining"] == 60

        # 自定义审计报表模板保存与渲染
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

        # HTTP Socket 端到端联通验证
        srv = build_http_server(gw, host="127.0.0.1", port=0)
        port = srv.server_address[1]
        t_srv = threading.Thread(target=srv.serve_forever, daemon=True)
        t_srv.start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/health", method="GET")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                http_data = json.loads(resp.read().decode("utf-8"))
                assert resp.status == 200 and http_data.get("status") == "ok"
        finally:
            srv.shutdown()
            srv.server_close()

        print("[PASS] AegisGate v2.0 基础业务功能冒烟自检全部通过。")
        return 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(run_smoke())
