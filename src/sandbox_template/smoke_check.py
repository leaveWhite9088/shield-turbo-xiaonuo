#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公开基础业务功能回归冒烟测试（smoke_check.py）。

说明：
本脚本仅在小规模样本数据上检验 AegisGate 核心业务接口的基础功能正确性与 HTTP 协议可用性，
帮助确认重构未破坏正常业务逻辑。本脚本不包含大规模性能压测，也不包含红队安全攻防测试。
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
    tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="aegis_smoke_"))
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

        gw = create_gateway(db_path, storage_dir)

        # 1. 健康探针
        st, _, body = gw.request("GET", "/api/v1/health")
        assert st == 200 and body.get("status") == "ok", f"Health check failed: {st} {body}"

        t_alpha = manifest["tenants"]["tenant_alpha"]
        h_admin = _auth_headers("tenant_alpha", t_alpha["users"]["admin"])
        h_auditor = _auth_headers("tenant_alpha", t_alpha["users"]["auditor"])
        h_analyst = _auth_headers("tenant_alpha", t_alpha["users"]["analyst"])
        h_researcher = _auth_headers("tenant_alpha", t_alpha["users"]["researcher"])

        # 2. 合规文档检索、密级与利益冲突隔离墙（Chinese Wall）基础校验
        st, _, s_admin = gw.request(
            "GET",
            "/api/v1/docs/search?q=wire+transfer+screening&deduplicate=1&limit=10",
            headers=h_admin,
        )
        assert st == 200 and s_admin["returned_count"] >= 1, f"Admin search failed: {st} {s_admin}"

        st, _, s_analyst = gw.request(
            "GET",
            "/api/v1/docs/search?q=classified+board+resolution&deduplicate=1",
            headers=h_analyst,
        )
        assert st == 200, f"Analyst search status error: {st}"
        for item in s_analyst["items"]:
            assert item["clearance_level"] <= 2, f"Analyst saw high clearance doc: {item}"

        # 验证利益冲突墙：doc_alpha_0003 对 ops_team(analyst) 封禁，但对同密级的 research_desk(researcher) 可见
        wall_doc_id = t_alpha["wall_doc_id"]
        _, _, s_res_wall = gw.request(
            "GET",
            "/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0",
            headers=h_researcher,
        )
        _, _, s_ana_wall = gw.request(
            "GET",
            "/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0",
            headers=h_analyst,
        )
        assert any(d["doc_id"] == wall_doc_id for d in s_res_wall["items"]), "Researcher should see deal doc"
        assert all(d["doc_id"] != wall_doc_id for d in s_ana_wall["items"]), "Analyst blocked by Chinese Wall"

        # 3. 批量读取授权文档
        visible_id = s_admin["items"][0]["doc_id"]
        st, _, b_res = gw.request(
            "POST",
            "/api/v1/docs/batch-get",
            headers=h_admin,
            body={"doc_ids": [visible_id]},
        )
        assert st == 200 and b_res["found"] == 1, f"Batch get failed: {st} {b_res}"

        # 4. 文档隔离与恢复
        st, _, q_res = gw.request(
            "POST",
            "/api/v1/docs/quarantine",
            headers=h_admin,
            body={"doc_id": visible_id, "quarantined": True},
        )
        assert st == 200 and q_res["quarantined"] is True
        st, _, s_after_q = gw.request(
            "GET",
            "/api/v1/docs/search?q=wire+transfer+screening&deduplicate=0&limit=50",
            headers=h_admin,
        )
        assert all(d["doc_id"] != visible_id for d in s_after_q["items"]), "Quarantined doc still returned"
        gw.request(
            "POST",
            "/api/v1/docs/quarantine",
            headers=h_admin,
            body={"doc_id": visible_id, "quarantined": False},
        )

        # 5. 角色授权管理
        st, _, g_res = gw.request(
            "POST",
            "/api/v1/admin/grants/revoke",
            headers=h_admin,
            body={"user_id": t_alpha["users"]["auditor"]["user_id"], "role": "SENIOR_AUDITOR", "action": "revoke"},
        )
        assert st == 200 and g_res["effective_clearance"] == 3  # 仍由 audit_dept 节点继承 SENIOR_AUDITOR(3)
        gw.request(
            "POST",
            "/api/v1/admin/grants/revoke",
            headers=h_admin,
            body={"user_id": t_alpha["users"]["auditor"]["user_id"], "role": "SENIOR_AUDITOR", "action": "grant"},
        )

        # 6. 实时交易批次评估与单笔查询
        base_ts = manifest["base_ts"]
        batch_payload = {
            "batch_id": "batch_smoke_01",
            "transactions": [
                {
                    "tx_id": "tx_smoke_001",
                    "account_id": "acct_alpha_001",
                    "counterparty_id": "cp_901",
                    "amount_cents": 120000,
                    "currency": "USD",
                    "channel": "ACH_BATCH",
                    "contact_email": "treasury.ops@alpha-corp.com",
                    "ts": base_ts + 120,
                    "metadata": {"region": "US"},
                },
                {
                    "tx_id": "tx_smoke_002",
                    "account_id": "acct_alpha_001",
                    "counterparty_id": "cp_902",
                    "amount_cents": 620000,
                    "currency": "USD",
                    "channel": "CRYPTO_BRIDGE",
                    "contact_email": "settlement-desk@alpha-corp.com",
                    "ts": base_ts + 180,
                    "metadata": {"region": "SG"},
                },
            ],
        }
        st, _, eval_res = gw.request(
            "POST",
            "/api/v1/risk/evaluate-batch",
            headers=h_auditor,
            body=batch_payload,
        )
        assert st == 200 and eval_res["evaluated_count"] == 2, f"Batch evaluate failed: {st} {eval_res}"
        dec_id = eval_res["results"][1]["decision_id"]
        assert eval_res["results"][1]["window"]["tx_count"] >= 2

        st, _, dec_detail = gw.request(
            "GET",
            f"/api/v1/risk/decisions/{dec_id}",
            headers=h_auditor,
        )
        assert st == 200 and dec_detail["tx_id"] == "tx_smoke_002"

        # 7. 规则沙盒试算
        st, _, sim_res = gw.request(
            "POST",
            "/api/v1/risk/simulate-rule",
            headers=h_analyst,
            body={
                "rule_tree": {
                    "op": "AND",
                    "bonus_score": 15,
                    "reason": "TEST_RULE",
                    "children": [
                        {"field": "channel", "op": "EQ", "value": "WIRE_INTL"},
                        {"field": "amount_cents", "op": "GT", "value": 50000},
                    ],
                },
                "sample_tx": {
                    "channel": "WIRE_INTL",
                    "amount_cents": 100000,
                    "contact_email": "valid.user@bank-domain.org",
                },
            },
        )
        assert st == 200 and sim_res["matched"] is True and sim_res["bonus_score"] == 15

        # 8. 配额扣减与单次应急令牌核销
        st, _, q_consume = gw.request(
            "POST",
            "/api/v1/quotas/consume",
            headers=h_admin,
            body={"quota_type": "EMERGENCY_EXPORT", "amount": 2},
        )
        assert st == 200 and q_consume["accepted"] is True and q_consume["remaining_quota"] == 3

        ov_tok = t_alpha["override_token"]
        st1, _, r1 = gw.request(
            "POST",
            "/api/v1/risk/override-token/redeem",
            headers=h_admin,
            body={"token_id": ov_tok, "tx_ref": "tx_smoke_002"},
        )
        st2, _, r2 = gw.request(
            "POST",
            "/api/v1/risk/override-token/redeem",
            headers=h_admin,
            body={"token_id": ov_tok, "tx_ref": "tx_smoke_002"},
        )
        assert st1 == 200 and r1["redeemed"] is True
        assert st2 == 409 and r2["redeemed"] is False

        # 9. Webhook 正常签名入账
        wh_body = json.dumps({"settlement_ref": "stl_smoke_01", "amount_cents": 88000}, separators=(",", ":"))
        wh_ts = base_ts + 200
        wh_nonce = "nonce_smoke_unique_001"
        sig_msg = f"tenant_alpha.{wh_ts}.{wh_nonce}.{wh_body}"
        sig_hex = hmac.new(
            t_alpha["webhook_secret"].encode("utf-8"),
            sig_msg.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        st, _, wh_res = gw.request(
            "POST",
            f"/api/v1/webhooks/settlement-callback?_now_ts={wh_ts + 5}",
            headers={
                "X-Aegis-Tenant": "tenant_alpha",
                "X-Aegis-Timestamp": str(wh_ts),
                "X-Aegis-Nonce": wh_nonce,
                "X-Aegis-Signature": f"sha256={sig_hex}",
            },
            body=wh_body,
        )
        assert st == 200 and wh_res["acknowledged"] is True

        # 10. 审计流水摘要与合规季度快照读取
        st, _, dig_res = gw.request(
            "GET",
            "/api/v1/audit/export-digest?sample_limit=5",
            headers=h_auditor,
        )
        assert st == 200 and dig_res["total_records"] >= 30 and len(dig_res["rolling_sha256"]) == 64

        st, _, snap_res = gw.request(
            "GET",
            "/api/v1/audit/snapshots?snapshot_name=2026-Q3.json",
            headers=h_auditor,
        )
        assert st == 200 and snap_res["data"]["period"] == "2026-Q3"

        # 11. 真实 HTTP Socket 端到端冒烟验证
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

        print("[PASS] AegisGate 基础业务功能冒烟自检全部通过（共 11 项核心回归检查）。")
        return 0
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(run_smoke())
