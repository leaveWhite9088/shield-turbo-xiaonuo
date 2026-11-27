# -*- coding: utf-8 -*-
"""AegisGate HTTP 路由网关与嵌入式应用入口（18 路由纵深安全加固版）。"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import pathlib
from typing import Any

from . import __version__
from .audit_export import (
    export_audit_digest,
    read_compliance_snapshot,
    render_saved_report,
    save_report_template,
)
from .auth import (
    AuthError,
    authenticate_caller,
    configure_doc_acl_rule,
    manage_role_delegation,
    process_settlement_webhook,
    revoke_or_grant_role,
)
from .config import DEFAULT_PAGE_LIMIT, MAX_JSON_BODY_BYTES, MAX_SAFE_TS
from .contagion_graph import manage_sanctioned_entity
from .db import init_schema
from .doc_writer import retire_compliance_document, upsert_compliance_document
from .ledger_ops import (
    consume_tenant_quota,
    redeem_override_token,
    transfer_tenant_quota,
)
from .middleware import (
    parse_json_payload,
    parse_url_and_query,
    strict_int,
)
from .rule_engine import (
    evaluate_transaction_batch,
    get_risk_decision_detail,
    simulate_custom_rule,
    update_tenant_policy,
)
from .search_service import (
    batch_get_documents,
    search_documents,
    set_document_quarantine,
)


class AegisGateway:
    """多租户风控与合规检索统一网关实例。"""

    def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self.storage_dir = str(pathlib.Path(storage_dir).resolve())
        init_schema(self.db_path)

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        """处理一次网关调用，返回 (status_code, response_headers, response_json_dict)。"""
        resp_headers = {"Content-Type": "application/json; charset=utf-8"}

        try:
            req_method = str(method or "").upper().strip()
            route, query_params = parse_url_and_query(path)
            req_headers = dict(headers or {})

            if req_method == "GET" and route == "/api/v1/health":
                return (
                    200,
                    resp_headers,
                    {
                        "status": "ok",
                        "service": "aegis-gateway",
                        "version": __version__,
                    },
                )

            now_ov_str = query_params.get("_now_ts")
            now_ov = (
                strict_int(now_ov_str, "_now_ts", min_val=0, max_val=MAX_SAFE_TS, allow_str=True)
                if now_ov_str not in (None, "")
                else None
            )

            if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
                _, raw_body = parse_json_payload(body)
                res = process_settlement_webhook(
                    self.db_path,
                    req_headers,
                    raw_body,
                    now_override=now_ov,
                )
                return 200, resp_headers, res

            caller = authenticate_caller(self.db_path, req_headers, now_override=now_ov)

            if req_method == "GET" and route == "/api/v1/docs/search":
                q = query_params.get("q", "")
                category = query_params.get("category", "")
                tag_filter = query_params.get("tag_filter", "")
                dedup_raw = query_params.get("deduplicate", "1").strip().lower()
                dedup_flag = dedup_raw not in ("0", "false")
                sort_by = query_params.get("sort_by", "score")
                sort_dir = query_params.get("sort_dir", "desc")
                limit_str = query_params.get("limit")
                limit = (
                    DEFAULT_PAGE_LIMIT
                    if limit_str in (None, "")
                    else strict_int(limit_str, "limit", allow_str=True)
                )
                offset_str = query_params.get("offset")
                offset = (
                    0
                    if offset_str in (None, "")
                    else strict_int(offset_str, "offset", allow_str=True)
                )
                res = search_documents(
                    self.db_path,
                    caller,
                    query=q,
                    category=category,
                    tag_filter=tag_filter,
                    deduplicate=dedup_flag,
                    sort_by=sort_by,
                    sort_dir=sort_dir,
                    limit=limit,
                    offset=offset,
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/upsert":
                data, _ = parse_json_payload(body)
                res = upsert_compliance_document(self.db_path, caller, data)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/retire":
                data, _ = parse_json_payload(body)
                res = retire_compliance_document(self.db_path, caller, str(data.get("doc_id") or ""))
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/batch-get":
                data, _ = parse_json_payload(body)
                res = batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/quarantine":
                data, _ = parse_json_payload(body)
                res = set_document_quarantine(
                    self.db_path,
                    caller,
                    doc_id=str(data.get("doc_id") or ""),
                    quarantined=data.get("quarantined", True),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
                data, _ = parse_json_payload(body)
                res = revoke_or_grant_role(
                    self.db_path,
                    caller,
                    target_user_id=str(data.get("user_id") or ""),
                    role_name=str(data.get("role") or ""),
                    action=str(data.get("action") or "revoke"),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/delegations":
                data, _ = parse_json_payload(body)
                res = manage_role_delegation(
                    self.db_path,
                    caller,
                    grantor_user_id=str(data.get("grantor_user_id") or caller.user_id),
                    grantee_user_id=str(data.get("grantee_user_id") or ""),
                    delegated_role=str(data.get("delegated_role") or ""),
                    starts_at=data.get("starts_at", 0),
                    expires_at=data.get("expires_at", 0),
                    action=str(data.get("action") or "create"),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
                data, _ = parse_json_payload(body)
                res = configure_doc_acl_rule(
                    self.db_path,
                    caller,
                    doc_id=str(data.get("doc_id") or ""),
                    subject_type=str(data.get("subject_type") or ""),
                    subject_id=str(data.get("subject_id") or ""),
                    effect=str(data.get("effect") or "DENY"),
                    active=data.get("active", True),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/sanctions":
                data, _ = parse_json_payload(body)
                res = manage_sanctioned_entity(
                    self.db_path,
                    caller,
                    entity_id=str(data.get("entity_id") or ""),
                    list_source=str(data.get("list_source") or "OFAC_SDN"),
                    active=data.get("active", True),
                )
                return 200, resp_headers, res

            if req_method == "PUT" and route == "/api/v1/policies":
                data, _ = parse_json_payload(body)
                res = update_tenant_policy(self.db_path, caller, data)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
                data, _ = parse_json_payload(body)
                res = evaluate_transaction_batch(
                    self.db_path,
                    caller,
                    batch_id=str(data.get("batch_id") or ""),
                    transactions=data.get("transactions") or [],
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
                data, _ = parse_json_payload(body)
                res = simulate_custom_rule(
                    data.get("rule_tree") if "rule_tree" in data else {},
                    data.get("sample_tx") if "sample_tx" in data else {},
                )
                return 200, resp_headers, res

            if req_method == "GET" and route.startswith("/api/v1/risk/decisions/"):
                decision_id = route.split("/api/v1/risk/decisions/", 1)[1].strip("/")
                res = get_risk_decision_detail(self.db_path, caller, decision_id)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/quotas/consume":
                data, _ = parse_json_payload(body)
                res = consume_tenant_quota(
                    self.db_path,
                    caller,
                    quota_type=str(data.get("quota_type") or ""),
                    amount=data.get("amount", 1),
                )
                status_code = 200 if res.get("accepted") else 409
                return status_code, resp_headers, res

            if req_method == "POST" and route == "/api/v1/quotas/transfer":
                data, _ = parse_json_payload(body)
                res = transfer_tenant_quota(
                    self.db_path,
                    caller,
                    from_quota=str(data.get("from_quota") or ""),
                    to_quota=str(data.get("to_quota") or ""),
                    amount=data.get("amount", 0),
                )
                status_code = 200 if res.get("transferred") else 409
                return status_code, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
                data, _ = parse_json_payload(body)
                res = redeem_override_token(
                    self.db_path,
                    caller,
                    token_id=str(data.get("token_id") or ""),
                    tx_ref=str(data.get("tx_ref") or ""),
                )
                status_code = 200 if res.get("redeemed") else 409
                return status_code, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/export-digest":
                s_raw = query_params.get("start_ts")
                e_raw = query_params.get("end_ts")
                slim_raw = query_params.get("sample_limit")
                s_ts = (
                    strict_int(s_raw, "start_ts", min_val=0, max_val=MAX_SAFE_TS, allow_str=True)
                    if s_raw not in (None, "")
                    else None
                )
                e_ts = (
                    strict_int(e_raw, "end_ts", min_val=0, max_val=MAX_SAFE_TS, allow_str=True)
                    if e_raw not in (None, "")
                    else None
                )
                slim = (
                    10
                    if slim_raw in (None, "")
                    else strict_int(slim_raw, "sample_limit", allow_str=True)
                )
                sev = query_params.get("severity", "")
                res = export_audit_digest(
                    self.db_path,
                    caller,
                    start_ts=s_ts,
                    end_ts=e_ts,
                    severity=sev,
                    sample_limit=slim,
                )
                return 200, resp_headers, res

            if req_method == "PUT" and route == "/api/v1/audit/report-template":
                data, _ = parse_json_payload(body)
                res = save_report_template(
                    self.db_path,
                    caller,
                    template_id=str(data.get("template_id") or ""),
                    title_format=data.get("title_format") if "title_format" in data else "",
                    extra_event_filter=data.get("extra_event_filter", ""),
                    sample_limit=data.get("sample_limit", 10),
                )
                return 200, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/render-report":
                tpl_id = query_params.get("template_id", "")
                s_raw = query_params.get("start_ts")
                e_raw = query_params.get("end_ts")
                s_ts = (
                    strict_int(s_raw, "start_ts", min_val=0, max_val=MAX_SAFE_TS, allow_str=True)
                    if s_raw not in (None, "")
                    else None
                )
                e_ts = (
                    strict_int(e_raw, "end_ts", min_val=0, max_val=MAX_SAFE_TS, allow_str=True)
                    if e_raw not in (None, "")
                    else None
                )
                res = render_saved_report(
                    self.db_path,
                    caller,
                    template_id=tpl_id,
                    start_ts=s_ts,
                    end_ts=e_ts,
                )
                return 200, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/snapshots":
                snap_name = query_params.get("snapshot_name", "")
                res = read_compliance_snapshot(self.storage_dir, caller, snap_name)
                return 200, resp_headers, res

            return 404, resp_headers, {"error": "ROUTE_NOT_FOUND", "path": route}

        except AuthError as exc:
            return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
        except PermissionError as exc:
            return 403, resp_headers, {"error": "FORBIDDEN", "message": str(exc)}
        except LookupError as exc:
            return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
        except (ValueError, KeyError, OverflowError, json.JSONDecodeError) as exc:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except Exception:
            return (
                500,
                resp_headers,
                {
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": "Internal gateway processing error",
                },
            )


def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
    return AegisGateway(db_path=db_path, storage_dir=storage_dir)


def build_http_server(
    gateway: AegisGateway,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            try:
                content_len = strict_int(
                    self.headers.get("Content-Length") or "0",
                    "Content-Length",
                    min_val=0,
                    max_val=MAX_JSON_BODY_BYTES,
                    allow_str=True,
                )
            except ValueError:
                err_bytes = b'{"error":"BAD_REQUEST","message":"Invalid or oversized Content-Length"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)
                return

            raw_body = self.rfile.read(content_len) if content_len > 0 else b""
            hdrs = {k: v for k, v in self.headers.items()}
            status, resp_hdrs, payload = gateway.request(
                self.command,
                self.path,
                headers=hdrs,
                body=raw_body,
            )
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            for hk, hv in resp_hdrs.items():
                self.send_header(hk, hv)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    return ThreadingHTTPServer((host, port), GatewayHTTPHandler)


def main() -> int:
    ap = argparse.ArgumentParser(description="启动 AegisGate 多租户风控与合规检索网关")
    ap.add_argument("--db", required=True)
    ap.add_argument("--storage", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    gw = create_gateway(args.db, args.storage)
    srv = build_http_server(gw, host=args.host, port=args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
