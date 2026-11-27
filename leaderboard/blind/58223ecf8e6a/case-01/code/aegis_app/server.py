# -*- coding: utf-8 -*-
"""AegisGate 18 路由统一入口；所有外部数值/布尔值经严格类型守卫。"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import pathlib
import sqlite3
from typing import Any

from . import __version__
from .audit_export import export_audit_digest, read_compliance_snapshot, render_saved_report, save_report_template
from .auth import (
    AuthError, authenticate_caller, configure_doc_acl_rule, manage_role_delegation,
    process_settlement_webhook, revoke_or_grant_role,
)
from .config import DEFAULT_PAGE_LIMIT
from .contagion_graph import manage_sanctioned_entity
from .db import init_schema
from .doc_writer import retire_compliance_document, upsert_compliance_document
from .ledger_ops import consume_tenant_quota, redeem_override_token, transfer_tenant_quota
from .middleware import parse_json_payload, parse_url_and_query
from .rule_engine import evaluate_transaction_batch, get_risk_decision_detail, simulate_custom_rule, update_tenant_policy
from .search_service import batch_get_documents, search_documents, set_document_quarantine
from .security import strict_bool, strict_int


class AegisGateway:
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
        req_method = str(method).upper().strip()
        req_headers = dict(headers or {})
        resp_headers = {"Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff"}
        try:
            route, query = parse_url_and_query(path)
            if req_method == "GET" and route == "/api/v1/health":
                return 200, resp_headers, {"status": "ok", "service": "aegis-gateway", "version": __version__}

            now_override = strict_int(query["_now_ts"], "_now_ts") if query.get("_now_ts") else None
            if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
                _, raw = parse_json_payload(body)
                return 200, resp_headers, process_settlement_webhook(
                    self.db_path, req_headers, raw, now_override=now_override,
                )

            caller = authenticate_caller(self.db_path, req_headers, now_override=now_override)
            if req_method == "GET" and route == "/api/v1/docs/search":
                result = search_documents(
                    self.db_path, caller,
                    query=query.get("q", ""), category=query.get("category", ""),
                    tag_filter=query.get("tag_filter", ""),
                    deduplicate=query.get("deduplicate", "1") != "0",
                    sort_by=query.get("sort_by", "score"), sort_dir=query.get("sort_dir", "desc"),
                    limit=strict_int(query.get("limit", str(DEFAULT_PAGE_LIMIT)), "limit"),
                    offset=strict_int(query.get("offset", "0"), "offset"),
                )
                return 200, resp_headers, result
            if req_method == "POST" and route == "/api/v1/docs/upsert":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, upsert_compliance_document(self.db_path, caller, data)
            if req_method == "POST" and route == "/api/v1/docs/retire":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, retire_compliance_document(
                    self.db_path, caller, str(data.get("doc_id") or ""),
                )
            if req_method == "POST" and route == "/api/v1/docs/batch-get":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
            if req_method == "POST" and route == "/api/v1/docs/quarantine":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, set_document_quarantine(
                    self.db_path, caller, doc_id=str(data.get("doc_id") or ""),
                    quarantined=strict_bool(data.get("quarantined", True), "quarantined"),
                )
            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, revoke_or_grant_role(
                    self.db_path, caller, target_user_id=str(data.get("user_id") or ""),
                    role_name=str(data.get("role") or ""), action=str(data.get("action") or "revoke"),
                )
            if req_method == "POST" and route == "/api/v1/admin/delegations":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, manage_role_delegation(
                    self.db_path, caller,
                    grantor_user_id=str(data.get("grantor_user_id") or caller.user_id),
                    grantee_user_id=str(data.get("grantee_user_id") or ""),
                    delegated_role=str(data.get("delegated_role") or ""),
                    starts_at=strict_int(data.get("starts_at", 0), "starts_at"),
                    expires_at=strict_int(data.get("expires_at", 0), "expires_at"),
                    action=str(data.get("action") or "create"),
                )
            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, configure_doc_acl_rule(
                    self.db_path, caller, doc_id=str(data.get("doc_id") or ""),
                    subject_type=str(data.get("subject_type") or ""),
                    subject_id=str(data.get("subject_id") or ""),
                    effect=str(data.get("effect") or "DENY"),
                    active=strict_bool(data.get("active", True), "active"),
                )
            if req_method == "POST" and route == "/api/v1/admin/sanctions":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, manage_sanctioned_entity(
                    self.db_path, caller, entity_id=str(data.get("entity_id") or ""),
                    list_source=str(data.get("list_source") or "OFAC_SDN"),
                    active=strict_bool(data.get("active", True), "active"),
                )
            if req_method == "PUT" and route == "/api/v1/policies":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, update_tenant_policy(self.db_path, caller, data)
            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, evaluate_transaction_batch(
                    self.db_path, caller, batch_id=str(data.get("batch_id") or ""),
                    transactions=data.get("transactions") or [],
                )
            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, simulate_custom_rule(
                    data.get("rule_tree") or {}, data.get("sample_tx") or {},
                )
            if req_method == "GET" and route.startswith("/api/v1/risk/decisions/"):
                decision_id = route.split("/api/v1/risk/decisions/", 1)[1].strip("/")
                return 200, resp_headers, get_risk_decision_detail(self.db_path, caller, decision_id)
            if req_method == "POST" and route == "/api/v1/quotas/consume":
                data, _ = parse_json_payload(body)
                result = consume_tenant_quota(
                    self.db_path, caller, quota_type=str(data.get("quota_type") or ""),
                    amount=strict_int(data.get("amount", 1), "amount"),
                )
                return (200 if result.get("accepted") else 409), resp_headers, result
            if req_method == "POST" and route == "/api/v1/quotas/transfer":
                data, _ = parse_json_payload(body)
                result = transfer_tenant_quota(
                    self.db_path, caller, from_quota=str(data.get("from_quota") or ""),
                    to_quota=str(data.get("to_quota") or ""),
                    amount=strict_int(data.get("amount", 0), "amount"),
                )
                return (200 if result.get("transferred") else 409), resp_headers, result
            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
                data, _ = parse_json_payload(body)
                result = redeem_override_token(
                    self.db_path, caller, token_id=str(data.get("token_id") or ""),
                    tx_ref=str(data.get("tx_ref") or ""),
                )
                return (200 if result.get("redeemed") else 409), resp_headers, result
            if req_method == "GET" and route == "/api/v1/audit/export-digest":
                result = export_audit_digest(
                    self.db_path, caller,
                    start_ts=strict_int(query["start_ts"], "start_ts") if query.get("start_ts") else None,
                    end_ts=strict_int(query["end_ts"], "end_ts") if query.get("end_ts") else None,
                    severity=query.get("severity", ""),
                    sample_limit=strict_int(query.get("sample_limit", "10"), "sample_limit"),
                )
                return 200, resp_headers, result
            if req_method == "PUT" and route == "/api/v1/audit/report-template":
                data, _ = parse_json_payload(body)
                return 200, resp_headers, save_report_template(
                    self.db_path, caller, template_id=str(data.get("template_id") or ""),
                    title_format=str(data.get("title_format") or ""),
                    extra_event_filter=str(data.get("extra_event_filter") or ""),
                    sample_limit=strict_int(data.get("sample_limit", 10), "sample_limit"),
                )
            if req_method == "GET" and route == "/api/v1/audit/render-report":
                result = render_saved_report(
                    self.db_path, caller, template_id=query.get("template_id", ""),
                    start_ts=strict_int(query["start_ts"], "start_ts") if query.get("start_ts") else None,
                    end_ts=strict_int(query["end_ts"], "end_ts") if query.get("end_ts") else None,
                )
                return 200, resp_headers, result
            if req_method == "GET" and route == "/api/v1/audit/snapshots":
                return 200, resp_headers, read_compliance_snapshot(
                    self.storage_dir, caller, query.get("snapshot_name", ""),
                )
            return 404, resp_headers, {"error": "ROUTE_NOT_FOUND"}
        except AuthError as exc:
            return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
        except PermissionError as exc:
            return 403, resp_headers, {"error": "FORBIDDEN", "message": str(exc)}
        except LookupError as exc:
            return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
        except (ValueError, KeyError, json.JSONDecodeError, OverflowError, RecursionError) as exc:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except sqlite3.IntegrityError:
            return 409, resp_headers, {"error": "CONFLICT", "message": "Resource conflicts with committed state"}
        except Exception:
            return 500, resp_headers, {"error": "INTERNAL_SERVER_ERROR", "message": "The request could not be completed"}


def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
    return AegisGateway(db_path, storage_dir)


def build_http_server(gateway: AegisGateway, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            try:
                content_length = strict_int(
                    self.headers.get("Content-Length") or 0, "Content-Length",
                    minimum=0, maximum=1_048_576,
                )
            except ValueError:
                self.send_error(413, "Request body too large or invalid")
                return
            raw_body = self.rfile.read(content_length) if content_length else b""
            status, headers, payload = gateway.request(
                self.command, self.path, headers=dict(self.headers.items()), body=raw_body,
            )
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
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
    parser = argparse.ArgumentParser(description="AegisGate gateway")
    parser.add_argument("--db", required=True)
    parser.add_argument("--storage", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    gateway = create_gateway(args.db, args.storage)
    server = build_http_server(gateway, args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
