# -*- coding: utf-8 -*-
"""AegisGate 18 路由入口、严格类型边界与脱敏错误响应。"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import pathlib
import re
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
from .runtime import MAX_JSON_BYTES, strict_int
from .search_service import batch_get_documents, search_documents, set_document_quarantine

_INT_TEXT = re.compile(r"-?[0-9]+")


def _query_int(params: dict[str, str], name: str, default: Any = None) -> Any:
    raw = params.get(name)
    if raw is None or raw == "":
        return default
    if _INT_TEXT.fullmatch(raw) is None:
        raise ValueError(f"{name} must be an integer")
    return strict_int(int(raw), name)


def _body_int(data: dict[str, Any], name: str, default: Any = None) -> int:
    return strict_int(data.get(name, default), name)


def _boolean(data: dict[str, Any], name: str, default: bool = True) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


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
        response_headers = {"Content-Type": "application/json; charset=utf-8", "X-Content-Type-Options": "nosniff"}
        try:
            if not isinstance(method, str) or len(method) > 16:
                raise ValueError("Invalid HTTP method")
            req_method = method.upper().strip()
            route, query = parse_url_and_query(path)
            req_headers = dict(headers or {})
            if req_method == "GET" and route == "/api/v1/health":
                return 200, response_headers, {"status": "ok", "service": "aegis-gateway", "version": __version__}
            if route == "/api/v1/internal/diagnostics":
                return 404, response_headers, {"error": "ROUTE_NOT_FOUND"}
            now_override = _query_int(query, "_now_ts")

            if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
                _, raw_body = parse_json_payload(body)
                result = process_settlement_webhook(
                    self.db_path, req_headers, raw_body, now_override=now_override
                )
                return 200, response_headers, result

            caller = authenticate_caller(self.db_path, req_headers, now_override=now_override)
            if req_method == "GET" and route == "/api/v1/docs/search":
                result = search_documents(
                    self.db_path, caller,
                    query=query.get("q", ""), category=query.get("category", ""),
                    tag_filter=query.get("tag_filter", ""),
                    deduplicate=query.get("deduplicate", "1") != "0",
                    sort_by=query.get("sort_by", "score"), sort_dir=query.get("sort_dir", "desc"),
                    limit=_query_int(query, "limit", DEFAULT_PAGE_LIMIT),
                    offset=_query_int(query, "offset", 0),
                )
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/docs/upsert":
                data, _ = parse_json_payload(body)
                return 200, response_headers, upsert_compliance_document(self.db_path, caller, data)
            if req_method == "POST" and route == "/api/v1/docs/retire":
                data, _ = parse_json_payload(body)
                result = retire_compliance_document(self.db_path, caller, str(data.get("doc_id") or ""))
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/docs/batch-get":
                data, _ = parse_json_payload(body)
                return 200, response_headers, batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
            if req_method == "POST" and route == "/api/v1/docs/quarantine":
                data, _ = parse_json_payload(body)
                result = set_document_quarantine(
                    self.db_path, caller, doc_id=str(data.get("doc_id") or ""),
                    quarantined=_boolean(data, "quarantined"),
                )
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
                data, _ = parse_json_payload(body)
                result = revoke_or_grant_role(
                    self.db_path, caller, target_user_id=str(data.get("user_id") or ""),
                    role_name=str(data.get("role") or ""), action=str(data.get("action") or "revoke"),
                )
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/admin/delegations":
                data, _ = parse_json_payload(body)
                result = manage_role_delegation(
                    self.db_path, caller,
                    grantor_user_id=str(data.get("grantor_user_id") or caller.user_id),
                    grantee_user_id=str(data.get("grantee_user_id") or ""),
                    delegated_role=str(data.get("delegated_role") or ""),
                    starts_at=_body_int(data, "starts_at", 0), expires_at=_body_int(data, "expires_at", 0),
                    action=str(data.get("action") or "create"),
                )
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
                data, _ = parse_json_payload(body)
                result = configure_doc_acl_rule(
                    self.db_path, caller, doc_id=str(data.get("doc_id") or ""),
                    subject_type=str(data.get("subject_type") or ""), subject_id=str(data.get("subject_id") or ""),
                    effect=str(data.get("effect") or "DENY"), active=_boolean(data, "active"),
                )
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/admin/sanctions":
                data, _ = parse_json_payload(body)
                result = manage_sanctioned_entity(
                    self.db_path, caller, entity_id=str(data.get("entity_id") or ""),
                    list_source=str(data.get("list_source") or "OFAC_SDN"), active=_boolean(data, "active"),
                )
                return 200, response_headers, result
            if req_method == "PUT" and route == "/api/v1/policies":
                data, _ = parse_json_payload(body)
                return 200, response_headers, update_tenant_policy(self.db_path, caller, data)
            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
                data, _ = parse_json_payload(body)
                result = evaluate_transaction_batch(
                    self.db_path, caller, batch_id=str(data.get("batch_id") or ""),
                    transactions=data.get("transactions") or [],
                )
                return 200, response_headers, result
            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
                data, _ = parse_json_payload(body)
                result = simulate_custom_rule(data.get("rule_tree") or {}, data.get("sample_tx") or {})
                return 200, response_headers, result
            if req_method == "GET" and route.startswith("/api/v1/risk/decisions/"):
                decision_id = route.split("/api/v1/risk/decisions/", 1)[1].strip("/")
                return 200, response_headers, get_risk_decision_detail(self.db_path, caller, decision_id)
            if req_method == "POST" and route == "/api/v1/quotas/consume":
                data, _ = parse_json_payload(body)
                result = consume_tenant_quota(
                    self.db_path, caller, quota_type=str(data.get("quota_type") or ""),
                    amount=_body_int(data, "amount", 1),
                )
                return (200 if result.get("accepted") else 409), response_headers, result
            if req_method == "POST" and route == "/api/v1/quotas/transfer":
                data, _ = parse_json_payload(body)
                result = transfer_tenant_quota(
                    self.db_path, caller, from_quota=str(data.get("from_quota") or ""),
                    to_quota=str(data.get("to_quota") or ""), amount=_body_int(data, "amount", 0),
                )
                return (200 if result.get("transferred") else 409), response_headers, result
            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
                data, _ = parse_json_payload(body)
                result = redeem_override_token(
                    self.db_path, caller, token_id=str(data.get("token_id") or ""), tx_ref=str(data.get("tx_ref") or ""),
                )
                return (200 if result.get("redeemed") else 409), response_headers, result
            if req_method == "GET" and route == "/api/v1/audit/export-digest":
                result = export_audit_digest(
                    self.db_path, caller, start_ts=_query_int(query, "start_ts"),
                    end_ts=_query_int(query, "end_ts"), severity=query.get("severity", ""),
                    sample_limit=_query_int(query, "sample_limit", 10),
                )
                return 200, response_headers, result
            if req_method == "PUT" and route == "/api/v1/audit/report-template":
                data, _ = parse_json_payload(body)
                result = save_report_template(
                    self.db_path, caller, template_id=str(data.get("template_id") or ""),
                    title_format=str(data.get("title_format") or ""),
                    extra_event_filter=str(data.get("extra_event_filter") or ""),
                    sample_limit=_body_int(data, "sample_limit", 10),
                )
                return 200, response_headers, result
            if req_method == "GET" and route == "/api/v1/audit/render-report":
                result = render_saved_report(
                    self.db_path, caller, template_id=query.get("template_id", ""),
                    start_ts=_query_int(query, "start_ts"), end_ts=_query_int(query, "end_ts"),
                )
                return 200, response_headers, result
            if req_method == "GET" and route == "/api/v1/audit/snapshots":
                result = read_compliance_snapshot(self.storage_dir, caller, query.get("snapshot_name", ""))
                return 200, response_headers, result
            return 404, response_headers, {"error": "ROUTE_NOT_FOUND", "path": route}
        except AuthError as exc:
            return exc.status_code, response_headers, {"error": "AUTH_ERROR", "message": str(exc)}
        except PermissionError as exc:
            return 403, response_headers, {"error": "FORBIDDEN", "message": str(exc)}
        except LookupError as exc:
            return 404, response_headers, {"error": "NOT_FOUND", "message": str(exc)}
        except (ValueError, KeyError, TypeError, OverflowError, json.JSONDecodeError, UnicodeError) as exc:
            return 400, response_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except Exception:
            return 500, response_headers, {"error": "INTERNAL_SERVER_ERROR", "message": "Internal request failure"}


def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
    return AegisGateway(db_path=db_path, storage_dir=storage_dir)


def build_http_server(gateway: AegisGateway, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        def _write(self, status: int, headers: dict[str, str], payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _dispatch(self) -> None:
            try:
                raw_length = self.headers.get("Content-Length") or "0"
                if not raw_length.isdigit():
                    raise ValueError("Invalid Content-Length")
                content_length = int(raw_length)
                if content_length > MAX_JSON_BYTES:
                    self._write(413, {"Content-Type": "application/json"}, {"error": "PAYLOAD_TOO_LARGE"})
                    return
                raw_body = self.rfile.read(content_length) if content_length else b""
                status, headers, payload = gateway.request(
                    self.command, self.path, headers=dict(self.headers.items()), body=raw_body
                )
                self._write(status, headers, payload)
            except (ValueError, OverflowError):
                self._write(400, {"Content-Type": "application/json"}, {"error": "BAD_REQUEST"})

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer((host, port), GatewayHTTPHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="启动 AegisGate 网关")
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
