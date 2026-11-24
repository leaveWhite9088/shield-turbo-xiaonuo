# -*- coding: utf-8 -*-
"""AegisGate 高并发纵深安全路由网关（9级疾风铁盾大师基线）。"""
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
from .config import DEFAULT_PAGE_LIMIT, MAX_BODY_BYTES
from .contagion_graph import manage_sanctioned_entity
from .db import init_schema, require_strict_int, reset_db_caches
from .doc_writer import retire_compliance_document, upsert_compliance_document
from .ledger_ops import (
    consume_tenant_quota,
    redeem_override_token,
    transfer_tenant_quota,
)
from .middleware import parse_json_payload, parse_url_and_query
from .rule_engine import (
    BatchConflictError,
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


def _parse_query_int(raw_val: str | None, field_name: str) -> int:
    if raw_val is None or raw_val == "":
        raise ValueError(f"Missing integer parameter {field_name}")
    val = int(raw_val)
    return require_strict_int(val, field_name)


class AegisGateway:
    def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self.storage_dir = str(pathlib.Path(storage_dir).resolve())
        init_schema(self.db_path)
        reset_db_caches(self.db_path)

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        req_method = method.upper().strip()
        resp_headers = {"Content-Type": "application/json; charset=utf-8"}
        if len(path) > 4096:
            return 400, resp_headers, {
                "error": "BAD_REQUEST",
                "message": "URI too long",
            }

        route, query_params, raw_query_map = parse_url_and_query(path)
        req_headers = dict(headers or {})

        try:
            if req_method == "GET" and route == "/api/v1/health":
                return 200, resp_headers, {
                    "status": "ok",
                    "service": "aegis-gateway",
                    "version": __version__,
                }

            if route == "/api/v1/internal/diagnostics":
                return 403, resp_headers, {
                    "error": "FORBIDDEN",
                    "message": "Internal diagnostics endpoint is disabled in production",
                }

            now_ov_str = query_params.get("_now_ts")
            now_ov = _parse_query_int(now_ov_str, "_now_ts") if now_ov_str else None

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
                dedup_flag = query_params.get("deduplicate", "1") != "0"
                sort_by = query_params.get("sort_by", "score")
                sort_dir = query_params.get("sort_dir", "desc")
                limit = _parse_query_int(query_params.get("limit", str(DEFAULT_PAGE_LIMIT)), "limit")
                offset = _parse_query_int(query_params.get("offset", "0"), "offset")
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
                    quarantined=bool(data.get("quarantined", True)),
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
                    active=bool(data.get("active", True)),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/sanctions":
                data, _ = parse_json_payload(body)
                res = manage_sanctioned_entity(
                    self.db_path,
                    caller,
                    entity_id=str(data.get("entity_id") or ""),
                    list_source=str(data.get("list_source") or "OFAC_SDN"),
                    active=bool(data.get("active", True)),
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
                    data.get("rule_tree") or {},
                    data.get("sample_tx") or {},
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
                s_ts = _parse_query_int(query_params["start_ts"], "start_ts") if query_params.get("start_ts") else None
                e_ts = _parse_query_int(query_params["end_ts"], "end_ts") if query_params.get("end_ts") else None
                sev = query_params.get("severity", "")
                slim = _parse_query_int(query_params.get("sample_limit", "10"), "sample_limit")
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
                    title_format=str(data.get("title_format") or ""),
                    extra_event_filter=str(data.get("extra_event_filter") or ""),
                    sample_limit=data.get("sample_limit", 10),
                )
                return 200, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/render-report":
                tpl_id = query_params.get("template_id", "")
                s_ts = _parse_query_int(query_params["start_ts"], "start_ts") if query_params.get("start_ts") else None
                e_ts = _parse_query_int(query_params["end_ts"], "end_ts") if query_params.get("end_ts") else None
                res = render_saved_report(
                    self.db_path,
                    caller,
                    template_id=tpl_id,
                    start_ts=s_ts,
                    end_ts=e_ts,
                )
                return 200, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/snapshots":
                raw_snap = raw_query_map.get("snapshot_name", "")
                if "%25" in raw_snap.lower() or "%00" in raw_snap.lower():
                    raise ValueError("Encoded traversal or null-byte snapshot_name rejected")
                snap_name = query_params.get("snapshot_name", "")
                res = read_compliance_snapshot(self.storage_dir, caller, snap_name)
                return 200, resp_headers, res

            return 404, resp_headers, {"error": "ROUTE_NOT_FOUND", "path": route}

        except AuthError as exc:
            return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
        except PermissionError as exc:
            return 403, resp_headers, {"error": "FORBIDDEN", "message": str(exc)}
        except BatchConflictError as exc:
            return 409, resp_headers, {"error": "CONFLICT", "message": str(exc)}
        except LookupError as exc:
            return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError, json.JSONDecodeError) as exc:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except Exception:
            return 500, resp_headers, {
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Internal gateway processing error",
            }


def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
    return AegisGateway(db_path=db_path, storage_dir=storage_dir)


def build_http_server(
    gateway: AegisGateway,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            content_len = int(self.headers.get("Content-Length") or 0)
            if content_len > MAX_BODY_BYTES:
                payload = json.dumps({"error": "BAD_REQUEST", "message": "Payload too large"}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            raw_body = self.rfile.read(content_len) if content_len > 0 else b""
            hdrs = {k: v for k, v in self.headers.items()}
            status, resp_hdrs, payload_dict = gateway.request(
                self.command,
                self.path,
                headers=hdrs,
                body=raw_body,
            )
            encoded = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
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
