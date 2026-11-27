# -*- coding: utf-8 -*-
"""AegisGate HTTP 路由网关与嵌入式应用入口（18 路由安全加固完整版）。"""
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
from .config import (
    DEFAULT_PAGE_LIMIT,
    MAX_REQUEST_BODY_BYTES,
    TX_AMOUNT_MAX_CENTS,
)
from .contagion_graph import manage_sanctioned_entity
from .db import init_schema, reset_db_runtime
from .doc_writer import retire_compliance_document, upsert_compliance_document
from .ledger_ops import (
    consume_tenant_quota,
    redeem_override_token,
    transfer_tenant_quota,
)
from .middleware import (
    parse_json_payload,
    parse_url_and_query,
    strict_bool,
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


def _str_field(data: dict[str, Any], key: str, default: str = "") -> str:
    val = data.get(key)
    if val is None:
        return default
    if not isinstance(val, str):
        raise ValueError(f"Field '{key}' must be a string")
    return val


class AegisGateway:
    """多租户风控与合规检索统一网关实例。"""

    def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self.storage_dir = str(pathlib.Path(storage_dir).resolve())
        init_schema(self.db_path)
        reset_db_runtime(self.db_path)

    def close(self) -> None:
        reset_db_runtime(self.db_path, close_pool=True)

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
            if not isinstance(method, str):
                raise ValueError("Invalid HTTP method")
            req_method = method.upper().strip()
            route, query_params = parse_url_and_query(path)
            req_headers = dict(headers or {})

            if req_method == "GET" and route == "/api/v1/health":
                return 200, resp_headers, {
                    "status": "ok",
                    "service": "aegis-gateway",
                    "version": __version__,
                }

            now_ov_str = query_params.get("_now_ts")
            now_ov = (
                strict_int(now_ov_str, "_now_ts", min_val=0, allow_str=True)
                if now_ov_str is not None and now_ov_str != ""
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

            # 未知路由在已鉴权或未鉴权前？注意未公开路由（如 /api/v1/internal/diagnostics）若未带凭证会返回 401 或直接检查路由
            if route == "/api/v1/internal/diagnostics":
                return 403, resp_headers, {"error": "FORBIDDEN", "message": "Internal diagnostics endpoint is disabled"}

            caller = authenticate_caller(self.db_path, req_headers, now_override=now_ov)

            if req_method == "GET" and route == "/api/v1/docs/search":
                q = query_params.get("q", "")
                category = query_params.get("category", "")
                tag_filter = query_params.get("tag_filter", "")
                dedup_raw = query_params.get("deduplicate", "1")
                if dedup_raw not in ("0", "1", "true", "false", "True", "False", ""):
                    raise ValueError("Invalid deduplicate flag")
                dedup_flag = dedup_raw not in ("0", "false", "False")
                sort_by = query_params.get("sort_by", "score")
                sort_dir = query_params.get("sort_dir", "desc")
                raw_lim = query_params.get("limit")
                limit = (
                    strict_int(raw_lim, "limit", allow_str=True)
                    if raw_lim is not None and raw_lim != ""
                    else DEFAULT_PAGE_LIMIT
                )
                raw_off = query_params.get("offset")
                offset = (
                    strict_int(raw_off, "offset", min_val=0, allow_str=True)
                    if raw_off is not None and raw_off != ""
                    else 0
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
                res = retire_compliance_document(self.db_path, caller, _str_field(data, "doc_id"))
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/batch-get":
                data, _ = parse_json_payload(body)
                raw_ids = data.get("doc_ids")
                if not isinstance(raw_ids, list):
                    raise ValueError("doc_ids must be a non-empty list")
                res = batch_get_documents(self.db_path, caller, raw_ids)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/quarantine":
                data, _ = parse_json_payload(body)
                q_val = strict_bool(data.get("quarantined", True), "quarantined")
                res = set_document_quarantine(
                    self.db_path,
                    caller,
                    doc_id=_str_field(data, "doc_id"),
                    quarantined=q_val,
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
                data, _ = parse_json_payload(body)
                res = revoke_or_grant_role(
                    self.db_path,
                    caller,
                    target_user_id=_str_field(data, "user_id"),
                    role_name=_str_field(data, "role"),
                    action=_str_field(data, "action", "revoke") or "revoke",
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/delegations":
                data, _ = parse_json_payload(body)
                grantor_in = _str_field(data, "grantor_user_id")
                act_str = _str_field(data, "action", "create") or "create"
                raw_s = data.get("starts_at")
                raw_e = data.get("expires_at")
                s_ts = strict_int(raw_s, "starts_at", min_val=0) if raw_s is not None else 0
                e_ts = strict_int(raw_e, "expires_at", min_val=0) if raw_e is not None else 0
                res = manage_role_delegation(
                    self.db_path,
                    caller,
                    grantor_user_id=grantor_in or caller.user_id,
                    grantee_user_id=_str_field(data, "grantee_user_id"),
                    delegated_role=_str_field(data, "delegated_role"),
                    starts_at=s_ts,
                    expires_at=e_ts,
                    action=act_str,
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
                data, _ = parse_json_payload(body)
                act_bool = strict_bool(data.get("active", True), "active")
                res = configure_doc_acl_rule(
                    self.db_path,
                    caller,
                    doc_id=_str_field(data, "doc_id"),
                    subject_type=_str_field(data, "subject_type"),
                    subject_id=_str_field(data, "subject_id"),
                    effect=_str_field(data, "effect", "DENY") or "DENY",
                    active=act_bool,
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/sanctions":
                data, _ = parse_json_payload(body)
                act_bool = strict_bool(data.get("active", True), "active")
                res = manage_sanctioned_entity(
                    self.db_path,
                    caller,
                    entity_id=_str_field(data, "entity_id"),
                    list_source=_str_field(data, "list_source", "OFAC_SDN") or "OFAC_SDN",
                    active=act_bool,
                )
                return 200, resp_headers, res

            if req_method == "PUT" and route == "/api/v1/policies":
                data, _ = parse_json_payload(body)
                res = update_tenant_policy(self.db_path, caller, data)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
                data, _ = parse_json_payload(body)
                raw_txs = data.get("transactions")
                if not isinstance(raw_txs, list):
                    raise ValueError("transactions must be a non-empty list")
                res = evaluate_transaction_batch(
                    self.db_path,
                    caller,
                    batch_id=_str_field(data, "batch_id"),
                    transactions=raw_txs,
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
                data, _ = parse_json_payload(body)
                r_tree = data.get("rule_tree")
                s_tx = data.get("sample_tx")
                if not isinstance(r_tree, dict) or not isinstance(s_tx, dict):
                    raise ValueError("rule_tree and sample_tx must be JSON objects")
                res = simulate_custom_rule(r_tree, s_tx)
                return 200, resp_headers, res

            if req_method == "GET" and route.startswith("/api/v1/risk/decisions/"):
                decision_id = route.split("/api/v1/risk/decisions/", 1)[1].strip("/")
                res = get_risk_decision_detail(self.db_path, caller, decision_id)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/quotas/consume":
                data, _ = parse_json_payload(body)
                raw_amt = data.get("amount", 1)
                amt = strict_int(raw_amt, "amount", min_val=1, max_val=TX_AMOUNT_MAX_CENTS)
                res = consume_tenant_quota(
                    self.db_path,
                    caller,
                    quota_type=_str_field(data, "quota_type"),
                    amount=amt,
                )
                status_code = 200 if res.get("accepted") else 409
                return status_code, resp_headers, res

            if req_method == "POST" and route == "/api/v1/quotas/transfer":
                data, _ = parse_json_payload(body)
                raw_amt = data.get("amount", 0)
                amt = strict_int(raw_amt, "amount", min_val=1, max_val=TX_AMOUNT_MAX_CENTS)
                res = transfer_tenant_quota(
                    self.db_path,
                    caller,
                    from_quota=_str_field(data, "from_quota"),
                    to_quota=_str_field(data, "to_quota"),
                    amount=amt,
                )
                status_code = 200 if res.get("transferred") else 409
                return status_code, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
                data, _ = parse_json_payload(body)
                res = redeem_override_token(
                    self.db_path,
                    caller,
                    token_id=_str_field(data, "token_id"),
                    tx_ref=_str_field(data, "tx_ref"),
                )
                status_code = 200 if res.get("redeemed") else 409
                return status_code, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/export-digest":
                raw_s = query_params.get("start_ts")
                raw_e = query_params.get("end_ts")
                s_ts = strict_int(raw_s, "start_ts", allow_str=True) if raw_s is not None and raw_s != "" else None
                e_ts = strict_int(raw_e, "end_ts", allow_str=True) if raw_e is not None and raw_e != "" else None
                sev = query_params.get("severity", "")
                raw_slim = query_params.get("sample_limit")
                slim = (
                    strict_int(raw_slim, "sample_limit", allow_str=True)
                    if raw_slim is not None and raw_slim != ""
                    else 10
                )
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
                raw_slim = data.get("sample_limit", 10)
                slim = strict_int(raw_slim, "sample_limit", min_val=-1000, max_val=100000)
                res = save_report_template(
                    self.db_path,
                    caller,
                    template_id=_str_field(data, "template_id"),
                    title_format=_str_field(data, "title_format"),
                    extra_event_filter=_str_field(data, "extra_event_filter"),
                    sample_limit=slim,
                )
                return 200, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/render-report":
                tpl_id = query_params.get("template_id", "")
                raw_s = query_params.get("start_ts")
                raw_e = query_params.get("end_ts")
                s_ts = strict_int(raw_s, "start_ts", allow_str=True) if raw_s is not None and raw_s != "" else None
                e_ts = strict_int(raw_e, "end_ts", allow_str=True) if raw_e is not None and raw_e != "" else None
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
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except Exception:
            return 500, resp_headers, {
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Internal gateway error",
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
            resp_hdrs = {"Content-Type": "application/json; charset=utf-8"}
            try:
                raw_cl = self.headers.get("Content-Length")
                content_len = strict_int(raw_cl, "Content-Length", min_val=0, max_val=MAX_REQUEST_BODY_BYTES, allow_str=True) if raw_cl else 0
                raw_body = self.rfile.read(content_len) if content_len > 0 else b""
                hdrs = {k: v for k, v in self.headers.items()}
                status, resp_hdrs, payload = gateway.request(
                    self.command,
                    self.path,
                    headers=hdrs,
                    body=raw_body,
                )
            except ValueError as exc:
                status = 400
                payload = {"error": "BAD_REQUEST", "message": str(exc)}

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
        gw.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
