# -*- coding: utf-8 -*-
"""AegisGate HTTP 路由网关与嵌入式应用入口。"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import pathlib
import urllib.parse
from typing import Any

from . import __version__
from .audit_export import export_audit_digest, read_compliance_snapshot
from .auth import (
    AuthError,
    authenticate_caller,
    configure_doc_acl_rule,
    consume_tenant_quota,
    process_settlement_webhook,
    redeem_override_token,
    revoke_or_grant_role,
)
from .config import DEFAULT_PAGE_LIMIT
from .db import ConflictError, ensure_db_optimized
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

MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024


class AegisGateway:
    """多租户风控与合规检索统一网关实例。"""

    def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self.storage_dir = str(pathlib.Path(storage_dir).resolve())
        ensure_db_optimized(self.db_path)

    def _parse_json_body(self, body: bytes | str | dict[str, Any] | None) -> tuple[dict[str, Any], str]:
        if body is None:
            return {}, ""
        if isinstance(body, dict):
            raw = json.dumps(body, separators=(",", ":"))
            if len(raw.encode("utf-8")) > MAX_REQUEST_BODY_BYTES:
                raise ValueError("Request payload exceeds maximum allowed size")
            return body, raw
        if isinstance(body, bytes):
            if len(body) > MAX_REQUEST_BODY_BYTES:
                raise ValueError("Request payload exceeds maximum allowed size")
            raw = body.decode("utf-8")
        else:
            raw = str(body)
            if len(raw.encode("utf-8")) > MAX_REQUEST_BODY_BYTES:
                raise ValueError("Request payload exceeds maximum allowed size")
        if not raw.strip():
            return {}, raw
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Request JSON payload must be an object")
        return data, raw

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        """处理一次 HTTP 网关调用，返回 (status_code, response_headers, response_json_dict)。"""
        req_method = method.upper().strip()
        parsed_url = urllib.parse.urlsplit(path)
        route = parsed_url.path.rstrip("/") or "/"
        query_params = dict(urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True))
        req_headers = dict(headers or {})
        resp_headers = {"Content-Type": "application/json; charset=utf-8"}

        try:
            if req_method == "GET" and route == "/api/v1/health":
                return 200, resp_headers, {
                    "status": "ok",
                    "service": "aegis-gateway",
                    "version": __version__,
                }

            if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
                _, raw_body = self._parse_json_body(body)
                now_ov_str = query_params.get("_now_ts")
                now_ov = int(now_ov_str) if now_ov_str else None
                res = process_settlement_webhook(
                    self.db_path,
                    req_headers,
                    raw_body,
                    now_override=now_ov,
                )
                return 200, resp_headers, res

            # 其余业务接口均需通过操作员身份认证
            caller = authenticate_caller(self.db_path, req_headers)

            if req_method == "GET" and route == "/api/v1/docs/search":
                q = query_params.get("q", "")
                category = query_params.get("category", "")
                tag_filter = query_params.get("tag_filter", "")
                dedup_flag = query_params.get("deduplicate", "1") != "0"
                sort_by = query_params.get("sort_by", "score")
                sort_dir = query_params.get("sort_dir", "desc")
                limit = int(query_params.get("limit", str(DEFAULT_PAGE_LIMIT)))
                offset = int(query_params.get("offset", "0"))
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

            if req_method == "POST" and route == "/api/v1/docs/batch-get":
                data, _ = self._parse_json_body(body)
                res = batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/docs/quarantine":
                data, _ = self._parse_json_body(body)
                res = set_document_quarantine(
                    self.db_path,
                    caller,
                    doc_id=str(data.get("doc_id") or ""),
                    quarantined=bool(data.get("quarantined", True)),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
                data, _ = self._parse_json_body(body)
                res = revoke_or_grant_role(
                    self.db_path,
                    caller,
                    target_user_id=str(data.get("user_id") or ""),
                    role_name=str(data.get("role") or ""),
                    action=str(data.get("action") or "revoke"),
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
                data, _ = self._parse_json_body(body)
                res = configure_doc_acl_rule(
                    self.db_path,
                    caller,
                    doc_id=str(data.get("doc_id") or ""),
                    subject_type=str(data.get("subject_type") or ""),
                    subject_id=str(data.get("subject_id") or ""),
                    active=bool(data.get("active", True)),
                )
                return 200, resp_headers, res

            if req_method == "PUT" and route == "/api/v1/policies":
                data, _ = self._parse_json_body(body)
                res = update_tenant_policy(self.db_path, caller, data)
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
                data, _ = self._parse_json_body(body)
                res = evaluate_transaction_batch(
                    self.db_path,
                    caller,
                    batch_id=str(data.get("batch_id") or ""),
                    transactions=data.get("transactions") or [],
                )
                return 200, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
                data, _ = self._parse_json_body(body)
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
                data, _ = self._parse_json_body(body)
                raw_amount = data.get("amount", 1)
                if isinstance(raw_amount, bool):
                    raise ValueError("amount must be an integer")
                res = consume_tenant_quota(
                    self.db_path,
                    caller,
                    quota_type=str(data.get("quota_type") or ""),
                    amount=int(raw_amount),
                )
                status_code = 200 if res.get("accepted") else 409
                return status_code, resp_headers, res

            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
                data, _ = self._parse_json_body(body)
                res = redeem_override_token(
                    self.db_path,
                    caller,
                    token_id=str(data.get("token_id") or ""),
                    tx_ref=str(data.get("tx_ref") or ""),
                )
                status_code = 200 if res.get("redeemed") else 409
                return status_code, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/export-digest":
                s_ts = int(query_params["start_ts"]) if query_params.get("start_ts") else None
                e_ts = int(query_params["end_ts"]) if query_params.get("end_ts") else None
                sev = query_params.get("severity", "")
                slim = int(query_params.get("sample_limit", "10"))
                res = export_audit_digest(
                    self.db_path,
                    caller,
                    start_ts=s_ts,
                    end_ts=e_ts,
                    severity=sev,
                    sample_limit=slim,
                )
                return 200, resp_headers, res

            if req_method == "GET" and route == "/api/v1/audit/snapshots":
                snap_name = query_params.get("snapshot_name", "")
                res = read_compliance_snapshot(self.storage_dir, caller, snap_name)
                return 200, resp_headers, res

            return 404, resp_headers, {"error": "ROUTE_NOT_FOUND", "path": route}

        except AuthError as exc:
            return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
        except ConflictError as exc:
            return exc.status_code, resp_headers, {"error": "CONFLICT", "message": str(exc)}
        except LookupError as exc:
            return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except Exception:
            return 500, resp_headers, {
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal error occurred",
            }


def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
    """工厂方法：创建网关实例（供 HTTP 服务器及自动化测试挂载）。"""
    return AegisGateway(db_path=db_path, storage_dir=storage_dir)


class _AegisThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def build_http_server(
    gateway: AegisGateway,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """构建标准库多线程 HTTP 服务器包装器。"""

    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            raw_len = self.headers.get("Content-Length")
            try:
                content_len = int(raw_len) if raw_len else 0
            except ValueError:
                content_len = -1

            if content_len < 0 or content_len > MAX_REQUEST_BODY_BYTES:
                status = 413 if content_len > MAX_REQUEST_BODY_BYTES else 400
                payload = {"error": "BAD_REQUEST", "message": "Invalid or oversized Content-Length"}
                resp_hdrs = {"Content-Type": "application/json; charset=utf-8"}
            else:
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

    return _AegisThreadingHTTPServer((host, port), GatewayHTTPHandler)


def main() -> int:
    ap = argparse.ArgumentParser(description="启动 AegisGate 多租户风控与合规检索网关")
    ap.add_argument("--db", required=True, help="SQLite 数据库文件路径")
    ap.add_argument("--storage", required=True, help="归档存储根目录路径")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    gw = create_gateway(args.db, args.storage)
    srv = build_http_server(gw, host=args.host, port=args.port)
    actual_port = srv.server_address[1]
    print(f"AegisGate listening on htt<REDACTED_PATH>")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
