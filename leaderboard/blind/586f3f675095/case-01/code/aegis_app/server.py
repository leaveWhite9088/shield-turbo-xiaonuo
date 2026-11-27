# -*- coding: utf-8 -*-
"""AegisGate HTTP 路由网关与嵌入式应用入口（18 路由完整网关版）。

单请求资源编排（性能 + 一致性）：
* 每个网关进程持有**一个** :class:`SharedResources`（连接池、增量索引、纪元总线、滑窗注册表、
  传染图、各维有界缓存），请求线程内复用同一连接（按线程隔离，绝不跨线程共享）；
* 每请求只取**一次**时钟（``_now_ts`` 覆盖值或墙钟），认证、风控、配额、审计全部基于同一 ``request_ts``；
* 任何 5xx 只返回稳定错误码，不泄露路径、主密钥或堆栈。
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import pathlib
import time
import traceback
import urllib.parse
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
from .config import DEFAULT_PAGE_LIMIT, MAX_BODY_BYTES, MAX_TS_ABS
from .contagion_graph import manage_sanctioned_entity
from .db import SharedResources, init_schema
from .doc_writer import retire_compliance_document, upsert_compliance_document
from .guards import GuardError, strict_int
from .ledger_ops import (
    consume_tenant_quota,
    redeem_override_token,
    transfer_tenant_quota,
)
from .middleware import (
    collect_internal_diagnostics,
    parse_json_payload,
    parse_now_override,
    parse_url_and_query,
)
from .rule_engine import (
    evaluate_transaction_batch,
    get_risk_decision_detail,
    simulate_custom_rule,
    update_tenant_policy,
)
from .search_service import (
    BadSqlRequest,
    batch_get_documents,
    search_documents,
    set_document_quarantine,
)
from .views import bind_caller

_DIAG_ENV_FLAG = "AEGIS_INTERNAL_DIAGNOSTICS"


def _int_param(params: dict[str, str], key: str, default: int) -> int:
    raw = params.get(key)
    if raw is None or raw == "":
        return default
    return strict_int(raw, name=key)


def _opt_ts(params: dict[str, str], key: str) -> int | None:
    raw = params.get(key)
    if raw is None or raw == "":
        return None
    return strict_int(raw, name=key)


class AegisGateway:
    """多租户风控与合规检索统一网关实例。"""

    def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
        self.db_path = str(pathlib.Path(db_path).resolve())
        self.storage_dir = str(pathlib.Path(storage_dir).resolve())
        init_schema(self.db_path)
        self.shared = SharedResources(self.db_path, self.storage_dir)
        self._diagnostics_enabled = os.environ.get(_DIAG_ENV_FLAG) == "1"

    # ------------------------------------------------------------------
    def health(self) -> dict[str, Any]:
        return {"status": "ok", "service": "aegis-gateway", "version": __version__}

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        """处理一次网关调用，返回 (status_code, response_headers, response_json_dict)。"""
        req_method = method.upper().strip()
        resp_headers = {"Content-Type": "application/json; charset=utf-8"}
        try:
            route, query_params = parse_url_and_query(path)
            now_ov = parse_now_override(query_params)
            req_headers = dict(headers or {})
            return self._dispatch(req_method, route, query_params, req_headers, body, now_ov, resp_headers)
        except AuthError as exc:
            return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
        except PermissionError as exc:
            return 403, resp_headers, {"error": "FORBIDDEN", "message": str(exc)}
        except LookupError as exc:
            return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
        except BadSqlRequest:
            return 500, resp_headers, {"error": "BAD_SQL_REQUEST", "message": "Unsupported SQL ordering parameter"}
        except (GuardError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
        except RecursionError:
            return 400, resp_headers, {"error": "BAD_REQUEST", "message": "Payload nesting too deep"}
        except Exception:  # noqa: BLE001 - 兜底：只回稳定错误码，不泄露内部细节
            return 500, resp_headers, {"error": "INTERNAL_SERVER_ERROR"}

    # ------------------------------------------------------------------
    def _dispatch(self, req_method, route, query_params, req_headers, body, now_ov, resp_headers):
        if req_method == "GET" and route == "/api/v1/health":
            payload = self.health()
            if query_params.get("debug") == "1":
                payload["diagnostics"] = collect_internal_diagnostics(self.db_path, self.storage_dir)
            return 200, resp_headers, payload

        if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
            _, raw_body = parse_json_payload(body, hook_nesting=True)
            res = process_settlement_webhook(
                self.db_path, req_headers, raw_body, now_override=now_ov,
                db=self.shared.db, shared=self.shared,
            )
            return 200, resp_headers, res

        caller = authenticate_caller(
            self.db_path, req_headers, now_override=now_ov, db=self.shared.db, shared=self.shared,
        )
        db = self.shared.db
        now_ts = caller.request_ts
        bind_caller(caller)

        if req_method == "GET" and route == "/api/v1/docs/search":
            limit = min(_int_param(query_params, "limit", DEFAULT_PAGE_LIMIT), 1000)
            offset = _int_param(query_params, "offset", 0)
            res = search_documents(
                self.db_path,
                caller,
                query=query_params.get("q", ""),
                category=query_params.get("category", ""),
                tag_filter=query_params.get("tag_filter", ""),
                deduplicate=query_params.get("deduplicate", "1") != "0",
                sort_by=query_params.get("sort_by", "score"),
                sort_dir=query_params.get("sort_dir", "desc"),
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
            doc_ids = data.get("doc_ids") or []
            res = batch_get_documents(self.db_path, caller, doc_ids)
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
                starts_at=_int_param(data, "starts_at", 0) if isinstance(data, dict) else 0,
                expires_at=_int_param(data, "expires_at", 0) if isinstance(data, dict) else 0,
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
                store=self.shared.contagion,
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
                amount=strict_int(data.get("amount", 1), name="amount"),
            )
            return (200 if res.get("accepted") else 409), resp_headers, res

        if req_method == "POST" and route == "/api/v1/quotas/transfer":
            data, _ = parse_json_payload(body)
            res = transfer_tenant_quota(
                self.db_path,
                caller,
                from_quota=str(data.get("from_quota") or ""),
                to_quota=str(data.get("to_quota") or ""),
                amount=strict_int(data.get("amount", 0), name="amount"),
            )
            return (200 if res.get("transferred") else 409), resp_headers, res

        if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
            data, _ = parse_json_payload(body)
            res = redeem_override_token(
                self.db_path,
                caller,
                token_id=str(data.get("token_id") or ""),
                tx_ref=str(data.get("tx_ref") or ""),
            )
            return (200 if res.get("redeemed") else 409), resp_headers, res

        if req_method == "GET" and route == "/api/v1/audit/export-digest":
            res = export_audit_digest(
                self.db_path,
                caller,
                start_ts=_opt_ts(query_params, "start_ts"),
                end_ts=_opt_ts(query_params, "end_ts"),
                severity=query_params.get("severity", ""),
                sample_limit=_int_param(query_params, "sample_limit", 10),
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
                sample_limit=strict_int(data.get("sample_limit", 10), name="sample_limit"),
            )
            return 200, resp_headers, res

        if req_method == "GET" and route == "/api/v1/audit/render-report":
            res = render_saved_report(
                self.db_path,
                caller,
                template_id=query_params.get("template_id", ""),
                start_ts=_opt_ts(query_params, "start_ts"),
                end_ts=_opt_ts(query_params, "end_ts"),
            )
            return 200, resp_headers, res

        if req_method == "GET" and route == "/api/v1/audit/snapshots":
            res = read_compliance_snapshot(self.storage_dir, caller, query_params.get("snapshot_name", ""))
            return 200, resp_headers, res

        if req_method == "GET" and route == "/api/v1/internal/diagnostics":
            # 仅运维专用网络可访问（默认回环绑定）；内容对各租户操作员等同，且已剔除密钥/路径/租户明文
            if not _is_local_peer(req_headers):
                raise PermissionError("Internal diagnostics available on loopback network only")
            return 200, resp_headers, collect_internal_diagnostics(self.db_path, self.storage_dir)

        return 404, resp_headers, {"error": "ROUTE_NOT_FOUND", "path": route}


def _is_local_peer(headers: dict[str, str]) -> bool:
    """诊断端点来源判定：只信任由本地 HTTP 传输层注入的对端地址（不可由客户端头伪造外部身份）。"""
    peer = (headers.get("x-aegis-peer-addr") or "").strip() if headers else ""
    if not peer:
        return False
    try:
        addr = ipaddress.ip_address(peer.rsplit(":", 1)[0] if ":" in peer else peer)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
    return AegisGateway(db_path=db_path, storage_dir=storage_dir)


def build_http_server(
    gateway: AegisGateway,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    class GatewayHTTPHandler(BaseHTTPRequestHandler):
        server_version = "aegis-gateway"
        sys_version = ""

        def _dispatch(self) -> None:
            try:
                raw_len = self.headers.get("Content-Length") or "0"
                content_len = int(raw_len)
            except (TypeError, ValueError):
                content_len = -1
            if content_len < 0 or content_len > MAX_BODY_BYTES:
                payload = {"error": "BAD_REQUEST", "message": "Request body exceeds size limit"}
                self._write(413, payload)
                self.close_connection = True
                return
            raw_body = self.rfile.read(content_len) if content_len > 0 else b""
            hdrs = {k: v for k, v in self.headers.items()}
            # 传输层注入真实对端地址（覆盖任何客户端伪造的同名头）
            try:
                peer_addr = str(self.client_address[0]) if self.client_address else ""
            except (IndexError, TypeError):
                peer_addr = ""
            hdrs["X-Aegis-Peer-Addr"] = peer_addr
            try:
                status, resp_hdrs, payload = gateway.request(
                    self.command, self.path, headers=hdrs, body=raw_body,
                )
            except Exception:  # noqa: BLE001
                status, resp_hdrs, payload = 500, {}, {"error": "INTERNAL_SERVER_ERROR"}
            self._write(status, payload, resp_hdrs)

        def _write(self, status: int, payload: dict[str, Any], resp_hdrs: dict[str, str] | None = None) -> None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            for hk, hv in (resp_hdrs or {}).items():
                if hk.lower() == "content-type":
                    continue
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
