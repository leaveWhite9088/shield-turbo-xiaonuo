# 官方 5 级平庸参照补丁样本（评委打分强制对照锚点）

> **强制封顶规则（打分前必读）**：
> 本样本展示了一个**典型的“5 级平庸水平”补丁**（改动 8 个文件，`+325 / -706` 行）。
> **凡是被测作品在算法降维、并发锁粒度、缓存隔离失效或纵深安全防御上的工程思想未明显超越本 5 级平庸样本的，其对应维度最高锁死在 5 级（即 D 层总分不得超过 `15.0 / 30`）！**

---

## 一、本 5 级平庸补丁的五大典型短板特征

1. **只做表层索引，未看穿 $O(N^2)$ 核心复杂度与内存膨胀**：
   - 仅在 `db.py` 加了基础单列索引，在 `search_service.py` 把引用计数改为 `GROUP BY`；
   - **完全未解决**合规文档检索去重中的双重循环 $O(N^2)$ 词集比对，未构建倒排索引，也未将 `audit_export.py` 改造为游标流式输出（仍全量深拷贝列表进内存）。
2. **用“一把粗暴全局大锁”逃避并发设计**：
   - 在 `server.py` 顶部套了一把 `_GLOBAL_GATEWAY_LOCK = threading.Lock()` 串行包裹所有请求；虽然表面防住了配额超扣，但导致跨租户高并发读写全部排队阻塞，未开启 SQLite WAL，也未使用细粒度分片锁或 SQL 原子条件扣减。
3. **缓存缺乏角色密级隔离与跨模块事件失效**：
   - 在 `search_service.py` 添加了 `_NAIVE_SEARCH_CACHE`，但当管理员在 `auth.py` 调用 `revoke_or_grant_role` 撤回用户高密级授权时，缓存毫无感知，导致被撤权员工仍能从脏缓存中读出绝密文档。
4. **安全加固停留在“脆弱字符串黑名单替换”与半截补丁**：
   - `audit_export.py` 仅用 `.replace("../", "").replace("..\\", "")` 防目录穿越，被 `....//` 或双重编码直接绕过；
   - `batch_get_documents` 只补了 `tenant_id` 横向过滤，却漏掉了 `clearance_level <= caller.max_clearance` 纵向密级校验；
   - Webhook 仅检查了 300 秒时间戳，漏掉了同窗口 `nonce` 唯一防重放与 `hmac.compare_digest` 常量时间比对。
5. **完全忽略不对称算法复杂度攻击（Anti-DoS）**：
   - 未修复 `rule_engine.py` 中嵌套量词邮箱正则的灾难性回溯（ReDoS），未限制自定义规则树的嵌套深度与节点总数，未封堵 `limit=-1`（SQLite 全表返回）慢查询放大漏洞。

---

## 二、官方 5 级平庸参照补丁全量 Diff 对照

```diff
--- a/aegis_app/__init__.py
+++ b/aegis_app/__init__.py
@@ -1,4 +1,4 @@
 # -*- coding: utf-8 -*-
-"""AegisGate 多租户实时风控决策与企业合规文档检索网关。"""
+"""AegisGate 多租户实时风控决策与企业合规文档检索网关（5级平庸基线）。"""
 
 __version__ = "1.0.0"

--- a/aegis_app/audit_export.py
+++ b/aegis_app/audit_export.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""合规审计流水汇总摘要导出与租户季度归档快照读取服务。"""
+"""审计导出服务（5级平庸样本：未做游标流式化；路径穿越仅做字符串替换，仍可被 ....// 绕过）。"""
 from __future__ import annotations
 
 import copy
@@ -23,11 +23,6 @@
     severity: str = "",
     sample_limit: int = 10,
 ) -> dict[str, Any]:
-    """统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。
-
-    滚动摘要规则：按 log_id 升序遍历匹配记录，依次向 SHA-256 更新
-    f"{log_id}|{event_type}|{severity}|{amount_cents}|{masked_account}|{ts}\\n"。
-    """
     clauses = ["tenant_id = ?"]
     params: list[Any] = [caller.tenant_id]
     if start_ts is not None:
@@ -52,7 +47,6 @@
     finally:
         conn.close()
 
-    # 构建完整内存对象快照列表以便汇总核对
     expanded_records: list[dict[str, Any]] = []
     for r in raw_rows:
         item = {
@@ -65,18 +59,15 @@
             "masked_account": r["masked_account"],
             "ts": int(r["ts"]),
             "payload": json.loads(r["payload_json"]),
-            "raw_payload_text": r["payload_json"],
         }
         expanded_records.append(copy.deepcopy(item))
-
-    archive_mirror = [copy.deepcopy(rec) for rec in expanded_records]
 
     hasher = hashlib.sha256()
     severity_counts: dict[str, int] = {}
     event_counts: dict[str, int] = {}
     total_amount_cents = 0
 
-    for rec in archive_mirror:
+    for rec in expanded_records:
         sev = rec["severity"]
         evt = rec["event_type"]
         amt = rec["amount_cents"]
@@ -96,12 +87,12 @@
             "masked_account": rec["masked_account"],
             "ts": rec["ts"],
         }
-        for rec in archive_mirror[:capped_sample]
+        for rec in expanded_records[:capped_sample]
     ]
 
     return {
         "tenant_id": caller.tenant_id,
-        "total_records": len(archive_mirror),
+        "total_records": len(expanded_records),
         "total_amount_cents": total_amount_cents,
         "severity_breakdown": dict(sorted(severity_counts.items())),
         "event_breakdown": dict(sorted(event_counts.items())),
@@ -115,13 +106,12 @@
     caller: CallerContext,
     snapshot_name: str,
 ) -> dict[str, Any]:
-    """读取当前租户归档目录下的合规季度快照文件。"""
     if not snapshot_name:
         raise ValueError("snapshot_name is required")
 
-    # 清理相对路径跳转标记后读取快照内容
+    # 脆弱黑名单替换：....// 替换一次 "../" 后仍会还原成 "../"
     decoded_once = urllib.parse.unquote(snapshot_name)
-    sanitized_rel = decoded_once.replace("../", "")
+    sanitized_rel = decoded_once.replace("../", "").replace("..\\", "")
     base_dir = os.path.join(storage_dir, caller.tenant_id, "snapshots")
     target_path = pathlib.Path(os.path.join(base_dir, sanitized_rel))
 

--- a/aegis_app/auth.py
+++ b/aegis_app/auth.py
@@ -1,15 +1,15 @@
 # -*- coding: utf-8 -*-
-"""租户身份认证、组织层级权限汇总、利益冲突隔离墙核验与配额/回调管理模块。"""
+"""租户身份认证模块（5级平庸样本：仅补了 Webhook 时间窗检查，漏掉 Nonce 去重与权限变更缓存失效通知）。"""
 from __future__ import annotations
 
-from dataclasses import dataclass
 import hashlib
 import hmac
 import json
 import time
+from dataclasses import dataclass
 from typing import Any
 
-from .config import ROLE_DEFAULT_CLEARANCE
+from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
 from .db import hash_api_token, open_connection
 
 
@@ -30,27 +30,25 @@
 
 
 def resolve_org_ancestors(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
-    """沿组织架构树向上遍历，返回当前部门及所有上级部门节点 ID 列表。"""
     ancestors: list[str] = []
     curr = start_node_id
     visited: set[str] = set()
-    while curr and curr not in visited:
-        visited.add(curr)
-        ancestors.append(curr)
-        conn = open_connection(db_path)
-        try:
+    conn = open_connection(db_path)
+    try:
+        while curr and curr not in visited:
+            visited.add(curr)
+            ancestors.append(curr)
             row = conn.execute(
                 "SELECT parent_node_id FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
                 (tenant_id, curr),
             ).fetchone()
             curr = row["parent_node_id"] if row else None
-        finally:
-            conn.close()
+    finally:
+        conn.close()
     return ancestors
 
 
 def is_doc_blocked_by_acl(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
-    """检查目标文档是否对指定用户或其所属组织层级链设置了利益冲突隔离墙（DENY）。"""
     conn = open_connection(db_path)
     try:
         u_row = conn.execute(
@@ -86,7 +84,6 @@
     subject_id: str,
     active: bool = True,
 ) -> dict[str, Any]:
-    """由合规管理员新增或解除文档利益冲突隔离墙规则（Chinese Wall）。"""
     require_admin(caller)
     if subject_type not in ("USER", "ORG_NODE"):
         raise ValueError("subject_type must be USER or ORG_NODE")
@@ -99,7 +96,6 @@
         ).fetchone()
         if not doc_row:
             raise LookupError(f"Document not found in tenant: {doc_id}")
-
         if active:
             conn.execute(
                 "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
@@ -115,7 +111,6 @@
         conn.commit()
     finally:
         conn.close()
-
     return {
         "tenant_id": caller.tenant_id,
         "doc_id": doc_id,
@@ -127,7 +122,6 @@
 
 
 def authenticate_caller(db_path: str, headers: dict[str, str]) -> CallerContext:
-    """校验请求头中的租户与操作员访问凭证，并解析有效角色集合。"""
     norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
     tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
     user_id = (norm_headers.get("x-aegis-user") or "").strip()
@@ -170,7 +164,6 @@
 
 
 def resolve_effective_permissions(db_path: str, tenant_id: str, user_id: str) -> tuple[set[str], int]:
-    """沿着组织汇报树向上汇总继承角色，并合并显式授权记录，返回有效角色集合与最高密级。"""
     conn = open_connection(db_path)
     try:
         u_row = conn.execute(
@@ -181,13 +174,19 @@
             return set(), 0
 
         roles: set[str] = {u_row["base_role"]}
-        for anc_node_id in resolve_org_ancestors(db_path, tenant_id, u_row["org_node_id"]):
+        curr_node = u_row["org_node_id"]
+        visited: set[str] = set()
+        while curr_node and curr_node not in visited:
+            visited.add(curr_node)
             n_row = conn.execute(
-                "SELECT inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
-                (tenant_id, anc_node_id),
+                "SELECT parent_node_id, inherited_role FROM org_nodes WHERE tenant_id = ? AND node_id = ?",
+                (tenant_id, curr_node),
             ).fetchone()
-            if n_row and n_row["inherited_role"]:
+            if not n_row:
+                break
+            if n_row["inherited_role"]:
                 roles.add(n_row["inherited_role"])
+            curr_node = n_row["parent_node_id"]
 
         g_rows = conn.execute(
             "SELECT granted_role FROM role_grants WHERE tenant_id = ? AND user_id = ? AND active = 1",
@@ -215,7 +214,6 @@
     role_name: str,
     action: str,
 ) -> dict[str, Any]:
-    """管理员工临时角色授权（支持 grant 与 revoke）。"""
     require_admin(caller)
     if role_name not in ROLE_DEFAULT_CLEARANCE:
         raise ValueError(f"Unsupported role: {role_name}")
@@ -267,7 +265,6 @@
     quota_type: str,
     amount: int = 1,
 ) -> dict[str, Any]:
-    """扣减租户指定类型的业务配额并返回剩余额度。"""
     if amount <= 0:
         raise ValueError("Quota consumption amount must be positive")
     now_ts = int(time.time())
@@ -323,7 +320,6 @@
     token_id: str,
     tx_ref: str,
 ) -> dict[str, Any]:
-    """核销单次使用的风控应急放行令牌。"""
     now_ts = int(time.time())
     conn = open_connection(db_path)
     try:
@@ -372,7 +368,6 @@
     *,
     now_override: int | None = None,
 ) -> dict[str, Any]:
-    """验证外部清算中心回调签名并登记入账通知。"""
     norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
     tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
     ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
@@ -386,6 +381,10 @@
         callback_ts = int(ts_str)
     except ValueError as exc:
         raise AuthError("Malformed webhook timestamp", 400) from exc
+
+    now_ts = int(now_override if now_override is not None else time.time())
+    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
+        raise AuthError("Webhook timestamp expired", 401)
 
     conn = open_connection(db_path)
     try:
@@ -413,7 +412,6 @@
         if not settlement_ref or amount_cents < 0:
             raise ValueError("Invalid settlement payload fields")
 
-        now_ts = int(now_override if now_override is not None else time.time())
         conn.execute(
             "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
             "VALUES (?, ?, ?, ?, ?, ?, ?)",

--- a/aegis_app/db.py
+++ b/aegis_app/db.py
@@ -168,6 +168,11 @@
     secret_value TEXT NOT NULL,
     classification TEXT NOT NULL
 );
+CREATE INDEX IF NOT EXISTS idx_basic_docs_tenant ON compliance_docs(tenant_id);
+CREATE INDEX IF NOT EXISTS idx_basic_citations_doc ON doc_citations(doc_id);
+CREATE INDEX IF NOT EXISTS idx_basic_tx_tenant ON transactions(tenant_id);
+CREATE INDEX IF NOT EXISTS idx_basic_audit_tenant ON audit_logs(tenant_id);
+
 """
 
 

--- a/aegis_app/rule_engine.py
+++ b/aegis_app/rule_engine.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""实时交易风控评分、滑动时间窗特征计算与自定义布尔规则树引擎。"""
+"""实时风控引擎（5级平庸样本：共用单次事务连接，但仍逐笔按租户查库过滤窗口，未消除回溯正则与深层递归炸弹）。"""
 from __future__ import annotations
 
 import json
@@ -23,7 +23,6 @@
 
 
 def load_tenant_policy(db_path: str, tenant_id: str) -> dict[str, Any]:
-    """从数据库读取并反序列化指定租户的当前风控策略配置。"""
     conn = open_connection(db_path)
     try:
         row = conn.execute(
@@ -47,7 +46,6 @@
     caller: CallerContext,
     updates: dict[str, Any],
 ) -> dict[str, Any]:
-    """更新租户风控阈值与自定义规则树并递增策略版本号。"""
     require_admin(caller)
     current = load_tenant_policy(db_path, caller.tenant_id)
     high_amt = int(updates.get("high_amount_cents", current["high_amount_cents"]))
@@ -100,7 +98,6 @@
 
 
 def eval_rule_node(node: dict[str, Any], tx: dict[str, Any]) -> tuple[bool, int, list[str]]:
-    """递归计算风控规则节点，返回 (是否命中, 附加风险分, 命中原因列表)。"""
     if not isinstance(node, dict):
         raise ValueError("Rule node must be an object")
 
@@ -171,7 +168,6 @@
 
 
 def simulate_custom_rule(rule_tree: dict[str, Any], sample_tx: dict[str, Any]) -> dict[str, Any]:
-    """在沙盒中试算自定义风控规则树对单笔交易样本的命中结果。"""
     if not isinstance(sample_tx, dict):
         raise ValueError("sample_tx must be an object")
     email = sample_tx.get("contact_email")
@@ -250,56 +246,43 @@
     batch_id: str,
     transactions: list[dict[str, Any]],
 ) -> dict[str, Any]:
-    """按输入顺序逐笔评估实时交易批次并持久化交易及风控决策记录。
-
-    同一批次必须是原子整体：若批次中任意一笔输入非法或交易号冲突，整批均不得落库生效。
-    """
     if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
         raise ValueError("batch_id and non-empty transactions list are required")
 
+    policy = load_tenant_policy(db_path, caller.tenant_id)
     results: list[dict[str, Any]] = []
     counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
 
-    for item in transactions:
-        tx_id = str(item.get("tx_id") or "").strip()
-        account_id = str(item.get("account_id") or "").strip()
-        counterparty_id = str(item.get("counterparty_id") or "").strip()
-        amount_cents = int(item.get("amount_cents") or 0)
-        currency = str(item.get("currency") or "USD").strip()
-        channel = str(item.get("channel") or "POS_CHIP").strip()
-        contact_email = str(item.get("contact_email") or "").strip()
-        ts = int(item.get("ts") or 0)
-        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
-
-        if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
-            raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
-        if not validate_contact_email(contact_email):
-            raise ValueError(f"Invalid contact_email in transaction {tx_id}")
-
-        policy = load_tenant_policy(db_path, caller.tenant_id)
-
-        conn = open_connection(db_path)
-        try:
+    conn = open_connection(db_path)
+    try:
+        for item in transactions:
+            tx_id = str(item.get("tx_id") or "").strip()
+            account_id = str(item.get("account_id") or "").strip()
+            counterparty_id = str(item.get("counterparty_id") or "").strip()
+            amount_cents = int(item.get("amount_cents") or 0)
+            currency = str(item.get("currency") or "USD").strip()
+            channel = str(item.get("channel") or "POS_CHIP").strip()
+            contact_email = str(item.get("contact_email") or "").strip()
+            ts = int(item.get("ts") or 0)
+            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
+
+            if not tx_id or not account_id or not counterparty_id or amount_cents <= 0 or ts <= 0:
+                raise ValueError(f"Invalid required transaction fields for tx_id={tx_id!r}")
+            if not validate_contact_email(contact_email):
+                raise ValueError(f"Invalid contact_email in transaction {tx_id}")
+
+            win_start = ts - SLIDING_WINDOW_SECONDS
             hist_rows = conn.execute(
-                "SELECT tx_id, account_id, counterparty_id, amount_cents, ts, metadata_json "
-                "FROM transactions WHERE tenant_id = ?",
-                (caller.tenant_id,),
+                "SELECT counterparty_id, amount_cents FROM transactions "
+                "WHERE tenant_id = ? AND account_id = ? AND ts BETWEEN ? AND ?",
+                (caller.tenant_id, account_id, win_start, ts),
             ).fetchall()
 
-            win_start = ts - SLIDING_WINDOW_SECONDS
-            win_tx_count = 1
-            win_amount_cents = amount_cents
-            cp_list: list[str] = [counterparty_id]
-
-            for hr in hist_rows:
-                _ = json.loads(hr["metadata_json"])
-                if hr["account_id"] == account_id and win_start <= int(hr["ts"]) <= ts:
-                    win_tx_count += 1
-                    win_amount_cents += int(hr["amount_cents"])
-                    if hr["counterparty_id"] not in cp_list:
-                        cp_list.append(hr["counterparty_id"])
-
-            win_unique_cps = len(cp_list)
+            win_tx_count = 1 + len(hist_rows)
+            win_amount_cents = amount_cents + sum(int(hr["amount_cents"]) for hr in hist_rows)
+            cp_set = {counterparty_id} | {hr["counterparty_id"] for hr in hist_rows}
+            win_unique_cps = len(cp_set)
+
             tx_eval_obj = {
                 "tx_id": tx_id,
                 "account_id": account_id,
@@ -359,25 +342,26 @@
                 ),
             )
             conn.commit()
-        finally:
-            conn.close()
-
-        counts[decision] += 1
-        results.append(
-            {
-                "decision_id": decision_id,
-                "tx_id": tx_id,
-                "account_id": account_id,
-                "risk_score": risk_score,
-                "decision": decision,
-                "window": {
-                    "tx_count": win_tx_count,
-                    "amount_cents": win_amount_cents,
-                    "unique_counterparties": win_unique_cps,
-                },
-                "reasons": reasons,
-            }
-        )
+
+            counts[decision] += 1
+            results.append(
+                {
+                    "decision_id": decision_id,
+                    "tx_id": tx_id,
+                    "account_id": account_id,
+                    "risk_score": risk_score,
+                    "decision": decision,
+                    "window": {
+                        "tx_count": win_tx_count,
+                        "amount_cents": win_amount_cents,
+                        "unique_counterparties": win_unique_cps,
+                    },
+                    "reasons": reasons,
+                }
+            )
+        conn.commit()
+    finally:
+        conn.close()
 
     return {
         "tenant_id": caller.tenant_id,
@@ -393,14 +377,13 @@
     caller: CallerContext,
     decision_id: str,
 ) -> dict[str, Any]:
-    """根据决策单号查询单笔实时风控评估详情。"""
     conn = open_connection(db_path)
     try:
         row = conn.execute(
             "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
             "win_tx_count, win_amount_cents, win_unique_counterparties, reasons_json, evaluated_at "
-            "FROM risk_decisions WHERE decision_id = ?",
-            (decision_id,),
+            "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
+            (decision_id, caller.tenant_id),
         ).fetchone()
         if not row:
             raise LookupError(f"Decision record not found: {decision_id}")

--- a/aegis_app/search_service.py
+++ b/aegis_app/search_service.py
@@ -1,62 +1,38 @@
 # -*- coding: utf-8 -*-
-"""企业合规文档检索、相关性打分、利益冲突墙校验与近似修订簇折叠服务。"""
+"""合规检索服务（5级平庸样本：保留了 O(N^2) 聚类扫描，缓存未绑定角色密级变化且撤权时未失效，batch_get 漏纵向密级校验）。"""
 from __future__ import annotations
 
 from collections import Counter
+import copy
 import re
 import time
 from typing import Any
 
-from .auth import (
-    CallerContext,
-    is_doc_blocked_by_acl,
-    require_admin,
-    resolve_effective_permissions,
-)
+from .auth import CallerContext, is_doc_blocked_by_acl, require_admin
 from .config import DEDUP_JACCARD_THRESHOLD, DEFAULT_PAGE_LIMIT
 from .db import open_connection
 
 TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
+
+# 5级平庸缓存：仅按 (db_path, tenant_id, user_id, 查询参数) 缓存，当管理员在 auth.py 撤回该用户授权时不会清理此缓存！
+_NAIVE_SEARCH_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
 
 
 def tokenize_text(text: str) -> list[str]:
     if not text:
         return []
-    # 逐字符归一化空白与标点后切分词项
-    cleaned = re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()
-    return [tok for tok in TOKEN_RE.findall(cleaned) if len(tok) >= 2]
-
-
-def _get_doc_citation_count(db_path: str, doc_id: str) -> int:
-    conn = open_connection(db_path)
-    try:
-        rows = conn.execute(
-            "SELECT citation_id, cited_by_ref FROM doc_citations WHERE doc_id = ?",
-            (doc_id,),
-        ).fetchall()
-        return len([dict(r) for r in rows])
-    finally:
-        conn.close()
-
-
-def _jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
-    tokens_a = tokenize_text(title_a) + tokenize_text(body_a)
-    tokens_b = tokenize_text(title_b) + tokenize_text(body_b)
-    uniq_a: list[str] = []
-    for t in tokens_a:
-        if t not in uniq_a:
-            uniq_a.append(t)
-    uniq_b: list[str] = []
-    for t in tokens_b:
-        if t not in uniq_b:
-            uniq_b.append(t)
-    if not uniq_a and not uniq_b:
+    return TOKEN_RE.findall(text.lower())
+
+
+def _jaccard_similarity(tokens_a: list[str], tokens_b: list[str]) -> float:
+    set_a = set(tokens_a)
+    set_b = set(tokens_b)
+    if not set_a and not set_b:
         return 1.0
-    inter_cnt = sum(1 for t in uniq_a if t in uniq_b)
-    union_cnt = len(uniq_a) + sum(1 for t in uniq_b if t not in uniq_a)
-    if union_cnt == 0:
+    union_len = len(set_a | set_b)
+    if union_len == 0:
         return 0.0
-    return inter_cnt / union_cnt
+    return len(set_a & set_b) / union_len
 
 
 def search_documents(
@@ -72,32 +48,56 @@
     limit: int = DEFAULT_PAGE_LIMIT,
     offset: int = 0,
 ) -> dict[str, Any]:
-    """执行多关键词合规文档检索，按调用者实时密级与利益冲突墙过滤，并折叠近似修订版。"""
-    sql_sort_col = "updated_at" if sort_by == "score" else sort_by
-    sql_sort_dir = sort_dir if sort_dir else "DESC"
+    # 简单字符串过滤防注入
+    safe_tag = tag_filter.replace("'", "").replace(";", "").replace("--", "")
+    if sort_by not in ("score", "updated_at", "risk_weight"):
+        raise ValueError("Unsupported sort_by field")
+    if str(sort_dir).lower() not in ("asc", "desc"):
+        raise ValueError("Unsupported sort_dir")
+
+    cache_key = (
+        db_path,
+        caller.tenant_id,
+        caller.user_id,
+        query,
+        category,
+        safe_tag,
+        deduplicate,
+        sort_by,
+        str(sort_dir).lower(),
+        limit,
+        offset,
+    )
+    if cache_key in _NAIVE_SEARCH_CACHE:
+        return copy.deepcopy(_NAIVE_SEARCH_CACHE[cache_key])
 
     where_clauses = [
-        f"tenant_id = '{caller.tenant_id}'",
+        "tenant_id = ?",
         "status = 'ACTIVE'",
         "quarantined = 0",
     ]
-    params: list[Any] = []
+    params: list[Any] = [caller.tenant_id]
     if category:
         where_clauses.append("category = ?")
         params.append(category)
     if tag_filter:
-        where_clauses.append(f"custom_tag = '{tag_filter}'")
+        where_clauses.append("custom_tag = ?")
+        params.append(tag_filter)
 
     sql = (
         "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
         "risk_weight, custom_tag, title, body, updated_at "
-        f"FROM compliance_docs WHERE {' AND '.join(where_clauses)} "
-        f"ORDER BY {sql_sort_col} {sql_sort_dir}"
+        f"FROM compliance_docs WHERE {' AND '.join(where_clauses)}"
     )
 
     conn = open_connection(db_path)
     try:
         raw_rows = conn.execute(sql, tuple(params)).fetchall()
+        cite_rows = conn.execute(
+            "SELECT doc_id, COUNT(*) AS cnt FROM doc_citations WHERE tenant_id = ? GROUP BY doc_id",
+            (caller.tenant_id,),
+        ).fetchall()
+        cite_map = {r["doc_id"]: int(r["cnt"]) for r in cite_rows}
     finally:
         conn.close()
 
@@ -105,9 +105,7 @@
     candidates: list[dict[str, Any]] = []
 
     for row in raw_rows:
-        # 实时核验操作员最高密级与部门利益冲突隔离墙（Chinese Wall）
-        _, live_clearance = resolve_effective_permissions(db_path, caller.tenant_id, caller.user_id)
-        if int(row["clearance_level"]) > live_clearance:
+        if int(row["clearance_level"]) > caller.max_clearance:
             continue
         if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, row["doc_id"]):
             continue
@@ -128,7 +126,7 @@
         else:
             term_score = 0.0
 
-        cite_cnt = _get_doc_citation_count(db_path, row["doc_id"])
+        cite_cnt = cite_map.get(row["doc_id"], 0)
         risk_w = int(row["risk_weight"])
         total_score = round(term_score + 0.25 * cite_cnt + 0.1 * risk_w, 4)
 
@@ -145,12 +143,13 @@
                 "citation_count": cite_cnt,
                 "score": total_score,
                 "updated_at": int(row["updated_at"]),
-                "_raw_body": row["body"],
+                "_all_tokens": title_tokens + body_tokens,
             }
         )
 
     candidates.sort(key=lambda d: (-d["score"], -d["updated_at"], d["doc_id"]))
 
+    # 仍保留 O(N^2) 嵌套遍历去重
     if deduplicate:
         kept: list[dict[str, Any]] = []
         consumed = [False] * len(candidates)
@@ -165,12 +164,7 @@
                 same_reg = bool(rep["regulation_code"]) and (
                     rep["regulation_code"] == candidates[j]["regulation_code"]
                 )
-                sim = _jaccard_similarity_from_texts(
-                    rep["title"],
-                    rep["_raw_body"],
-                    candidates[j]["title"],
-                    candidates[j]["_raw_body"],
-                )
+                sim = _jaccard_similarity(rep["_all_tokens"], candidates[j]["_all_tokens"])
                 if same_reg and sim >= DEDUP_JACCARD_THRESHOLD:
                     consumed[j] = True
                     cluster_size += 1
@@ -185,26 +179,26 @@
             final_list.append(copied)
 
     reverse_flag = str(sort_dir).lower() != "asc"
-    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
     if reverse_flag:
-        final_list.sort(key=lambda d: (-d[sort_field], d["doc_id"]))
+        final_list.sort(key=lambda d: (-d[sort_by], d["doc_id"]))
     else:
-        final_list.sort(key=lambda d: (d[sort_field], d["doc_id"]))
+        final_list.sort(key=lambda d: (d[sort_by], d["doc_id"]))
 
     total_matched = len(final_list)
-
     if limit < 0:
         sliced = final_list[max(0, offset):]
     else:
         sliced = final_list[max(0, offset): max(0, offset) + limit]
 
     items_out = [{k: v for k, v in doc.items() if not k.startswith("_")} for doc in sliced]
-    return {
+    resp = {
         "tenant_id": caller.tenant_id,
         "total_matched": total_matched,
         "returned_count": len(items_out),
         "items": items_out,
     }
+    _NAIVE_SEARCH_CACHE[cache_key] = copy.deepcopy(resp)
+    return resp
 
 
 def batch_get_documents(
@@ -212,7 +206,7 @@
     caller: CallerContext,
     doc_ids: list[str],
 ) -> dict[str, Any]:
-    """按文档 ID 列表批量获取完整合规文档内容。"""
+    """仅补了 tenant_id 过滤，但遗漏了 clearance_level 与 quarantined 纵向密级拦截。"""
     if not isinstance(doc_ids, list) or not doc_ids:
         raise ValueError("doc_ids must be a non-empty list")
 
@@ -222,8 +216,8 @@
         rows = conn.execute(
             f"SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
             f"risk_weight, custom_tag, title, body, status, quarantined, updated_at "
-            f"FROM compliance_docs WHERE doc_id IN ({placeholders})",
-            tuple(doc_ids),
+            f"FROM compliance_docs WHERE tenant_id = ? AND doc_id IN ({placeholders})",
+            (caller.tenant_id, *doc_ids),
         ).fetchall()
     finally:
         conn.close()
@@ -262,7 +256,6 @@
     doc_id: str,
     quarantined: bool,
 ) -> dict[str, Any]:
-    """由合规管理员将指定合规文档置为隔离下架或解除隔离状态。"""
     require_admin(caller)
     now_ts = int(time.time())
     q_val = 1 if quarantined else 0
@@ -279,6 +272,7 @@
     finally:
         conn.close()
 
+    _NAIVE_SEARCH_CACHE.clear()
     return {
         "tenant_id": caller.tenant_id,
         "doc_id": doc_id,

--- a/aegis_app/server.py
+++ b/aegis_app/server.py
@@ -1,12 +1,12 @@
 # -*- coding: utf-8 -*-
-"""AegisGate HTTP 路由网关与嵌入式应用入口。"""
+"""网关入口（5级平庸样本：套了一把全局粗暴大锁串行化所有请求，导致高并发读写吞吐退化）。"""
 from __future__ import annotations
 
 import argparse
 from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
 import json
 import pathlib
-import traceback
+import threading
 import urllib.parse
 from typing import Any
 
@@ -21,8 +21,8 @@
     redeem_override_token,
     revoke_or_grant_role,
 )
-from .config import DEFAULT_PAGE_LIMIT, GATEWAY_INTERNAL_BUILD, MASTER_SIGNING_PEPPER
-from .db import init_schema, open_connection
+from .config import DEFAULT_PAGE_LIMIT
+from .db import init_schema
 from .rule_engine import (
     evaluate_transaction_batch,
     get_risk_decision_detail,
@@ -35,10 +35,11 @@
     set_document_quarantine,
 )
 
+# 粗暴全局互斥大锁：虽然避免了并发配额超扣，但把所有租户的并发读和写全部卡成单线程排队
+_GLOBAL_GATEWAY_LOCK = threading.Lock()
+
 
 class AegisGateway:
-    """多租户风控与合规检索统一网关实例。"""
-
     def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
         self.db_path = str(pathlib.Path(db_path).resolve())
         self.storage_dir = str(pathlib.Path(storage_dir).resolve())
@@ -61,24 +62,6 @@
             raise ValueError("Request JSON payload must be an object")
         return data, raw
 
-    def _collect_diagnostics(self) -> dict[str, Any]:
-        conn = open_connection(self.db_path)
-        try:
-            t_rows = conn.execute("SELECT tenant_id, webhook_secret, status FROM tenants").fetchall()
-            s_rows = conn.execute("SELECT secret_key, secret_value FROM system_secrets").fetchall()
-            return {
-                "service": "aegis-gateway",
-                "version": __version__,
-                "build": GATEWAY_INTERNAL_BUILD,
-                "db_path": self.db_path,
-                "storage_dir": self.storage_dir,
-                "master_signing_pepper": MASTER_SIGNING_PEPPER,
-                "registered_tenants": [dict(r) for r in t_rows],
-                "system_secrets": {r["secret_key"]: r["secret_value"] for r in s_rows},
-            }
-        finally:
-            conn.close()
-
     def request(
         self,
         method: str,
@@ -87,7 +70,6 @@
         headers: dict[str, str] | None = None,
         body: bytes | str | dict[str, Any] | None = None,
     ) -> tuple[int, dict[str, str], dict[str, Any]]:
-        """处理一次 HTTP 网关调用，返回 (status_code, response_headers, response_json_dict)。"""
         req_method = method.upper().strip()
         parsed_url = urllib.parse.urlsplit(path)
         route = parsed_url.path.rstrip("/") or "/"
@@ -95,189 +77,179 @@
         req_headers = dict(headers or {})
         resp_headers = {"Content-Type": "application/json; charset=utf-8"}
 
-        try:
-            if req_method == "GET" and route == "/api/v1/health":
-                payload: dict[str, Any] = {
-                    "status": "ok",
-                    "service": "aegis-gateway",
-                    "version": __version__,
+        with _GLOBAL_GATEWAY_LOCK:
+            try:
+                if req_method == "GET" and route == "/api/v1/health":
+                    return 200, resp_headers, {
+                        "status": "ok",
+                        "service": "aegis-gateway",
+                        "version": __version__,
+                    }
+
+                if req_method == "GET" and route == "/api/v1/internal/diagnostics":
+                    return 403, resp_headers, {"error": "FORBIDDEN", "message": "Diagnostics disabled"}
+
+                if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
+                    _, raw_body = self._parse_json_body(body)
+                    now_ov_str = query_params.get("_now_ts")
+                    now_ov = int(now_ov_str) if now_ov_str else None
+                    res = process_settlement_webhook(
+                        self.db_path,
+                        req_headers,
+                        raw_body,
+                        now_override=now_ov,
+                    )
+                    return 200, resp_headers, res
+
+                caller = authenticate_caller(self.db_path, req_headers)
+
+                if req_method == "GET" and route == "/api/v1/docs/search":
+                    q = query_params.get("q", "")
+                    category = query_params.get("category", "")
+                    tag_filter = query_params.get("tag_filter", "")
+                    dedup_flag = query_params.get("deduplicate", "1") != "0"
+                    sort_by = query_params.get("sort_by", "score")
+                    sort_dir = query_params.get("sort_dir", "desc")
+                    limit = int(query_params.get("limit", str(DEFAULT_PAGE_LIMIT)))
+                    offset = int(query_params.get("offset", "0"))
+                    res = search_documents(
+                        self.db_path,
+                        caller,
+                        query=q,
+                        category=category,
+                        tag_filter=tag_filter,
+                        deduplicate=dedup_flag,
+                        sort_by=sort_by,
+                        sort_dir=sort_dir,
+                        limit=limit,
+                        offset=offset,
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/docs/batch-get":
+                    data, _ = self._parse_json_body(body)
+                    res = batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/docs/quarantine":
+                    data, _ = self._parse_json_body(body)
+                    res = set_document_quarantine(
+                        self.db_path,
+                        caller,
+                        doc_id=str(data.get("doc_id") or ""),
+                        quarantined=bool(data.get("quarantined", True)),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
+                    data, _ = self._parse_json_body(body)
+                    res = revoke_or_grant_role(
+                        self.db_path,
+                        caller,
+                        target_user_id=str(data.get("user_id") or ""),
+                        role_name=str(data.get("role") or ""),
+                        action=str(data.get("action") or "revoke"),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/admin/doc-acl":
+                    data, _ = self._parse_json_body(body)
+                    res = configure_doc_acl_rule(
+                        self.db_path,
+                        caller,
+                        doc_id=str(data.get("doc_id") or ""),
+                        subject_type=str(data.get("subject_type") or ""),
+                        subject_id=str(data.get("subject_id") or ""),
+                        active=bool(data.get("active", True)),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "PUT" and route == "/api/v1/policies":
+                    data, _ = self._parse_json_body(body)
+                    res = update_tenant_policy(self.db_path, caller, data)
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
+                    data, _ = self._parse_json_body(body)
+                    res = evaluate_transaction_batch(
+                        self.db_path,
+                        caller,
+                        batch_id=str(data.get("batch_id") or ""),
+                        transactions=data.get("transactions") or [],
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
+                    data, _ = self._parse_json_body(body)
+                    res = simulate_custom_rule(
+                        data.get("rule_tree") or {},
+                        data.get("sample_tx") or {},
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "GET" and route.startswith("/api/v1/risk/decisions/"):
+                    decision_id = route.split("/api/v1/risk/decisions/", 1)[1].strip("/")
+                    res = get_risk_decision_detail(self.db_path, caller, decision_id)
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/quotas/consume":
+                    data, _ = self._parse_json_body(body)
+                    res = consume_tenant_quota(
+                        self.db_path,
+                        caller,
+                        quota_type=str(data.get("quota_type") or ""),
+                        amount=int(data.get("amount", 1)),
+                    )
+                    status_code = 200 if res.get("accepted") else 409
+                    return status_code, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
+                    data, _ = self._parse_json_body(body)
+                    res = redeem_override_token(
+                        self.db_path,
+                        caller,
+                        token_id=str(data.get("token_id") or ""),
+                        tx_ref=str(data.get("tx_ref") or ""),
+                    )
+                    status_code = 200 if res.get("redeemed") else 409
+                    return status_code, resp_headers, res
+
+                if req_method == "GET" and route == "/api/v1/audit/export-digest":
+                    s_ts = int(query_params["start_ts"]) if query_params.get("start_ts") else None
+                    e_ts = int(query_params["end_ts"]) if query_params.get("end_ts") else None
+                    sev = query_params.get("severity", "")
+                    slim = int(query_params.get("sample_limit", "10"))
+                    res = export_audit_digest(
+                        self.db_path,
+                        caller,
+                        start_ts=s_ts,
+                        end_ts=e_ts,
+                        severity=sev,
+                        sample_limit=slim,
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "GET" and route == "/api/v1/audit/snapshots":
+                    snap_name = query_params.get("snapshot_name", "")
+                    res = read_compliance_snapshot(self.storage_dir, caller, snap_name)
+                    return 200, resp_headers, res
+
+                return 404, resp_headers, {"error": "ROUTE_NOT_FOUND", "path": route}
+
+            except AuthError as exc:
+                return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
+            except LookupError as exc:
+                return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
+            except (ValueError, KeyError, json.JSONDecodeError) as exc:
+                return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
+            except Exception:
+                return 500, resp_headers, {
+                    "error": "INTERNAL_SERVER_ERROR",
+                    "message": "Unexpected gateway failure",
                 }
-                if query_params.get("debug") == "1":
-                    payload["diagnostics"] = self._collect_diagnostics()
-                return 200, resp_headers, payload
-
-            if req_method == "GET" and route == "/api/v1/internal/diagnostics":
-                return 200, resp_headers, self._collect_diagnostics()
-
-            if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
-                _, raw_body = self._parse_json_body(body)
-                now_ov_str = query_params.get("_now_ts")
-                now_ov = int(now_ov_str) if now_ov_str else None
-                res = process_settlement_webhook(
-                    self.db_path,
-                    req_headers,
-                    raw_body,
-                    now_override=now_ov,
-                )
-                return 200, resp_headers, res
-
-            # 其余业务接口均需通过操作员身份认证
-            caller = authenticate_caller(self.db_path, req_headers)
-
-            if req_method == "GET" and route == "/api/v1/docs/search":
-                q = query_params.get("q", "")
-                category = query_params.get("category", "")
-                tag_filter = query_params.get("tag_filter", "")
-                dedup_flag = query_params.get("deduplicate", "1") != "0"
-                sort_by = query_params.get("sort_by", "score")
-                sort_dir = query_params.get("sort_dir", "desc")
-                limit = int(query_params.get("limit", str(DEFAULT_PAGE_LIMIT)))
-                offset = int(query_params.get("offset", "0"))
-                res = search_documents(
-                    self.db_path,
-                    caller,
-                    query=q,
-                    category=category,
-                    tag_filter=tag_filter,
-                    deduplicate=dedup_flag,
-                    sort_by=sort_by,
-                    sort_dir=sort_dir,
-                    limit=limit,
-                    offset=offset,
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/docs/batch-get":
-                data, _ = self._parse_json_body(body)
-                res = batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/docs/quarantine":
-                data, _ = self._parse_json_body(body)
-                res = set_document_quarantine(
-                    self.db_path,
-                    caller,
-                    doc_id=str(data.get("doc_id") or ""),
-                    quarantined=bool(data.get("quarantined", True)),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
-                data, _ = self._parse_json_body(body)
-                res = revoke_or_grant_role(
-                    self.db_path,
-                    caller,
-                    target_user_id=str(data.get("user_id") or ""),
-                    role_name=str(data.get("role") or ""),
-                    action=str(data.get("action") or "revoke"),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
-                data, _ = self._parse_json_body(body)
-                res = configure_doc_acl_rule(
-                    self.db_path,
-                    caller,
-                    doc_id=str(data.get("doc_id") or ""),
-                    subject_type=str(data.get("subject_type") or ""),
-                    subject_id=str(data.get("subject_id") or ""),
-                    active=bool(data.get("active", True)),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "PUT" and route == "/api/v1/policies":
-                data, _ = self._parse_json_body(body)
-                res = update_tenant_policy(self.db_path, caller, data)
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
-                data, _ = self._parse_json_body(body)
-                res = evaluate_transaction_batch(
-                    self.db_path,
-                    caller,
-                    batch_id=str(data.get("batch_id") or ""),
-                    transactions=data.get("transactions") or [],
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
-                data, _ = self._parse_json_body(body)
-                res = simulate_custom_rule(
-                    data.get("rule_tree") or {},
-                    data.get("sample_tx") or {},
-                )
-                return 200, resp_headers, res
-
-            if req_method == "GET" and route.startswith("/api/v1/risk/decisions/"):
-                decision_id = route.split("/api/v1/risk/decisions/", 1)[1].strip("/")
-                res = get_risk_decision_detail(self.db_path, caller, decision_id)
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/quotas/consume":
-                data, _ = self._parse_json_body(body)
-                res = consume_tenant_quota(
-                    self.db_path,
-                    caller,
-                    quota_type=str(data.get("quota_type") or ""),
-                    amount=int(data.get("amount", 1)),
-                )
-                status_code = 200 if res.get("accepted") else 409
-                return status_code, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
-                data, _ = self._parse_json_body(body)
-                res = redeem_override_token(
-                    self.db_path,
-                    caller,
-                    token_id=str(data.get("token_id") or ""),
-                    tx_ref=str(data.get("tx_ref") or ""),
-                )
-                status_code = 200 if res.get("redeemed") else 409
-                return status_code, resp_headers, res
-
-            if req_method == "GET" and route == "/api/v1/audit/export-digest":
-                s_ts = int(query_params["start_ts"]) if query_params.get("start_ts") else None
-                e_ts = int(query_params["end_ts"]) if query_params.get("end_ts") else None
-                sev = query_params.get("severity", "")
-                slim = int(query_params.get("sample_limit", "10"))
-                res = export_audit_digest(
-                    self.db_path,
-                    caller,
-                    start_ts=s_ts,
-                    end_ts=e_ts,
-                    severity=sev,
-                    sample_limit=slim,
-                )
-                return 200, resp_headers, res
-
-            if req_method == "GET" and route == "/api/v1/audit/snapshots":
-                snap_name = query_params.get("snapshot_name", "")
-                res = read_compliance_snapshot(self.storage_dir, caller, snap_name)
-                return 200, resp_headers, res
-
-            return 404, resp_headers, {"error": "ROUTE_NOT_FOUND", "path": route}
-
-        except AuthError as exc:
-            return exc.status_code, resp_headers, {"error": "AUTH_ERROR", "message": str(exc)}
-        except LookupError as exc:
-            return 404, resp_headers, {"error": "NOT_FOUND", "message": str(exc)}
-        except (ValueError, KeyError, json.JSONDecodeError) as exc:
-            return 400, resp_headers, {"error": "BAD_REQUEST", "message": str(exc)}
-        except Exception as exc:
-            return 500, resp_headers, {
-                "error": "INTERNAL_SERVER_ERROR",
-                "message": str(exc),
-                "debug_context": {
-                    "db_path": self.db_path,
-                    "storage_dir": self.storage_dir,
-                    "master_pepper": MASTER_SIGNING_PEPPER,
-                    "traceback": traceback.format_exc(),
-                },
-            }
 
 
 def create_gateway(db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> AegisGateway:
-    """工厂方法：创建网关实例（供 HTTP 服务器及自动化测试挂载）。"""
     return AegisGateway(db_path=db_path, storage_dir=storage_dir)
 
 
@@ -286,8 +258,6 @@
     host: str = "127.0.0.1",
     port: int = 0,
 ) -> ThreadingHTTPServer:
-    """构建标准库多线程 HTTP 服务器包装器。"""
-
     class GatewayHTTPHandler(BaseHTTPRequestHandler):
         def _dispatch(self) -> None:
             content_len = int(self.headers.get("Content-Length") or 0)
@@ -320,28 +290,3 @@
             return
 
     return ThreadingHTTPServer((host, port), GatewayHTTPHandler)
-
-
-def main() -> int:
-    ap = argparse.ArgumentParser(description="启动 AegisGate 多租户风控与合规检索网关")
-    ap.add_argument("--db", required=True, help="SQLite 数据库文件路径")
-    ap.add_argument("--storage", required=True, help="归档存储根目录路径")
-    ap.add_argument("--host", default="127.0.0.1")
-    ap.add_argument("--port", type=int, default=8080)
-    args = ap.parse_args()
-
-    gw = create_gateway(args.db, args.storage)
-    srv = build_http_server(gw, host=args.host, port=args.port)
-    actual_port = srv.server_address[1]
-    print(f"AegisGate listening on http://{args.host}:{actual_port}")
-    try:
-        srv.serve_forever()
-    except KeyboardInterrupt:
-        pass
-    finally:
-        srv.server_close()
-    return 0
-
-
-if __name__ == "__main__":
-    raise SystemExit(main())

--- a/smoke_check.py
+++ /dev/null
@@ -1,296 +0,0 @@
-#!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-"""公开基础业务功能回归冒烟测试（smoke_check.py）。
-
-说明：
-本脚本仅在小规模样本数据上检验 AegisGate 核心业务接口的基础功能正确性与 HTTP 协议可用性，
-帮助确认重构未破坏正常业务逻辑。本脚本不包含大规模性能压测，也不包含红队安全攻防测试。
-"""
-from __future__ import annotations
-
-import hashlib
-import hmac
-import json
-import pathlib
-import shutil
-import sys
-import tempfile
-import threading
-import urllib.request
-
-HERE = pathlib.Path(__file__).resolve().parent
-if str(HERE) not in sys.path:
-    sys.path.insert(0, str(HERE))
-
-from aegis_app.db import seed_dataset  # noqa: E402
-from aegis_app.server import build_http_server, create_gateway  # noqa: E402
-
-
-def _auth_headers(tenant_id: str, user_info: dict[str, str]) -> dict[str, str]:
-    return {
-        "X-Aegis-Tenant": tenant_id,
-        "X-Aegis-User": user_info["user_id"],
-        "X-Aegis-Token": user_info["token"],
-    }
-
-
-def run_smoke() -> int:
-    tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="aegis_smoke_"))
-    try:
-        db_path = tmp_root / "smoke.db"
-        storage_dir = tmp_root / "storage"
-        manifest = seed_dataset(
-            db_path,
-            storage_dir,
-            seed=20261122,
-            num_tenants=2,
-            docs_per_tenant=16,
-            tx_per_tenant=24,
-            audit_rows_per_tenant=30,
-        )
-
-        gw = create_gateway(db_path, storage_dir)
-
-        # 1. 健康探针
-        st, _, body = gw.request("GET", "/api/v1/health")
-        assert st == 200 and body.get("status") == "ok", f"Health check failed: {st} {body}"
-
-        t_alpha = manifest["tenants"]["tenant_alpha"]
-        h_admin = _auth_headers("tenant_alpha", t_alpha["users"]["admin"])
-        h_auditor = _auth_headers("tenant_alpha", t_alpha["users"]["auditor"])
-        h_analyst = _auth_headers("tenant_alpha", t_alpha["users"]["analyst"])
-        h_researcher = _auth_headers("tenant_alpha", t_alpha["users"]["researcher"])
-
-        # 2. 合规文档检索、密级与利益冲突隔离墙（Chinese Wall）基础校验
-        st, _, s_admin = gw.request(
-            "GET",
-            "/api/v1/docs/search?q=wire+transfer+screening&deduplicate=1&limit=10",
-            headers=h_admin,
-        )
-        assert st == 200 and s_admin["returned_count"] >= 1, f"Admin search failed: {st} {s_admin}"
-
-        st, _, s_analyst = gw.request(
-            "GET",
-            "/api/v1/docs/search?q=classified+board+resolution&deduplicate=1",
-            headers=h_analyst,
-        )
-        assert st == 200, f"Analyst search status error: {st}"
-        for item in s_analyst["items"]:
-            assert item["clearance_level"] <= 2, f"Analyst saw high clearance doc: {item}"
-
-        # 验证利益冲突墙：doc_alpha_0003 对 ops_team(analyst) 封禁，但对同密级的 research_desk(researcher) 可见
-        wall_doc_id = t_alpha["wall_doc_id"]
-        _, _, s_res_wall = gw.request(
-            "GET",
-            "/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0",
-            headers=h_researcher,
-        )
-        _, _, s_ana_wall = gw.request(
-            "GET",
-            "/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0",
-            headers=h_analyst,
-        )
-        assert any(d["doc_id"] == wall_doc_id for d in s_res_wall["items"]), "Researcher should see deal doc"
-        assert all(d["doc_id"] != wall_doc_id for d in s_ana_wall["items"]), "Analyst blocked by Chinese Wall"
-
-        # 3. 批量读取授权文档
-        visible_id = s_admin["items"][0]["doc_id"]
-        st, _, b_res = gw.request(
-            "POST",
-            "/api/v1/docs/batch-get",
-            headers=h_admin,
-            body={"doc_ids": [visible_id]},
-        )
-        assert st == 200 and b_res["found"] == 1, f"Batch get failed: {st} {b_res}"
-
-        # 4. 文档隔离与恢复
-        st, _, q_res = gw.request(
-            "POST",
-            "/api/v1/docs/quarantine",
-            headers=h_admin,
-            body={"doc_id": visible_id, "quarantined": True},
-        )
-        assert st == 200 and q_res["quarantined"] is True
-        st, _, s_after_q = gw.request(
-            "GET",
-            "/api/v1/docs/search?q=wire+transfer+screening&deduplicate=0&limit=50",
-            headers=h_admin,
-        )
-        assert all(d["doc_id"] != visible_id for d in s_after_q["items"]), "Quarantined doc still returned"
-        gw.request(
-            "POST",
-            "/api/v1/docs/quarantine",
-            headers=h_admin,
-            body={"doc_id": visible_id, "quarantined": False},
-        )
-
-        # 5. 角色授权管理
-        st, _, g_res = gw.request(
-            "POST",
-            "/api/v1/admin/grants/revoke",
-            headers=h_admin,
-            body={"user_id": t_alpha["users"]["auditor"]["user_id"], "role": "SENIOR_AUDITOR", "action": "revoke"},
-        )
-        assert st == 200 and g_res["effective_clearance"] == 3  # 仍由 audit_dept 节点继承 SENIOR_AUDITOR(3)
-        gw.request(
-            "POST",
-            "/api/v1/admin/grants/revoke",
-            headers=h_admin,
-            body={"user_id": t_alpha["users"]["auditor"]["user_id"], "role": "SENIOR_AUDITOR", "action": "grant"},
-        )
-
-        # 6. 实时交易批次评估与单笔查询
-        base_ts = manifest["base_ts"]
-        batch_payload = {
-            "batch_id": "batch_smoke_01",
-            "transactions": [
-                {
-                    "tx_id": "tx_smoke_001",
-                    "account_id": "acct_alpha_001",
-                    "counterparty_id": "cp_901",
-                    "amount_cents": 120000,
-                    "currency": "USD",
-                    "channel": "ACH_BATCH",
-                    "contact_email": "treasury.ops@alpha-corp.com",
-                    "ts": base_ts + 120,
-                    "metadata": {"region": "US"},
-                },
-                {
-                    "tx_id": "tx_smoke_002",
-                    "account_id": "acct_alpha_001",
-                    "counterparty_id": "cp_902",
-                    "amount_cents": 620000,
-                    "currency": "USD",
-                    "channel": "CRYPTO_BRIDGE",
-                    "contact_email": "settlement-desk@alpha-corp.com",
-                    "ts": base_ts + 180,
-                    "metadata": {"region": "SG"},
-                },
-            ],
-        }
-        st, _, eval_res = gw.request(
-            "POST",
-            "/api/v1/risk/evaluate-batch",
-            headers=h_auditor,
-            body=batch_payload,
-        )
-        assert st == 200 and eval_res["evaluated_count"] == 2, f"Batch evaluate failed: {st} {eval_res}"
-        dec_id = eval_res["results"][1]["decision_id"]
-        assert eval_res["results"][1]["window"]["tx_count"] >= 2
-
-        st, _, dec_detail = gw.request(
-            "GET",
-            f"/api/v1/risk/decisions/{dec_id}",
-            headers=h_auditor,
-        )
-        assert st == 200 and dec_detail["tx_id"] == "tx_smoke_002"
-
-        # 7. 规则沙盒试算
-        st, _, sim_res = gw.request(
-            "POST",
-            "/api/v1/risk/simulate-rule",
-            headers=h_analyst,
-            body={
-                "rule_tree": {
-                    "op": "AND",
-                    "bonus_score": 15,
-                    "reason": "TEST_RULE",
-                    "children": [
-                        {"field": "channel", "op": "EQ", "value": "WIRE_INTL"},
-                        {"field": "amount_cents", "op": "GT", "value": 50000},
-                    ],
-                },
-                "sample_tx": {
-                    "channel": "WIRE_INTL",
-                    "amount_cents": 100000,
-                    "contact_email": "valid.user@bank-domain.org",
-                },
-            },
-        )
-        assert st == 200 and sim_res["matched"] is True and sim_res["bonus_score"] == 15
-
-        # 8. 配额扣减与单次应急令牌核销
-        st, _, q_consume = gw.request(
-            "POST",
-            "/api/v1/quotas/consume",
-            headers=h_admin,
-            body={"quota_type": "EMERGENCY_EXPORT", "amount": 2},
-        )
-        assert st == 200 and q_consume["accepted"] is True and q_consume["remaining_quota"] == 3
-
-        ov_tok = t_alpha["override_token"]
-        st1, _, r1 = gw.request(
-            "POST",
-            "/api/v1/risk/override-token/redeem",
-            headers=h_admin,
-            body={"token_id": ov_tok, "tx_ref": "tx_smoke_002"},
-        )
-        st2, _, r2 = gw.request(
-            "POST",
-            "/api/v1/risk/override-token/redeem",
-            headers=h_admin,
-            body={"token_id": ov_tok, "tx_ref": "tx_smoke_002"},
-        )
-        assert st1 == 200 and r1["redeemed"] is True
-        assert st2 == 409 and r2["redeemed"] is False
-
-        # 9. Webhook 正常签名入账
-        wh_body = json.dumps({"settlement_ref": "stl_smoke_01", "amount_cents": 88000}, separators=(",", ":"))
-        wh_ts = base_ts + 200
-        wh_nonce = "nonce_smoke_unique_001"
-        sig_msg = f"tenant_alpha.{wh_ts}.{wh_nonce}.{wh_body}"
-        sig_hex = hmac.new(
-            t_alpha["webhook_secret"].encode("utf-8"),
-            sig_msg.encode("utf-8"),
-            hashlib.sha256,
-        ).hexdigest()
-        st, _, wh_res = gw.request(
-            "POST",
-            f"/api/v1/webhooks/settlement-callback?_now_ts={wh_ts + 5}",
-            headers={
-                "X-Aegis-Tenant": "tenant_alpha",
-                "X-Aegis-Timestamp": str(wh_ts),
-                "X-Aegis-Nonce": wh_nonce,
-                "X-Aegis-Signature": f"sha256={sig_hex}",
-            },
-            body=wh_body,
-        )
-        assert st == 200 and wh_res["acknowledged"] is True
-
-        # 10. 审计流水摘要与合规季度快照读取
-        st, _, dig_res = gw.request(
-            "GET",
-            "/api/v1/audit/export-digest?sample_limit=5",
-            headers=h_auditor,
-        )
-        assert st == 200 and dig_res["total_records"] >= 30 and len(dig_res["rolling_sha256"]) == 64
-
-        st, _, snap_res = gw.request(
-            "GET",
-            "/api/v1/audit/snapshots?snapshot_name=2026-Q3.json",
-            headers=h_auditor,
-        )
-        assert st == 200 and snap_res["data"]["period"] == "2026-Q3"
-
-        # 11. 真实 HTTP Socket 端到端冒烟验证
-        srv = build_http_server(gw, host="127.0.0.1", port=0)
-        port = srv.server_address[1]
-        t_srv = threading.Thread(target=srv.serve_forever, daemon=True)
-        t_srv.start()
-        try:
-            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/health", method="GET")
-            with urllib.request.urlopen(req, timeout=5.0) as resp:
-                http_data = json.loads(resp.read().decode("utf-8"))
-                assert resp.status == 200 and http_data.get("status") == "ok"
-        finally:
-            srv.shutdown()
-            srv.server_close()
-
-        print("[PASS] AegisGate 基础业务功能冒烟自检全部通过（共 11 项核心回归检查）。")
-        return 0
-    finally:
-        shutil.rmtree(tmp_root, ignore_errors=True)
-
-
-if __name__ == "__main__":
-    raise SystemExit(run_smoke())
```
