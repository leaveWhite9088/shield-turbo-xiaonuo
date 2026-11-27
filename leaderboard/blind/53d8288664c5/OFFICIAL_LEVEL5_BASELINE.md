# 官方 5 级平庸参照补丁样本（评委打分强制对照锚点 · xiaonuo-v3.0）

> **强制封顶规则（打分前必读）**：
> 本样本展示了一个在 16 模块代码库上**典型的“5.0 级平庸水平”补丁**（改动 18 个文件，`+433 / -853` 行）。
> **凡是被测作品在增量算法降维、跨模块统一锁偏序、五维纪元与二级借调快照、或双通道二阶安全与抗复杂度熔断上的工程思想未明显超越本 5 级平庸样本的，其 D 层总分不得超过 `13.5 / 30`！**

---

## 一、本 5 级平庸补丁的五大典型短板特征

1. **只加基础单列索引，未解决高阶算法复杂度、双向引用增量传播与内存驻留**：
   - 仅在 `db.py` 加了 4 个单列索引，将引用读取合并为全表拉取；
   - **完全未解决**近似聚类去重的 $O(N^2)$ 两两比较、短语词距的 $O(P_1 \times P_2)$ 下标嵌套遍历、三跳制裁传染逐笔重新拉边建图与 `list.pop(0)` 搜索，且 `audit_export.py` 仍全量 `fetchall()` 大载荷列。
2. **用“一把全局粗暴大锁”逃避跨模块锁偏序与并发设计**：
   - 在 `server.py` 入口套了一把 `_GLOBAL_GATEWAY_LOCK` 串行化全站读写请求，未启用 SQLite WAL 与线程本地连接复用，更未针对 `transfer_tenant_quota` 与 `evaluate_transaction_batch`（`REJECT` 联动扣减 `REALTIME_ALERT_POOL`）设计全局升序分片锁与 `BEGIN IMMEDIATE` 单事务。
3. **无界粗糙缓存：一写即整库清空，二级借调上游到期/撤权/隔离墙变更却漏失效**：
   - `search_service.py` 的 `_NAIVE_SEARCH_CACHE` 在每次单篇 `upsert`/`retire`/`quarantine` 时粗暴清空全库缓存（高频混写下持续抖动），而在角色撤回、二级转借调上游一级窗口自然跨过 `expires_at`（零写操作）、源头委托人被撤权或利益冲突墙变更时毫无感知，导致严重脏读越权。
4. **只修表层查询拼接，漏掉双通道二阶注入、格式化反射/放大、跨租户引用侧信道与有向环路**：
   - 虽参数化了 `search_documents` 主查询并关闭了 `/diagnostics`，但漏掉了 `audit_export.py` 报表模板 `extra_event_filter` 的二阶 SQL 注入、`title_format.format(..., env=RUNTIME_ENV)` 的属性反射与 `:0>200000` 宽度内存放大，以及跨租户内部 `doc_` 引用存在性侧信道；
   - `delegation.py` 未做访问集合防环与跳数前置剪枝，遇到双向借调有向环路即触发无限递归栈崩溃；`batch_get_documents` 漏掉纵向密级与三级利益冲突墙；Webhook 漏掉 `nonce` 唯一防重放。
5. **未做四位一体强原子回滚与抗复杂度/数值边界熔断**：
   - `evaluate_transaction_batch` 逐笔独立扣减 `REALTIME_ALERT_POOL` 并提交（末尾交易失败会导致已扣告警配额永久泄漏，且脏边污染滑窗与三跳传染图）；未修邮箱与自定义规则 ReDoS（含花括号大上界与反向引用）、千层 JSON/膨胀规则树/超长引用洪水、`limit=-1` 放大及 `bool`/超 64 位整数/`NaN` 类型混淆。

---

## 二、官方 5 级平庸参照补丁全量 Diff 对照

```diff
--- a/aegis_app/__init__.py
+++ b/aegis_app/__init__.py
@@ -1,4 +1,4 @@
 # -*- coding: utf-8 -*-
-"""AegisGate 多租户实时风控决策与企业合规文档检索网关（v3.0）。"""
+"""AegisGate 多租户实时风控决策与企业合规文档检索网关（v3.0 · 5级平庸基线）。"""
 
 __version__ = "3.0.0"

--- a/aegis_app/acl_wall.py
+++ b/aegis_app/acl_wall.py
@@ -1,13 +1,5 @@
 # -*- coding: utf-8 -*-
-"""三级优先级利益冲突隔离墙（Chinese Wall）裁决引擎。
-
-裁决优先级规则（从高到低）：
-1. 个人显式豁免（subject_type='USER', effect='ALLOW'）—— 最高优先级直接放行；
-2. 个人显式封禁（subject_type='USER', effect='DENY'）—— 直接阻断；
-3. 组织层级就近原则（subject_type='ORG_NODE'）：沿操作员所在部门向根部逐级上溯，
-   采用距离操作员最近（深度最深）的第一个有规则节点的裁决结果（若同一节点同时存在 DENY 与 ALLOW，DENY 优先）；
-4. 若整条链路均无匹配规则，默认放行（返回 False 表示未封禁）。
-"""
+"""三级利益冲突隔离墙（5级平庸样本：逐篇文档重复打开连接回溯组织树，规则更新未清空检索缓存）。"""
 from __future__ import annotations
 
 import time
@@ -17,7 +9,6 @@
 
 
 def get_org_lineage(db_path: str, tenant_id: str, start_node_id: str) -> list[str]:
-    """按由近及远（当前部门 -> 父部门 -> 总部）顺序返回组织节点链。"""
     lineage: list[str] = []
     curr = start_node_id
     visited: set[str] = set()
@@ -37,7 +28,6 @@
 
 
 def is_doc_blocked_by_wall(db_path: str, tenant_id: str, user_id: str, doc_id: str) -> bool:
-    """按三级优先级判定指定操作员是否被利益冲突隔离墙禁止访问目标文档。"""
     conn = open_connection(db_path)
     try:
         u_row = conn.execute(
@@ -95,7 +85,6 @@
     effect: str = "DENY",
     active: bool = True,
 ) -> dict[str, Any]:
-    """配置或停用文档利益冲突隔离墙规则（支持 USER / ORG_NODE 与 DENY / ALLOW）。"""
     norm_type = str(subject_type or "").upper()
     norm_effect = str(effect or "DENY").upper()
     if norm_type not in ("USER", "ORG_NODE"):

--- a/aegis_app/audit_export.py
+++ b/aegis_app/audit_export.py
@@ -1,8 +1,7 @@
 # -*- coding: utf-8 -*-
-"""合规审计流水汇总摘要导出、自定义报表模板渲染与季度归档快照读取服务。"""
+"""审计导出与报表渲染（5级平庸样本：全量 fetchall，未拦截二阶模板 SQL 注入、format 反射与双重编码目录穿越）。"""
 from __future__ import annotations
 
-import copy
 import hashlib
 import json
 import os
@@ -21,55 +20,41 @@
     raw_rows: list[Any],
     sample_limit: int,
 ) -> dict[str, Any]:
-    expanded_records: list[dict[str, Any]] = []
-    for r in raw_rows:
-        item = {
-            "log_id": int(r["log_id"]),
-            "tenant_id": r["tenant_id"],
-            "actor_id": r["actor_id"],
-            "event_type": r["event_type"],
-            "severity": r["severity"],
-            "amount_cents": int(r["amount_cents"]),
-            "masked_account": r["masked_account"],
-            "ts": int(r["ts"]),
-            "payload": json.loads(r["payload_json"]),
-            "raw_payload_text": r["payload_json"],
-        }
-        expanded_records.append(copy.deepcopy(item))
-
-    archive_mirror = [copy.deepcopy(rec) for rec in expanded_records]
-
     hasher = hashlib.sha256()
     severity_counts: dict[str, int] = {}
     event_counts: dict[str, int] = {}
     total_amount_cents = 0
-
-    for rec in archive_mirror:
-        sev = rec["severity"]
-        evt = rec["event_type"]
-        amt = rec["amount_cents"]
+    capped_sample = max(0, min(int(sample_limit), 50))
+    samples: list[dict[str, Any]] = []
+
+    for r in raw_rows:
+        log_id = int(r["log_id"])
+        sev = r["severity"]
+        evt = r["event_type"]
+        amt = int(r["amount_cents"])
+        masked_acc = r["masked_account"]
+        ts = int(r["ts"])
+
         severity_counts[sev] = severity_counts.get(sev, 0) + 1
         event_counts[evt] = event_counts.get(evt, 0) + 1
         total_amount_cents += amt
-        line = f"{rec['log_id']}|{evt}|{sev}|{amt}|{rec['masked_account']}|{rec['ts']}\n"
-        hasher.update(line.encode("utf-8"))
-
-    capped_sample = max(0, min(int(sample_limit), 50))
-    samples = [
-        {
-            "log_id": rec["log_id"],
-            "event_type": rec["event_type"],
-            "severity": rec["severity"],
-            "amount_cents": rec["amount_cents"],
-            "masked_account": rec["masked_account"],
-            "ts": rec["ts"],
-        }
-        for rec in archive_mirror[:capped_sample]
-    ]
+        hasher.update(f"{log_id}|{evt}|{sev}|{amt}|{masked_acc}|{ts}\n".encode("utf-8"))
+
+        if len(samples) < capped_sample:
+            samples.append(
+                {
+                    "log_id": log_id,
+                    "event_type": evt,
+                    "severity": sev,
+                    "amount_cents": amt,
+                    "masked_account": masked_acc,
+                    "ts": ts,
+                }
+            )
 
     return {
         "tenant_id": tenant_id,
-        "total_records": len(archive_mirror),
+        "total_records": len(raw_rows),
         "total_amount_cents": total_amount_cents,
         "severity_breakdown": dict(sorted(severity_counts.items())),
         "event_breakdown": dict(sorted(event_counts.items())),
@@ -87,7 +72,6 @@
     severity: str = "",
     sample_limit: int = 10,
 ) -> dict[str, Any]:
-    """统计指定时间窗口内的审计事件分布并计算顺序滚动完整性校验哈希。"""
     clauses = ["tenant_id = ?"]
     params: list[Any] = [caller.tenant_id]
     if start_ts is not None:
@@ -124,11 +108,6 @@
     extra_event_filter: str = "",
     sample_limit: int = 10,
 ) -> dict[str, Any]:
-    """保存租户自定义审计汇总报表配置模板（供周期性渲染报表复用）。
-
-    合法 title_format 支持占位符 {tenant_id}、{total_records}、{total_amount_cents}；
-    extra_event_filter 为空字符串或目标事件类型名称（如 RISK_EVAL、DOC_ACCESS）。
-    """
     if "SENIOR_AUDITOR" not in caller.effective_roles and "COMPLIANCE_ADMIN" not in caller.effective_roles:
         require_admin(caller)
     tpl_id = str(template_id or "").strip()
@@ -168,7 +147,6 @@
     start_ts: int | None = None,
     end_ts: int | None = None,
 ) -> dict[str, Any]:
-    """读取已保存的报表模板并渲染生成带格式化标题的审计汇总报告。"""
     conn = open_connection(db_path)
     try:
         tpl = conn.execute(
@@ -179,14 +157,15 @@
         if not tpl:
             raise LookupError(f"Report template not found: {template_id}")
 
-        clauses = [f"tenant_id = '{caller.tenant_id}'"]
-        params: list[Any] = []
+        clauses = ["tenant_id = ?"]
+        params: list[Any] = [caller.tenant_id]
         if start_ts is not None:
             clauses.append("ts >= ?")
             params.append(int(start_ts))
         if end_ts is not None:
             clauses.append("ts <= ?")
             params.append(int(end_ts))
+        # 仍未修复从数据库读出的二阶过滤条件字符串拼接注入
         if tpl["extra_event_filter"]:
             clauses.append(f"event_type = '{tpl['extra_event_filter']}'")
 
@@ -218,12 +197,11 @@
     caller: CallerContext,
     snapshot_name: str,
 ) -> dict[str, Any]:
-    """读取当前租户归档目录下的合规季度快照文件。"""
     if not snapshot_name:
         raise ValueError("snapshot_name is required")
 
     decoded_once = urllib.parse.unquote(snapshot_name)
-    sanitized_rel = decoded_once.replace("../", "")
+    sanitized_rel = decoded_once.replace("../", "").replace("..\\", "")
     base_dir = os.path.join(storage_dir, caller.tenant_id, "snapshots")
     target_path = pathlib.Path(os.path.join(base_dir, sanitized_rel))
 

--- a/aegis_app/auth.py
+++ b/aegis_app/auth.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""租户身份认证、有效权限（含临时借调委托链）汇总与合作方回调验签门面模块。"""
+"""认证与权限管理（5级平庸样本：补了常量时间比较与回调时间窗，但漏了 nonce 唯一防重放，且撤权未失效缓存）。"""
 from __future__ import annotations
 
 from dataclasses import dataclass
@@ -10,7 +10,7 @@
 from typing import Any
 
 from .acl_wall import is_doc_blocked_by_wall, upsert_doc_acl_rule
-from .config import ROLE_DEFAULT_CLEARANCE
+from .config import ROLE_DEFAULT_CLEARANCE, WEBHOOK_TOLERANCE_SECONDS
 from .db import hash_api_token, open_connection
 from .delegation import (
     create_or_revoke_delegation,
@@ -43,7 +43,6 @@
     *,
     at_ts: int | None = None,
 ) -> tuple[set[str], int]:
-    """合并操作员原生角色、组织继承角色、显式授予角色以及在 at_ts 时刻有效且未级联失效的借调角色。"""
     eval_ts = int(at_ts if at_ts is not None else time.time())
     roles = resolve_base_and_explicit_roles(db_path, tenant_id, user_id)
     if not roles:
@@ -61,7 +60,6 @@
     *,
     now_override: int | None = None,
 ) -> CallerContext:
-    """校验请求头凭证并组装带实时借调权限的操作员上下文。"""
     norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
     tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
     user_id = (norm_headers.get("x-aegis-user") or "").strip()
@@ -88,7 +86,7 @@
         if not u_row or not u_row["active"]:
             raise AuthError("Invalid operator identity", 401)
 
-        if u_row["api_token_hash"] != hash_api_token(raw_token):
+        if not hmac.compare_digest(u_row["api_token_hash"], hash_api_token(raw_token)):
             raise AuthError("Invalid access token", 401)
 
         roles, max_cl = resolve_effective_permissions(
@@ -234,7 +232,6 @@
     *,
     now_override: int | None = None,
 ) -> dict[str, Any]:
-    """验证外部清算中心回调签名并登记入账通知。"""
     norm_headers = {k.lower(): v for k, v in (headers or {}).items()}
     tenant_id = (norm_headers.get("x-aegis-tenant") or "").strip()
     ts_str = (norm_headers.get("x-aegis-timestamp") or "").strip()
@@ -248,6 +245,10 @@
         callback_ts = int(ts_str)
     except ValueError as exc:
         raise AuthError("Malformed webhook timestamp", 400) from exc
+
+    now_ts = int(now_override if now_override is not None else time.time())
+    if abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS:
+        raise AuthError("Webhook timestamp expired", 401)
 
     conn = open_connection(db_path)
     try:
@@ -266,7 +267,7 @@
         ).hexdigest()
 
         provided_sig = sig_header.removeprefix("sha256=").strip()
-        if provided_sig != expected_sig:
+        if not hmac.compare_digest(provided_sig, expected_sig):
             raise AuthError("Webhook signature verification failed", 401)
 
         payload = json.loads(raw_body)
@@ -275,7 +276,7 @@
         if not settlement_ref or amount_cents < 0:
             raise ValueError("Invalid settlement payload fields")
 
-        now_ts = int(now_override if now_override is not None else time.time())
+        # 遗漏了 nonce 唯一性校验，时间窗内重放仍可重复入账
         conn.execute(
             "INSERT INTO webhook_events(tenant_id, nonce, callback_ts, settlement_ref, amount_cents, raw_payload, created_at) "
             "VALUES (?, ?, ?, ?, ?, ?, ?)",

--- a/aegis_app/config.py
+++ b/aegis_app/config.py
@@ -45,7 +45,7 @@
 
 @dataclass(frozen=True)
 class RuntimeEnvSettings:
-    """网关运行时环境元配置对象（供内部诊断与报表头格式化组件读取）。"""
+    """网关运行时环境元配置对象。"""
 
     service_name: str = "aegis-gateway"
     build_tag: str = GATEWAY_INTERNAL_BUILD

--- a/aegis_app/contagion_graph.py
+++ b/aegis_app/contagion_graph.py
@@ -1,16 +1,5 @@
 # -*- coding: utf-8 -*-
-"""三跳受制裁黑名单实体资金传染链路追踪（3-Hop Contagion Graph）与名单管理模块。
-
-图连通与传染跳数定义：
-- 在租户 24 小时活跃窗口 [ts - 86400, ts] 内，每笔交易 (account_id, counterparty_id) 构成一条双向资金关联边；
-- 当前正在评估的交易自身的边 (tx.account_id, tx.counterparty_id) 同步计入当前图；
-- 设活跃受制裁实体集合为 S（sanctioned_entities 表中 active=1 的 entity_id）：
-  * 若 tx.account_id in S 或 tx.counterparty_id in S（即本次交易两端直接命中制裁名单），则传染跳数 hop = 1；
-  * 否则计算 tx.account_id 与 tx.counterparty_id 到集合 S 中任意实体的最短无向边路径长度 d_min：
-    传染跳数 hop = d_min + 1（例如 tx.counterparty_id 曾与受制裁实体直接交易过，即 d_min = 1，则本次交易 hop = 2；
-    若隔一层中间跳板账户，d_min = 2，则本次交易 hop = 3）；
-  * 若 hop > 3 或不可达，记为 0（无三跳内制裁传染）。
-"""
+"""三跳制裁传染图追踪（5级平庸样本：每笔交易仍独立拉取窗口全量边重建邻接表并执行列表 BFS）。"""
 from __future__ import annotations
 
 import time
@@ -28,7 +17,6 @@
     counterparty_id: str,
     ts: int,
 ) -> int:
-    """在 [ts - 86400, ts] 活跃交易关联图上计算当前交易的三跳制裁传染等级（0 表示安全，1..3 表示对应跳数）。"""
     conn = open_connection(db_path)
     try:
         s_rows = conn.execute(
@@ -43,25 +31,22 @@
 
         win_start = ts - SLIDING_WINDOW_SECONDS
         tx_rows = conn.execute(
-            "SELECT account_id, counterparty_id, ts FROM transactions WHERE tenant_id = ?",
-            (tenant_id,),
+            "SELECT account_id, counterparty_id FROM transactions WHERE tenant_id = ? AND ts >= ? AND ts <= ?",
+            (tenant_id, win_start, ts),
         ).fetchall()
     finally:
         conn.close()
 
     adj: dict[str, list[str]] = {}
     for r in tx_rows:
-        r_ts = int(r["ts"])
-        if win_start <= r_ts <= ts:
-            u = r["account_id"]
-            v = r["counterparty_id"]
-            adj.setdefault(u, []).append(v)
-            adj.setdefault(v, []).append(u)
+        u = r["account_id"]
+        v = r["counterparty_id"]
+        adj.setdefault(u, []).append(v)
+        adj.setdefault(v, []).append(u)
 
     adj.setdefault(account_id, []).append(counterparty_id)
     adj.setdefault(counterparty_id, []).append(account_id)
 
-    # 从每个受制裁源点执行广度优先搜索，计算到达 account_id 或 counterparty_id 的最小边距离
     best_hop = 0
     for src in sanctioned:
         if src not in adj:
@@ -94,7 +79,6 @@
     list_source: str = "OFAC_SDN",
     active: bool = True,
 ) -> dict[str, Any]:
-    """由合规管理员实时新增、激活或移除租户受制裁实体黑名单。"""
     require_admin(caller)
     ent = str(entity_id or "").strip()
     if not ent:

--- a/aegis_app/db.py
+++ b/aegis_app/db.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""SQLite 存储模型定义与确定性多租户业务种子初始化器。"""
+"""SQLite 存储层（5级平庸样本：仅添加基础单列索引，未开启 WAL 或连接池复用）。"""
 from __future__ import annotations
 
 import hashlib
@@ -214,6 +214,13 @@
 );
 """
 
+BASIC_INDEXES_SQL = """
+CREATE INDEX IF NOT EXISTS idx_l5_docs_tenant ON compliance_docs(tenant_id);
+CREATE INDEX IF NOT EXISTS idx_l5_citations_doc ON doc_citations(doc_id);
+CREATE INDEX IF NOT EXISTS idx_l5_tx_tenant ON transactions(tenant_id);
+CREATE INDEX IF NOT EXISTS idx_l5_audit_tenant ON audit_logs(tenant_id);
+"""
+
 
 def hash_api_token(raw_token: str) -> str:
     return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
@@ -231,6 +238,7 @@
     conn = open_connection(path)
     try:
         conn.executescript(SCHEMA_SQL)
+        conn.executescript(BASIC_INDEXES_SQL)
         conn.commit()
     finally:
         conn.close()
@@ -268,7 +276,6 @@
     audit_rows_per_tenant: int = 80,
     base_ts: int = 1760000000,
 ) -> dict[str, Any]:
-    """按确定性种子初始化多租户业务数据、多级组织树、借调委托、制裁图谱边与快照文件。"""
     init_schema(db_path)
     storage_root = pathlib.Path(storage_dir)
     storage_root.mkdir(parents=True, exist_ok=True)
@@ -316,7 +323,6 @@
                 (tenant_id, f"Aegis {t_slug.title()} Financial", "ENTERPRISE", webhook_secret),
             )
 
-            # 5 层组织架构树（含 ops_team 下的特殊子团队 ops_special_unit 用于检验最近祖先覆盖规则）
             nodes = [
                 (f"{tenant_id}_root", tenant_id, None, "Executive HQ", "VIEWER"),
                 (f"{tenant_id}_risk_div", tenant_id, f"{tenant_id}_root", "Risk Division", "ANALYST"),
@@ -354,8 +360,6 @@
                 (tenant_id, user_tokens["auditor"]["user_id"], "SENIOR_AUDITOR", base_ts),
             )
 
-            # 预置一级借调委托（auditor -> researcher: [base_ts - 3600, base_ts + 7200)）
-            # 及二级转借调委托（researcher -> specialist: [base_ts + 200, base_ts + 9000)）
             conn.execute(
                 "INSERT INTO delegation_grants(tenant_id, grantor_user_id, grantee_user_id, delegated_role, starts_at, expires_at, active, created_at) "
                 "VALUES (?, ?, ?, 'SENIOR_AUDITOR', ?, ?, 1, ?)",
@@ -420,7 +424,6 @@
                 ),
             )
 
-            # 初始化受制裁黑名单实体与多层资金链路（sanctioned_entity -> bridge_cp -> mule_acct -> ...）
             sanc_entity = f"ent_{t_slug}_sanctioned_01"
             conn.execute(
                 "INSERT OR REPLACE INTO sanctioned_entities(tenant_id, entity_id, list_source, active, updated_at) "
@@ -535,7 +538,6 @@
                 citation_rows,
             )
 
-            # 多层级利益冲突墙：父部门 ops_team 设为 DENY，但子部门 ops_special 显式设为 ALLOW（检验最近组织节点优先级覆盖！）
             if docs_per_tenant >= 3:
                 conn.execute(
                     "INSERT INTO doc_acl_rules(tenant_id, doc_id, subject_type, subject_id, effect, active, updated_at) "
@@ -553,8 +555,6 @@
             tx_rows = []
             dec_rows = []
 
-            # 构造确定性的 2 跳 / 3 跳制裁传染边：
-            # sanc_entity <--(tx1)--> bridge_hop1 <--(tx2)--> acct_{slug}_002
             hop_edges = [
                 (f"tx_{t_slug}_sanc_e1", f"bridge_{t_slug}_h1", sanc_entity, 95000, base_ts - 3600),
                 (f"tx_{t_slug}_sanc_e2", f"acct_{t_slug}_002", f"bridge_{t_slug}_h1", 88000, base_ts - 1800),
@@ -633,7 +633,6 @@
                 dec_rows,
             )
 
-            # 多配额池（支撑单池扣减与跨池原子调拨）
             conn.execute(
                 "INSERT OR REPLACE INTO tenant_quotas(tenant_id, quota_type, remaining_quota, updated_at) VALUES (?, 'EMERGENCY_EXPORT', 5, ?)",
                 (tenant_id, base_ts),
@@ -656,7 +655,6 @@
                 (override_tok, tenant_id),
             )
 
-            # 默认审计报表模板
             conn.execute(
                 "INSERT OR REPLACE INTO report_templates(tenant_id, template_id, title_format, extra_event_filter, sample_limit, created_by, updated_at) "
                 "VALUES (?, 'tpl_default_q4', '[{tenant_id}] Compliance Summary ({total_records} events)', '', 5, ?, ?)",

--- a/aegis_app/delegation.py
+++ b/aegis_app/delegation.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""跨部门角色临时借调委托（支持最多二级受控转借调）与有效期内级联资格核验模块。"""
+"""跨部门角色借调委托管理（5级平庸样本：每次鉴权递归新建连接，未防委托有向环路，变更未联动检索缓存失效）。"""
 from __future__ import annotations
 
 import time
@@ -10,7 +10,6 @@
 
 
 def resolve_base_and_explicit_roles(db_path: str, tenant_id: str, user_id: str) -> set[str]:
-    """计算操作员通过自身岗位、组织树继承以及管理员直接授予（不含他人委托）拥有的原生角色集合。"""
     conn = open_connection(db_path)
     try:
         u_row = conn.execute(
@@ -54,7 +53,6 @@
     at_ts: int,
     depth: int = 0,
 ) -> list[tuple[str, int]]:
-    """沿当前有效时间窗回溯指定角色的上游委托路径，返回 (上游委托人 user_id, 路径跳数) 列表。"""
     conn = open_connection(db_path)
     try:
         d_rows = conn.execute(
@@ -65,17 +63,14 @@
         ).fetchall()
         active_grantors: list[str] = []
         for dr in d_rows:
-            s_ts = int(dr["starts_at"])
-            e_ts = int(dr["expires_at"])
-            if not (s_ts <= at_ts < e_ts):
-                continue
-            gid = str(dr["grantor_user_id"])
-            u_row = conn.execute(
-                "SELECT active FROM users WHERE tenant_id = ? AND user_id = ?",
-                (tenant_id, gid),
-            ).fetchone()
-            if u_row and int(u_row["active"]) == 1:
-                active_grantors.append(gid)
+            if int(dr["starts_at"]) <= at_ts < int(dr["expires_at"]):
+                gid = str(dr["grantor_user_id"])
+                u_row = conn.execute(
+                    "SELECT active FROM users WHERE tenant_id = ? AND user_id = ?",
+                    (tenant_id, gid),
+                ).fetchone()
+                if u_row and int(u_row["active"]) == 1:
+                    active_grantors.append(gid)
     finally:
         conn.close()
 
@@ -84,14 +79,7 @@
         next_hop = depth + 1
         discovered.append((gid, next_hop))
         discovered.extend(
-            _collect_upstream_grantors(
-                db_path,
-                tenant_id,
-                gid,
-                role_name,
-                at_ts,
-                next_hop,
-            )
+            _collect_upstream_grantors(db_path, tenant_id, gid, role_name, at_ts, next_hop)
         )
     return discovered
 
@@ -102,13 +90,6 @@
     grantee_user_id: str,
     at_ts: int,
 ) -> set[str]:
-    """查询在指定时刻 at_ts 对受托人生效的临时借调角色（最多支持 MAX_DELEGATION_HOPS=2 跳传递）。
-
-    级联有效性约束：
-    1. 整条借调链路（1 跳直接委托或 2 跳转借调）上的每一段记录均须 active=1 且满足 starts_at <= at_ts < expires_at；
-    2. 链路中间受托人与源头委托人当前均须 active=1，且源头委托人当前实际持有该原生角色；
-    3. 一旦源头委托人被撤回角色、或上游一级委托被撤销/跨过 expires_at，下游受托资格自动级联失效；超过 2 跳不再生效。
-    """
     conn = open_connection(db_path)
     try:
         d_rows = conn.execute(
@@ -128,17 +109,9 @@
 
     effective_delegated: set[str] = set()
     for role_name in candidate_roles:
-        upstream_chain = _collect_upstream_grantors(
-            db_path,
-            tenant_id,
-            grantee_user_id,
-            role_name,
-            at_ts,
-        )
-        for src_uid, hop_dist in upstream_chain:
+        for src_uid, hop_dist in _collect_upstream_grantors(db_path, tenant_id, grantee_user_id, role_name, at_ts):
             if 1 <= hop_dist <= MAX_DELEGATION_HOPS:
-                src_native = resolve_base_and_explicit_roles(db_path, tenant_id, src_uid)
-                if role_name in src_native:
+                if role_name in resolve_base_and_explicit_roles(db_path, tenant_id, src_uid):
                     effective_delegated.add(role_name)
                     break
     return effective_delegated
@@ -158,7 +131,6 @@
     action: str = "create",
     now_ts: int | None = None,
 ) -> dict[str, Any]:
-    """创建或撤销跨部门角色借调委托（支持原生持有人发起一级借调，或有效一级受托人发起二级转借调）。"""
     if delegated_role not in ROLE_DEFAULT_CLEARANCE:
         raise ValueError(f"Unsupported delegated_role: {delegated_role}")
     if actor_user_id != grantor_user_id and "COMPLIANCE_ADMIN" not in actor_roles:
@@ -182,13 +154,7 @@
             grantor_native = resolve_base_and_explicit_roles(db_path, tenant_id, grantor_user_id)
             can_delegate = delegated_role in grantor_native
             if not can_delegate and MAX_DELEGATION_HOPS >= 2:
-                upstream = _collect_upstream_grantors(
-                    db_path,
-                    tenant_id,
-                    grantor_user_id,
-                    delegated_role,
-                    eval_ts,
-                )
+                upstream = _collect_upstream_grantors(db_path, tenant_id, grantor_user_id, delegated_role, eval_ts)
                 can_delegate = any(
                     hop == 1 and delegated_role in resolve_base_and_explicit_roles(db_path, tenant_id, src_uid)
                     for src_uid, hop in upstream

--- a/aegis_app/doc_indexer.py
+++ b/aegis_app/doc_indexer.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""合规文本分词、相邻查询词最小跨度邻近度加分与词袋相似度计算模块。"""
+"""合规文本分词与邻近度打分（5级平庸样本：未建立位置倒排表，仍逐对嵌套扫描下标距离）。"""
 from __future__ import annotations
 
 import re
@@ -12,17 +12,10 @@
 def tokenize_text(text: str) -> list[str]:
     if not text:
         return []
-    cleaned = re.sub(r"[^a-zA-Z0-9_]+", " ", text).lower()
-    return [tok for tok in TOKEN_RE.findall(cleaned) if len(tok) >= 2]
+    return TOKEN_RE.findall(text.lower())
 
 
 def compute_phrase_proximity_bonus(body_tokens: list[str], query_terms: list[str]) -> float:
-    """计算相邻查询词对在正文词序列中的最小距离邻近度加分。
-
-    规则：若去重查询词序列包含至少 2 个词项 (q_0, q_1, ..., q_{k-1})，
-    对每个相邻词对 (q_m, q_{m+1})，找出它们在 body_tokens 中出现下标的最小绝对差 d = min |i - j|；
-    若 1 <= d <= PROXIMITY_MAX_SPAN(6)，则累加 2.4 / d。
-    """
     if len(query_terms) < 2 or not body_tokens:
         return 0.0
 
@@ -49,20 +42,11 @@
 
 
 def jaccard_similarity_from_texts(title_a: str, body_a: str, title_b: str, body_b: str) -> float:
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
+    set_a = set(tokenize_text(title_a) + tokenize_text(body_a))
+    set_b = set(tokenize_text(title_b) + tokenize_text(body_b))
+    if not set_a and not set_b:
         return 1.0
-    inter_cnt = sum(1 for t in uniq_a if t in uniq_b)
-    union_cnt = len(uniq_a) + sum(1 for t in uniq_b if t not in uniq_a)
+    union_cnt = len(set_a | set_b)
     if union_cnt == 0:
         return 0.0
-    return inter_cnt / union_cnt
+    return len(set_a & set_b) / union_cnt

--- a/aegis_app/doc_writer.py
+++ b/aegis_app/doc_writer.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""企业合规文档实时流式入库、正文修订（Upsert）与退役归档（Retire）服务。"""
+"""文档实时入库与修订（5级平庸样本：每次单篇写入粗暴清空全库全局检索缓存，高频混写时缓存完全抖动失效）。"""
 from __future__ import annotations
 
 import time
@@ -8,6 +8,7 @@
 from .auth import CallerContext
 from .config import CLEARANCE_LEVELS
 from .db import open_connection
+from .search_service import clear_naive_search_cache
 
 
 def _require_editor_clearance(caller: CallerContext, doc_clearance: int) -> None:
@@ -22,7 +23,6 @@
     caller: CallerContext,
     payload: dict[str, Any],
 ) -> dict[str, Any]:
-    """实时新增或修订本租户下的合规文档，并同步登记可选引用记录。"""
     doc_id = str(payload.get("doc_id") or "").strip()
     category = str(payload.get("category") or "AML").strip().upper()
     regulation_code = str(payload.get("regulation_code") or "").strip()
@@ -105,6 +105,7 @@
     finally:
         conn.close()
 
+    clear_naive_search_cache()
     return {
         "tenant_id": caller.tenant_id,
         "doc_id": doc_id,
@@ -118,7 +119,6 @@
     caller: CallerContext,
     doc_id: str,
 ) -> dict[str, Any]:
-    """将指定合规文档置为 RETIRED 退役状态，不再参与常规在线检索。"""
     if "COMPLIANCE_ADMIN" not in caller.effective_roles:
         raise PermissionError("COMPLIANCE_ADMIN role required to retire documents")
     now_ts = int(caller.request_ts or int(time.time()))
@@ -134,6 +134,7 @@
     finally:
         conn.close()
 
+    clear_naive_search_cache()
     return {
         "tenant_id": caller.tenant_id,
         "doc_id": doc_id,

--- a/aegis_app/ledger_ops.py
+++ b/aegis_app/ledger_ops.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""租户配额扣减、跨配额池调拨（Quota Transfer）与单次应急放行令牌核销服务。"""
+"""配额账本服务（5级平庸样本：依赖 server.py 全局大锁串行化，未做锁序规范与严格整数校验）。"""
 from __future__ import annotations
 
 import json
@@ -16,7 +16,6 @@
     tenant_id: str,
     now_ts: int,
 ) -> bool:
-    """高危风控拦截时从本租户 REALTIME_ALERT_POOL 尝试扣减 1 点实时告警配额。"""
     conn = open_connection(db_path)
     try:
         row = conn.execute(
@@ -43,7 +42,6 @@
     quota_type: str,
     amount: int = 1,
 ) -> dict[str, Any]:
-    """扣减租户指定类型的业务配额并返回剩余额度。"""
     if amount <= 0:
         raise ValueError("Quota consumption amount must be positive")
     now_ts = int(caller.request_ts or int(time.time()))
@@ -100,7 +98,6 @@
     to_quota: str,
     amount: int,
 ) -> dict[str, Any]:
-    """在本租户两个配额池之间调拨额度（须保证总额守恒、余额非负且高并发双向调拨零死锁）。"""
     require_admin(caller)
     if amount <= 0:
         raise ValueError("Transfer amount must be positive")
@@ -167,7 +164,6 @@
     token_id: str,
     tx_ref: str,
 ) -> dict[str, Any]:
-    """核销单次使用的风控应急放行令牌。"""
     now_ts = int(caller.request_ts or int(time.time()))
     conn = open_connection(db_path)
     try:

--- a/aegis_app/legacy_compat.py
+++ b/aegis_app/legacy_compat.py
@@ -17,7 +17,6 @@
 
 
 def canonicalize_regulation_code(reg_code: str) -> str:
-    """将历史遗留法规编号归一化为现行标准主编号，用于跨版本修订簇折叠。"""
     if not reg_code:
         return ""
     cleaned = reg_code.strip().upper()
@@ -29,10 +28,6 @@
     policy: dict[str, Any],
     base_channel_weight: int,
 ) -> tuple[int, bool, str | None]:
-    """针对主权央行及国际清算组织对手方的历史结算兼容规则。
-
-    返回 (调整后渠道权重, 是否豁免对手方扇出惩罚, 附加兼容说明标签)。
-    """
     cp_id = str(tx.get("counterparty_id") or "")
     currency = str(tx.get("currency") or "USD").upper()
     amount_cents = int(tx.get("amount_cents") or 0)

--- a/aegis_app/middleware.py
+++ b/aegis_app/middleware.py
@@ -1,14 +1,10 @@
 # -*- coding: utf-8 -*-
-"""网关请求载荷解析、请求时钟提取与内部诊断聚合中间件。"""
+"""请求解析中间件（5级平庸样本：未限制请求体积与 JSON 嵌套层数，未拦截 NaN/Infinity）。"""
 from __future__ import annotations
 
 import json
 import urllib.parse
 from typing import Any
-
-from . import __version__
-from .config import GATEWAY_INTERNAL_BUILD, MASTER_SIGNING_PEPPER
-from .db import open_connection
 
 
 def parse_url_and_query(path: str) -> tuple[str, dict[str, str]]:
@@ -34,22 +30,3 @@
     if not isinstance(data, dict):
         raise ValueError("Request JSON payload must be an object")
     return data, raw
-
-
-def collect_internal_diagnostics(db_path: str, storage_dir: str) -> dict[str, Any]:
-    conn = open_connection(db_path)
-    try:
-        t_rows = conn.execute("SELECT tenant_id, webhook_secret, status FROM tenants").fetchall()
-        s_rows = conn.execute("SELECT secret_key, secret_value FROM system_secrets").fetchall()
-        return {
-            "service": "aegis-gateway",
-            "version": __version__,
-            "build": GATEWAY_INTERNAL_BUILD,
-            "db_path": db_path,
-            "storage_dir": storage_dir,
-            "master_signing_pepper": MASTER_SIGNING_PEPPER,
-            "registered_tenants": [dict(r) for r in t_rows],
-            "system_secrets": {r["secret_key"]: r["secret_value"] for r in s_rows},
-        }
-    finally:
-        conn.close()

--- a/aegis_app/rule_engine.py
+++ b/aegis_app/rule_engine.py
@@ -1,5 +1,5 @@
 # -*- coding: utf-8 -*-
-"""实时交易风控评分、三跳制裁传染耦合、滑动窗口动态中位数与自定义规则树引擎。"""
+"""风控引擎（5级平庸样本：仍逐笔独立建连提交导致半批脏残留，未修回溯正则、规则炸弹与非严格数值类型）。"""
 from __future__ import annotations
 
 import json
@@ -199,7 +199,6 @@
     win_median_cents: int,
     sanction_hop: int,
 ) -> tuple[int, str, list[str]]:
-    """根据滑动窗口四维指标、三跳制裁传染等级、主权结算兼容规则与自定义规则树计算风险分。"""
     score = 0
     reasons: list[str] = []
 
@@ -237,12 +236,10 @@
         score += 14
         reasons.append("COUNTERPARTY_FANOUT")
 
-    # 动态中位数突变检测：窗口满 3 笔且当前交易金额达到窗口中位数的 3 倍及以上
     if win_tx_count >= 3 and win_median_cents > 0 and amount_cents >= 3 * win_median_cents:
         score += 11
         reasons.append("MEDIAN_DEVIATION_SPIKE")
 
-    # 三跳受制裁实体传染加分
     if sanction_hop in SANCTION_HOP_SCORES:
         score += SANCTION_HOP_SCORES[sanction_hop]
         reasons.append(f"SANCTION_HOP_{sanction_hop}")
@@ -274,10 +271,10 @@
     batch_id: str,
     transactions: list[dict[str, Any]],
 ) -> dict[str, Any]:
-    """按输入顺序逐笔评估实时交易批次并持久化交易及风控决策记录。"""
     if not batch_id or not isinstance(transactions, list) or len(transactions) == 0:
         raise ValueError("batch_id and non-empty transactions list are required")
 
+    policy = load_tenant_policy(db_path, caller.tenant_id)
     results: list[dict[str, Any]] = []
     counts = {"ALLOW": 0, "REVIEW": 0, "REJECT": 0}
 
@@ -297,7 +294,6 @@
         if not validate_contact_email(contact_email):
             raise ValueError(f"Invalid contact_email in transaction {tx_id}")
 
-        policy = load_tenant_policy(db_path, caller.tenant_id)
         sanction_hop = compute_sanction_contagion_hop(
             db_path,
             caller.tenant_id,
@@ -308,31 +304,28 @@
 
         conn = open_connection(db_path)
         try:
+            win_start = ts - SLIDING_WINDOW_SECONDS
             hist_rows = conn.execute(
-                "SELECT tx_id, account_id, counterparty_id, amount_cents, ts, metadata_json "
-                "FROM transactions WHERE tenant_id = ?",
-                (caller.tenant_id,),
+                "SELECT counterparty_id, amount_cents FROM transactions "
+                "WHERE tenant_id = ? AND account_id = ? AND ts >= ? AND ts <= ?",
+                (caller.tenant_id, account_id, win_start, ts),
             ).fetchall()
         finally:
             conn.close()
 
-        win_start = ts - SLIDING_WINDOW_SECONDS
         win_tx_count = 1
         win_amount_cents = amount_cents
         win_amounts_list: list[int] = [amount_cents]
-        cp_list: list[str] = [counterparty_id]
+        cp_set: set[str] = {counterparty_id}
 
         for hr in hist_rows:
-            _ = json.loads(hr["metadata_json"])
-            if hr["account_id"] == account_id and win_start <= int(hr["ts"]) <= ts:
-                h_amt = int(hr["amount_cents"])
-                win_tx_count += 1
-                win_amount_cents += h_amt
-                win_amounts_list.append(h_amt)
-                if hr["counterparty_id"] not in cp_list:
-                    cp_list.append(hr["counterparty_id"])
-
-        win_unique_cps = len(cp_list)
+            h_amt = int(hr["amount_cents"])
+            win_tx_count += 1
+            win_amount_cents += h_amt
+            win_amounts_list.append(h_amt)
+            cp_set.add(hr["counterparty_id"])
+
+        win_unique_cps = len(cp_set)
         win_median_cents = compute_exact_median_cents(win_amounts_list)
 
         tx_eval_obj = {
@@ -356,6 +349,7 @@
             sanction_hop=sanction_hop,
         )
 
+        # 5级平庸样本：逐笔独立扣减告警配额并立即提交，末尾交易异常会导致已扣配额泄漏不回滚
         alert_dispatched = False
         if decision == "REJECT":
             if try_consume_realtime_alert_quota(db_path, caller.tenant_id, ts):
@@ -452,8 +446,8 @@
             "SELECT decision_id, tx_id, tenant_id, account_id, risk_score, decision, "
             "win_tx_count, win_amount_cents, win_unique_counterparties, win_median_cents, "
             "sanction_hop, reasons_json, evaluated_at "
-            "FROM risk_decisions WHERE decision_id = ?",
-            (decision_id,),
+            "FROM risk_decisions WHERE decision_id = ? AND tenant_id = ?",
+            (decision_id, caller.tenant_id),
         ).fetchone()
         if not row:
             raise LookupError(f"Decision record not found: {decision_id}")

--- a/aegis_app/search_service.py
+++ b/aegis_app/search_service.py
@@ -1,56 +1,33 @@
 # -*- coding: utf-8 -*-
-"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。"""
+"""合规文档检索服务（5级平庸样本：保留 O(N^2) 去重，无界粗糙缓存漏绑权限纪元/委托时效，batch_get 漏纵向与隔离墙校验）。"""
 from __future__ import annotations
 
 from collections import Counter
+import copy
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
-from .doc_indexer import (
-    compute_phrase_proximity_bonus,
-    jaccard_similarity_from_texts,
-    tokenize_text,
-)
+from .doc_indexer import compute_phrase_proximity_bonus, tokenize_text
 from .legacy_compat import canonicalize_regulation_code
 
-
-def _get_doc_citation_count(db_path: str, tenant_id: str, doc_id: str) -> int:
-    """统计文档当前有效的唯一引用源数量（内部 doc_ 引用须核验源文档处于 ACTIVE 且未隔离状态）。"""
-    conn = open_connection(db_path)
-    try:
-        rows = conn.execute(
-            "SELECT cited_by_ref FROM doc_citations WHERE tenant_id = ? AND doc_id = ?",
-            (tenant_id, doc_id),
-        ).fetchall()
-        seen_refs: list[str] = []
-        for r in rows:
-            ref = str(r["cited_by_ref"] or "").strip()
-            if ref and ref != doc_id and ref not in seen_refs:
-                seen_refs.append(ref)
-
-        valid_cnt = 0
-        for ref in seen_refs:
-            if ref.startswith("doc_"):
-                ref_sql = (
-                    "SELECT status, quarantined FROM compliance_docs "
-                    f"WHERE doc_id = '{ref}'"
-                )
-                ref_row = conn.execute(ref_sql).fetchone()
-                if ref_row and ref_row["status"] == "ACTIVE" and int(ref_row["quarantined"]) == 0:
-                    valid_cnt += 1
-            else:
-                valid_cnt += 1
-        return valid_cnt
-    finally:
-        conn.close()
+# 5级平庸缓存：无容量上限，未绑定角色撤回/借调过期/利益冲突墙更新，且任意文档写入即整库清空
+_NAIVE_SEARCH_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
+
+
+def clear_naive_search_cache() -> None:
+    _NAIVE_SEARCH_CACHE.clear()
+
+
+def _jaccard_sets(set_a: set[str], set_b: set[str]) -> float:
+    if not set_a and not set_b:
+        return 1.0
+    union_len = len(set_a | set_b)
+    if union_len == 0:
+        return 0.0
+    return len(set_a & set_b) / union_len
 
 
 def search_documents(
@@ -66,32 +43,70 @@
     limit: int = DEFAULT_PAGE_LIMIT,
     offset: int = 0,
 ) -> dict[str, Any]:
-    """执行合规文档检索：融合委托有效密级、三级利益冲突墙、词距邻近度加成与历史双轨法规号折叠。"""
-    sql_sort_col = "updated_at" if sort_by == "score" else sort_by
-    sql_sort_dir = sort_dir if sort_dir else "DESC"
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
+        tag_filter,
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
+            "SELECT doc_id, cited_by_ref FROM doc_citations WHERE tenant_id = ?",
+            (caller.tenant_id,),
+        ).fetchall()
+        # 5级平庸样本：虽合并拉取了引用，但未校验被引用内部 doc_ 的租户归属（遗留跨租户引用存在性侧信道）
+        active_global_docs = {
+            r["doc_id"]
+            for r in conn.execute(
+                "SELECT doc_id FROM compliance_docs WHERE status = 'ACTIVE' AND quarantined = 0"
+            ).fetchall()
+        }
+        refs_by_doc: dict[str, set[str]] = {}
+        for cr in cite_rows:
+            did = str(cr["doc_id"])
+            ref = str(cr["cited_by_ref"] or "").strip()
+            if ref and ref != did:
+                refs_by_doc.setdefault(did, set()).add(ref)
+        cite_map = {
+            did: sum(1 for ref in rset if (not ref.startswith("doc_")) or (ref in active_global_docs))
+            for did, rset in refs_by_doc.items()
+        }
     finally:
         conn.close()
 
@@ -99,13 +114,7 @@
     candidates: list[dict[str, Any]] = []
 
     for row in raw_rows:
-        _, live_clearance = resolve_effective_permissions(
-            db_path,
-            caller.tenant_id,
-            caller.user_id,
-            at_ts=caller.request_ts,
-        )
-        if int(row["clearance_level"]) > live_clearance:
+        if int(row["clearance_level"]) > caller.max_clearance:
             continue
         if is_doc_blocked_by_acl(db_path, caller.tenant_id, caller.user_id, row["doc_id"]):
             continue
@@ -128,7 +137,7 @@
             term_score = 0.0
             prox_bonus = 0.0
 
-        cite_cnt = _get_doc_citation_count(db_path, caller.tenant_id, row["doc_id"])
+        cite_cnt = cite_map.get(row["doc_id"], 0)
         risk_w = int(row["risk_weight"])
         total_score = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)
 
@@ -146,7 +155,7 @@
                 "citation_count": cite_cnt,
                 "score": total_score,
                 "updated_at": int(row["updated_at"]),
-                "_raw_body": row["body"],
+                "_tok_set": set(title_tokens + body_tokens),
             }
         )
 
@@ -166,12 +175,7 @@
                 same_reg = bool(rep["_canon_reg"]) and (
                     rep["_canon_reg"] == candidates[j]["_canon_reg"]
                 )
-                sim = jaccard_similarity_from_texts(
-                    rep["title"],
-                    rep["_raw_body"],
-                    candidates[j]["title"],
-                    candidates[j]["_raw_body"],
-                )
+                sim = _jaccard_sets(rep["_tok_set"], candidates[j]["_tok_set"])
                 if same_reg and sim >= DEDUP_JACCARD_THRESHOLD:
                     consumed[j] = True
                     cluster_size += 1
@@ -186,11 +190,10 @@
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
     if limit < 0:
@@ -199,12 +202,14 @@
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
@@ -212,7 +217,7 @@
     caller: CallerContext,
     doc_ids: list[str],
 ) -> dict[str, Any]:
-    """按文档 ID 列表批量获取完整合规文档内容。"""
+    """仅补了 tenant_id 过滤，遗漏了纵向 clearance_level、quarantined 与利益冲突隔离墙拦截。"""
     if not isinstance(doc_ids, list) or not doc_ids:
         raise ValueError("doc_ids must be a non-empty list")
 
@@ -222,8 +227,8 @@
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
@@ -278,6 +283,7 @@
     finally:
         conn.close()
 
+    clear_naive_search_cache()
     return {
         "tenant_id": caller.tenant_id,
         "doc_id": doc_id,

--- a/aegis_app/server.py
+++ b/aegis_app/server.py
@@ -1,12 +1,12 @@
 # -*- coding: utf-8 -*-
-"""AegisGate HTTP 路由网关与嵌入式应用入口（18 路由完整网关版）。"""
+"""网关入口（5级平庸样本：套了一把全局粗暴大锁串行化全站读写请求，严重阻塞跨租户并发吞吐）。"""
 from __future__ import annotations
 
 import argparse
 from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
 import json
 import pathlib
-import traceback
+import threading
 from typing import Any
 
 from . import __version__
@@ -24,7 +24,7 @@
     process_settlement_webhook,
     revoke_or_grant_role,
 )
-from .config import DEFAULT_PAGE_LIMIT, MASTER_SIGNING_PEPPER
+from .config import DEFAULT_PAGE_LIMIT
 from .contagion_graph import manage_sanctioned_entity
 from .db import init_schema
 from .doc_writer import retire_compliance_document, upsert_compliance_document
@@ -33,11 +33,7 @@
     redeem_override_token,
     transfer_tenant_quota,
 )
-from .middleware import (
-    collect_internal_diagnostics,
-    parse_json_payload,
-    parse_url_and_query,
-)
+from .middleware import parse_json_payload, parse_url_and_query
 from .rule_engine import (
     evaluate_transaction_batch,
     get_risk_decision_detail,
@@ -50,10 +46,11 @@
     set_document_quarantine,
 )
 
+# 全局粗暴互斥大锁：将所有租户的并发读与写全部串行化为单线程排队
+_GLOBAL_GATEWAY_LOCK = threading.Lock()
+
 
 class AegisGateway:
-    """多租户风控与合规检索统一网关实例。"""
-
     def __init__(self, db_path: str | pathlib.Path, storage_dir: str | pathlib.Path) -> None:
         self.db_path = str(pathlib.Path(db_path).resolve())
         self.storage_dir = str(pathlib.Path(storage_dir).resolve())
@@ -67,266 +64,257 @@
         headers: dict[str, str] | None = None,
         body: bytes | str | dict[str, Any] | None = None,
     ) -> tuple[int, dict[str, str], dict[str, Any]]:
-        """处理一次网关调用，返回 (status_code, response_headers, response_json_dict)。"""
         req_method = method.upper().strip()
         route, query_params = parse_url_and_query(path)
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
+                if route == "/api/v1/internal/diagnostics":
+                    return 403, resp_headers, {"error": "FORBIDDEN", "message": "Diagnostics disabled"}
+
+                now_ov_str = query_params.get("_now_ts")
+                now_ov = int(now_ov_str) if now_ov_str else None
+
+                if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
+                    _, raw_body = parse_json_payload(body)
+                    res = process_settlement_webhook(
+                        self.db_path,
+                        req_headers,
+                        raw_body,
+                        now_override=now_ov,
+                    )
+                    return 200, resp_headers, res
+
+                caller = authenticate_caller(self.db_path, req_headers, now_override=now_ov)
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
+                if req_method == "POST" and route == "/api/v1/docs/upsert":
+                    data, _ = parse_json_payload(body)
+                    res = upsert_compliance_document(self.db_path, caller, data)
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/docs/retire":
+                    data, _ = parse_json_payload(body)
+                    res = retire_compliance_document(self.db_path, caller, str(data.get("doc_id") or ""))
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/docs/batch-get":
+                    data, _ = parse_json_payload(body)
+                    res = batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/docs/quarantine":
+                    data, _ = parse_json_payload(body)
+                    res = set_document_quarantine(
+                        self.db_path,
+                        caller,
+                        doc_id=str(data.get("doc_id") or ""),
+                        quarantined=bool(data.get("quarantined", True)),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
+                    data, _ = parse_json_payload(body)
+                    res = revoke_or_grant_role(
+                        self.db_path,
+                        caller,
+                        target_user_id=str(data.get("user_id") or ""),
+                        role_name=str(data.get("role") or ""),
+                        action=str(data.get("action") or "revoke"),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/admin/delegations":
+                    data, _ = parse_json_payload(body)
+                    res = manage_role_delegation(
+                        self.db_path,
+                        caller,
+                        grantor_user_id=str(data.get("grantor_user_id") or caller.user_id),
+                        grantee_user_id=str(data.get("grantee_user_id") or ""),
+                        delegated_role=str(data.get("delegated_role") or ""),
+                        starts_at=int(data.get("starts_at") or 0),
+                        expires_at=int(data.get("expires_at") or 0),
+                        action=str(data.get("action") or "create"),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/admin/doc-acl":
+                    data, _ = parse_json_payload(body)
+                    res = configure_doc_acl_rule(
+                        self.db_path,
+                        caller,
+                        doc_id=str(data.get("doc_id") or ""),
+                        subject_type=str(data.get("subject_type") or ""),
+                        subject_id=str(data.get("subject_id") or ""),
+                        effect=str(data.get("effect") or "DENY"),
+                        active=bool(data.get("active", True)),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/admin/sanctions":
+                    data, _ = parse_json_payload(body)
+                    res = manage_sanctioned_entity(
+                        self.db_path,
+                        caller,
+                        entity_id=str(data.get("entity_id") or ""),
+                        list_source=str(data.get("list_source") or "OFAC_SDN"),
+                        active=bool(data.get("active", True)),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "PUT" and route == "/api/v1/policies":
+                    data, _ = parse_json_payload(body)
+                    res = update_tenant_policy(self.db_path, caller, data)
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
+                    data, _ = parse_json_payload(body)
+                    res = evaluate_transaction_batch(
+                        self.db_path,
+                        caller,
+                        batch_id=str(data.get("batch_id") or ""),
+                        transactions=data.get("transactions") or [],
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
+                    data, _ = parse_json_payload(body)
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
+                    data, _ = parse_json_payload(body)
+                    res = consume_tenant_quota(
+                        self.db_path,
+                        caller,
+                        quota_type=str(data.get("quota_type") or ""),
+                        amount=int(data.get("amount", 1)),
+                    )
+                    status_code = 200 if res.get("accepted") else 409
+                    return status_code, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/quotas/transfer":
+                    data, _ = parse_json_payload(body)
+                    res = transfer_tenant_quota(
+                        self.db_path,
+                        caller,
+                        from_quota=str(data.get("from_quota") or ""),
+                        to_quota=str(data.get("to_quota") or ""),
+                        amount=int(data.get("amount", 0)),
+                    )
+                    status_code = 200 if res.get("transferred") else 409
+                    return status_code, resp_headers, res
+
+                if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
+                    data, _ = parse_json_payload(body)
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
+                if req_method == "PUT" and route == "/api/v1/audit/report-template":
+                    data, _ = parse_json_payload(body)
+                    res = save_report_template(
+                        self.db_path,
+                        caller,
+                        template_id=str(data.get("template_id") or ""),
+                        title_format=str(data.get("title_format") or ""),
+                        extra_event_filter=str(data.get("extra_event_filter") or ""),
+                        sample_limit=int(data.get("sample_limit", 10)),
+                    )
+                    return 200, resp_headers, res
+
+                if req_method == "GET" and route == "/api/v1/audit/render-report":
+                    tpl_id = query_params.get("template_id", "")
+                    s_ts = int(query_params["start_ts"]) if query_params.get("start_ts") else None
+                    e_ts = int(query_params["end_ts"]) if query_params.get("end_ts") else None
+                    res = render_saved_report(
+                        self.db_path,
+                        caller,
+                        template_id=tpl_id,
+                        start_ts=s_ts,
+                        end_ts=e_ts,
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
+            except PermissionError as exc:
+                return 403, resp_headers, {"error": "FORBIDDEN", "message": str(exc)}
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
-                    payload["diagnostics"] = collect_internal_diagnostics(self.db_path, self.storage_dir)
-                return 200, resp_headers, payload
-
-            if req_method == "GET" and route == "/api/v1/internal/diagnostics":
-                return 200, resp_headers, collect_internal_diagnostics(self.db_path, self.storage_dir)
-
-            now_ov_str = query_params.get("_now_ts")
-            now_ov = int(now_ov_str) if now_ov_str else None
-
-            if req_method == "POST" and route == "/api/v1/webhooks/settlement-callback":
-                _, raw_body = parse_json_payload(body)
-                res = process_settlement_webhook(
-                    self.db_path,
-                    req_headers,
-                    raw_body,
-                    now_override=now_ov,
-                )
-                return 200, resp_headers, res
-
-            caller = authenticate_caller(self.db_path, req_headers, now_override=now_ov)
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
-            if req_method == "POST" and route == "/api/v1/docs/upsert":
-                data, _ = parse_json_payload(body)
-                res = upsert_compliance_document(self.db_path, caller, data)
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/docs/retire":
-                data, _ = parse_json_payload(body)
-                res = retire_compliance_document(self.db_path, caller, str(data.get("doc_id") or ""))
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/docs/batch-get":
-                data, _ = parse_json_payload(body)
-                res = batch_get_documents(self.db_path, caller, data.get("doc_ids") or [])
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/docs/quarantine":
-                data, _ = parse_json_payload(body)
-                res = set_document_quarantine(
-                    self.db_path,
-                    caller,
-                    doc_id=str(data.get("doc_id") or ""),
-                    quarantined=bool(data.get("quarantined", True)),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/admin/grants/revoke":
-                data, _ = parse_json_payload(body)
-                res = revoke_or_grant_role(
-                    self.db_path,
-                    caller,
-                    target_user_id=str(data.get("user_id") or ""),
-                    role_name=str(data.get("role") or ""),
-                    action=str(data.get("action") or "revoke"),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/admin/delegations":
-                data, _ = parse_json_payload(body)
-                res = manage_role_delegation(
-                    self.db_path,
-                    caller,
-                    grantor_user_id=str(data.get("grantor_user_id") or caller.user_id),
-                    grantee_user_id=str(data.get("grantee_user_id") or ""),
-                    delegated_role=str(data.get("delegated_role") or ""),
-                    starts_at=int(data.get("starts_at") or 0),
-                    expires_at=int(data.get("expires_at") or 0),
-                    action=str(data.get("action") or "create"),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/admin/doc-acl":
-                data, _ = parse_json_payload(body)
-                res = configure_doc_acl_rule(
-                    self.db_path,
-                    caller,
-                    doc_id=str(data.get("doc_id") or ""),
-                    subject_type=str(data.get("subject_type") or ""),
-                    subject_id=str(data.get("subject_id") or ""),
-                    effect=str(data.get("effect") or "DENY"),
-                    active=bool(data.get("active", True)),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/admin/sanctions":
-                data, _ = parse_json_payload(body)
-                res = manage_sanctioned_entity(
-                    self.db_path,
-                    caller,
-                    entity_id=str(data.get("entity_id") or ""),
-                    list_source=str(data.get("list_source") or "OFAC_SDN"),
-                    active=bool(data.get("active", True)),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "PUT" and route == "/api/v1/policies":
-                data, _ = parse_json_payload(body)
-                res = update_tenant_policy(self.db_path, caller, data)
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/risk/evaluate-batch":
-                data, _ = parse_json_payload(body)
-                res = evaluate_transaction_batch(
-                    self.db_path,
-                    caller,
-                    batch_id=str(data.get("batch_id") or ""),
-                    transactions=data.get("transactions") or [],
-                )
-                return 200, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/risk/simulate-rule":
-                data, _ = parse_json_payload(body)
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
-                data, _ = parse_json_payload(body)
-                res = consume_tenant_quota(
-                    self.db_path,
-                    caller,
-                    quota_type=str(data.get("quota_type") or ""),
-                    amount=int(data.get("amount", 1)),
-                )
-                status_code = 200 if res.get("accepted") else 409
-                return status_code, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/quotas/transfer":
-                data, _ = parse_json_payload(body)
-                res = transfer_tenant_quota(
-                    self.db_path,
-                    caller,
-                    from_quota=str(data.get("from_quota") or ""),
-                    to_quota=str(data.get("to_quota") or ""),
-                    amount=int(data.get("amount", 0)),
-                )
-                status_code = 200 if res.get("transferred") else 409
-                return status_code, resp_headers, res
-
-            if req_method == "POST" and route == "/api/v1/risk/override-token/redeem":
-                data, _ = parse_json_payload(body)
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
-            if req_method == "PUT" and route == "/api/v1/audit/report-template":
-                data, _ = parse_json_payload(body)
-                res = save_report_template(
-                    self.db_path,
-                    caller,
-                    template_id=str(data.get("template_id") or ""),
-                    title_format=str(data.get("title_format") or ""),
-                    extra_event_filter=str(data.get("extra_event_filter") or ""),
-                    sample_limit=int(data.get("sample_limit", 10)),
-                )
-                return 200, resp_headers, res
-
-            if req_method == "GET" and route == "/api/v1/audit/render-report":
-                tpl_id = query_params.get("template_id", "")
-                s_ts = int(query_params["start_ts"]) if query_params.get("start_ts") else None
-                e_ts = int(query_params["end_ts"]) if query_params.get("end_ts") else None
-                res = render_saved_report(
-                    self.db_path,
-                    caller,
-                    template_id=tpl_id,
-                    start_ts=s_ts,
-                    end_ts=e_ts,
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
-        except PermissionError as exc:
-            return 403, resp_headers, {"error": "FORBIDDEN", "message": str(exc)}
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
@@ -370,26 +358,3 @@
             return
 
     return ThreadingHTTPServer((host, port), GatewayHTTPHandler)
-
-
-def main() -> int:
-    ap = argparse.ArgumentParser(description="启动 AegisGate 多租户风控与合规检索网关")
-    ap.add_argument("--db", required=True)
-    ap.add_argument("--storage", required=True)
-    ap.add_argument("--host", default="127.0.0.1")
-    ap.add_argument("--port", type=int, default=8080)
-    args = ap.parse_args()
-
-    gw = create_gateway(args.db, args.storage)
-    srv = build_http_server(gw, host=args.host, port=args.port)
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

--- a/aegis_app/window_stats.py
+++ b/aegis_app/window_stats.py
@@ -1,19 +1,13 @@
 # -*- coding: utf-8 -*-
-"""24 小时滑动窗口精确统计与动态金额中位数计算模块。"""
+"""24 小时滑动窗口中位数计算（5级平庸样本：改用内置排序但未做流式增量维护）。"""
 from __future__ import annotations
 
 
 def compute_exact_median_cents(amounts: list[int]) -> int:
-    """计算非空整数金额列表的精确中位数（偶数个元素取中间两数的整数均值 (a + b) // 2）。"""
     if not amounts:
         return 0
-    ordered = list(amounts)
-    # 传统交换排序以获取有序金额序列
+    ordered = sorted(amounts)
     n = len(ordered)
-    for i in range(n):
-        for j in range(0, n - i - 1):
-            if ordered[j] > ordered[j + 1]:
-                ordered[j], ordered[j + 1] = ordered[j + 1], ordered[j]
     mid = n // 2
     if n % 2 == 1:
         return int(ordered[mid])

--- a/smoke_check.py
+++ /dev/null
@@ -1,248 +0,0 @@
-#!/usr/bin/env python3
-# -*- coding: utf-8 -*-
-"""公开基础业务功能回归冒烟测试（smoke_check.py · v3.0）。
-
-说明：仅在小规模样本上检验核心业务路由与跨模块契约的基础功能正确性，不包含高压性能压测与红队安全攻防载荷。
-"""
-from __future__ import annotations
-
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
-    tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="aegis_smoke_v3_"))
-    try:
-        db_path = tmp_root / "smoke.db"
-        storage_dir = tmp_root / "storage"
-        manifest = seed_dataset(
-            db_path,
-            storage_dir,
-            seed=20261126,
-            num_tenants=2,
-            docs_per_tenant=16,
-            tx_per_tenant=24,
-            audit_rows_per_tenant=30,
-        )
-        base_ts = int(manifest["base_ts"])
-        gw = create_gateway(db_path, storage_dir)
-
-        st, _, body = gw.request("GET", "/api/v1/health")
-        assert st == 200 and body.get("status") == "ok"
-
-        t_alpha = manifest["tenants"]["tenant_alpha"]
-        h_admin = _auth_headers("tenant_alpha", t_alpha["users"]["admin"])
-        h_auditor = _auth_headers("tenant_alpha", t_alpha["users"]["auditor"])
-        h_analyst = _auth_headers("tenant_alpha", t_alpha["users"]["analyst"])
-        h_specialist = _auth_headers("tenant_alpha", t_alpha["users"]["specialist"])
-        h_researcher = _auth_headers("tenant_alpha", t_alpha["users"]["researcher"])
-
-        # 1. 合规检索、词距邻近度与三级隔离墙（ops_team DENY，子部门 ops_special ALLOW）
-        wall_doc_id = t_alpha["wall_doc_id"]
-        _, _, s_spec = gw.request(
-            "GET",
-            f"/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0&_now_ts={base_ts + 10}",
-            headers=h_specialist,
-        )
-        _, _, s_ana = gw.request(
-            "GET",
-            f"/api/v1/docs/search?q=merger+acquisition+valuation&deduplicate=0&_now_ts={base_ts + 10}",
-            headers=h_analyst,
-        )
-        assert any(d["doc_id"] == wall_doc_id for d in s_spec["items"]), "Sub-unit ALLOW should override parent DENY"
-        assert all(d["doc_id"] != wall_doc_id for d in s_ana["items"]), "Parent ops_team DENY should block analyst"
-
-        # 2. 实时文档 Upsert、跨文档有效引用联动（隔离源文档自动剥离引用）与二级转借调时效窗口核验
-        st_up, _, up_res = gw.request(
-            "POST",
-            f"/api/v1/docs/upsert?_now_ts={base_ts + 20}",
-            headers=h_auditor,
-            body={
-                "doc_id": "doc_alpha_live_01",
-                "category": "AML",
-                "regulation_code": "FATF-R16",
-                "clearance_level": 3,
-                "risk_weight": 20,
-                "custom_tag": "tag_live",
-                "title": "Live Streaming AML Guidance",
-                "body": "wire transfer travel rule live streaming incremental index verification",
-                "citations": ["ref_live_1", "doc_alpha_0002"],
-            },
-        )
-        assert st_up == 200 and up_res["operation"] == "created"
-
-        # researcher（1跳借调）与 specialist（在 base_ts+300 处于 2跳有效借调窗内）均能检索密级 3 文档且包含 2 条有效引用
-        _, _, s_del1 = gw.request(
-            "GET",
-            f"/api/v1/docs/search?q=incremental+index+verification&deduplicate=0&_now_ts={base_ts + 30}",
-            headers=h_researcher,
-        )
-        live_hit_1 = [d for d in s_del1["items"] if d["doc_id"] == "doc_alpha_live_01"]
-        assert len(live_hit_1) == 1 and live_hit_1[0]["citation_count"] == 2
-
-        _, _, s_del2 = gw.request(
-            "GET",
-            f"/api/v1/docs/search?q=incremental+index+verification&deduplicate=0&_now_ts={base_ts + 300}",
-            headers=h_specialist,
-        )
-        assert any(d["doc_id"] == "doc_alpha_live_01" for d in s_del2["items"]), "2-hop transitive delegation should grant clearance 3"
-
-        # 在 base_ts+7500 时，虽然 specialist 自身二级借调窗 [+200, +9000) 未到期，但上游 researcher 一级借调窗 [-3600, +7200) 已到期，须自动降级
-        _, _, s_del2_exp = gw.request(
-            "GET",
-            f"/api/v1/docs/search?q=live+streaming+incremental+index&deduplicate=1&_now_ts={base_ts + 7500}",
-            headers=h_specialist,
-        )
-        assert all(d["doc_id"] != "doc_alpha_live_01" for d in s_del2_exp["items"]), "Expired upstream hop-1 must invalidate hop-2"
-
-        # 隔离内部引用源 doc_alpha_0002 后，doc_alpha_live_01 的有效引用计数须立即从 2 降为 1；解封后恢复为 2
-        gw.request(
-            "POST",
-            f"/api/v1/docs/quarantine?_now_ts={base_ts + 35}",
-            headers=h_admin,
-            body={"doc_id": "doc_alpha_0002", "quarantined": True},
-        )
-        _, _, s_q_on = gw.request(
-            "GET",
-            f"/api/v1/docs/search?q=incremental+index+verification&deduplicate=0&_now_ts={base_ts + 36}",
-            headers=h_auditor,
-        )
-        assert [d for d in s_q_on["items"] if d["doc_id"] == "doc_alpha_live_01"][0]["citation_count"] == 1
-
-        gw.request(
-            "POST",
-            f"/api/v1/docs/quarantine?_now_ts={base_ts + 37}",
-            headers=h_admin,
-            body={"doc_id": "doc_alpha_0002", "quarantined": False},
-        )
-        st_ret, _, _ = gw.request(
-            "POST",
-            f"/api/v1/docs/retire?_now_ts={base_ts + 40}",
-            headers=h_admin,
-            body={"doc_id": "doc_alpha_live_01"},
-        )
-        assert st_ret == 200
-
-        # 3. 实时风控批次评估（含精确中位数、三跳受制裁传染、主权豁免与高危 REJECT 实时告警配额联动）
-        batch_payload = {
-            "batch_id": "batch_smoke_v3",
-            "transactions": [
-                {
-                    "tx_id": "tx_smk_1",
-                    "account_id": "acct_alpha_002",
-                    "counterparty_id": "cp_901",
-                    "amount_cents": 120000,
-                    "currency": "USD",
-                    "channel": "WIRE_INTL",
-                    "contact_email": "treasury.ops@alpha-corp.com",
-                    "ts": base_ts + 120,
-                    "metadata": {"region": "US"},
-                },
-                {
-                    "tx_id": "tx_smk_2",
-                    "account_id": "acct_alpha_001",
-                    "counterparty_id": "SOV_CB_BIS_01",
-                    "amount_cents": 300000,
-                    "currency": "EUR",
-                    "channel": "WIRE_INTL",
-                    "contact_email": "cb.desk@alpha-corp.com",
-                    "ts": base_ts + 150,
-                    "metadata": {"region": "EU"},
-                },
-                {
-                    "tx_id": "tx_smk_3_reject",
-                    "account_id": "acct_alpha_001",
-                    "counterparty_id": t_alpha["sanctioned_entity"],
-                    "amount_cents": 600000,
-                    "currency": "USD",
-                    "channel": "CRYPTO_BRIDGE",
-                    "contact_email": "alert.desk@alpha-corp.com",
-                    "ts": base_ts + 160,
-                    "metadata": {"region": "US"},
-                },
-            ],
-        }
-        st_ev, _, ev_res = gw.request(
-            "POST",
-            "/api/v1/risk/evaluate-batch",
-            headers=h_auditor,
-            body=batch_payload,
-        )
-        assert st_ev == 200 and ev_res["evaluated_count"] == 3
-        assert ev_res["results"][0]["sanction_hop"] == 3 and ev_res["results"][0]["alert_dispatched"] is False
-        assert "LEGACY_SOVEREIGN_EXEMPT" in ev_res["results"][1]["reasons"]
-        assert ev_res["results"][2]["decision"] == "REJECT" and ev_res["results"][2]["alert_dispatched"] is True
-        assert "ALERT_QUOTA_CONSUMED" in ev_res["results"][2]["reasons"]
-        assert "median_cents" in ev_res["results"][0]["window"]
-
-        # 4. 跨池配额调拨（REALTIME_ALERT_POOL 刚才被 REJECT 扣了 1 点剩 49，调入 10 点后为 59）
-        st_tr, _, tr_res = gw.request(
-            "POST",
-            "/api/v1/quotas/transfer",
-            headers=h_admin,
-            body={"from_quota": "RESERVE_BUFFER_POOL", "to_quota": "REALTIME_ALERT_POOL", "amount": 10},
-        )
-        assert st_tr == 200 and tr_res["transferred"] is True and tr_res["from_remaining"] == 40 and tr_res["to_remaining"] == 59
-
-        # 5. 自定义审计报表模板保存与渲染
-        st_tp, _, _ = gw.request(
-            "PUT",
-            "/api/v1/audit/report-template",
-            headers=h_auditor,
-            body={
-                "template_id": "tpl_smoke_1",
-                "title_format": "Report for {tenant_id}: {total_records} logs",
-                "extra_event_filter": "RISK_EVAL",
-                "sample_limit": 3,
-            },
-        )
-        assert st_tp == 200
-        st_rn, _, rn_res = gw.request(
-            "GET",
-            "/api/v1/audit/render-report?template_id=tpl_smoke_1",
-            headers=h_auditor,
-        )
-        assert st_rn == 200 and rn_res["rendered_title"].startswith("Report for tenant_alpha:")
-
-        # 6. HTTP Socket 端到端联通验证
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
-        print("[PASS] AegisGate v3.0 基础业务功能冒烟自检全部通过。")
-        return 0
-    finally:
-        shutil.rmtree(tmp_root, ignore_errors=True)
-
-
-if __name__ == "__main__":
-    raise SystemExit(run_smoke())
```
