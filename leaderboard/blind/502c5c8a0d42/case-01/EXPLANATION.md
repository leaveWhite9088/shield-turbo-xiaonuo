# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
1. **高频连接开关开销**：原版在单次请求循环内反复调用 `sqlite3.connect` 并关闭（如检索每篇文档都重开连接查权限、ACL 和引用计数）。重构后在 `aegis_app/runtime.py` 中通过 `DBRuntime.get_connection` 维护按线程隔离的连接池（`threading.local()`），并在 `aegis_app/db.py` 的 `init_schema` 与连接初始化阶段幂等开启 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL`、`temp_store=MEMORY`、`cache_size=-32000` 和 `busy_timeout=30000`。
2. **缺失二级索引与 N+1 查询放大**：原版核心业务表缺乏二级索引。我们在 `aegis_app/db.py` 的 `SCHEMA_SQL` 中幂等补充了覆盖索引：`idx_org_nodes_tenant_node`、`idx_users_tenant_user`、`idx_role_grants_tenant_user_active`、`idx_doc_acl_tenant_doc_active`、`idx_docs_tenant_status_quar_cl`、`idx_doc_citations_tenant_doc`、`idx_tx_tenant_acct_ts`、`idx_risk_decisions_tenant_dec`、`idx_audit_logs_tenant_ts_log`、`idx_audit_logs_tenant_sev_ts_log`，以及唯一索引 `idx_webhook_events_tenant_nonce`。同时将文档引用计数改为单次 `GROUP BY doc_id` 聚合查询，并将批次风控的多笔事务合并为单一 `BEGIN IMMEDIATE` + `executemany` 批量落盘。

### 1.2 核心算法时间复杂度与流式内存治理
1. **合规文档检索与近似修订簇去重（`aegis_app/search_service.py`）**：
   - **原瓶颈**：全表加载文档后逐篇重复查询权限与引用计数，且去重阶段对所有候选文档做 $O(N^2 \cdot L)$ 的双重循环重新分词与列表线性去重。
   - **改进方案**：构建租户级预分词倒排索引 `TenantDocIndex`（预计算 `title_tf`、`body_tf`、`token_set: frozenset[str]`、`cite_count` 与 `denied_users`/`denied_orgs`），查询词通过倒排索引 postings 并集快速召回，利益冲突墙降为 $O(1)$ 集合不相交判定；去重阶段利用“仅同非空 `regulation_code` 可折叠”的业务性质，按 `regulation_code` 分桶并在桶内使用 `frozenset` 交集计算 Jaccard 相似度，复杂度从 $O(N^2 \cdot L)$ 降至按桶局部集合运算。保留原版排序键与阈值判定，保证结果 100% 零失真。
2. **实时交易批次滑动时间窗（`aegis_app/rule_engine.py`）**：
   - **原瓶颈**：每笔交易全表扫描 `tenant_id` 并对每条历史记录无意义反序列化 `metadata_json`，复杂度 $O(B \cdot M)$。
   - **改进方案**：在 `evaluate_transaction_batch` 中先做全量输入预校验，随后按 `(tenant_id, account_id, ts)` 索引一次性加载窗口 `[min_ts - 86400, max_ts]` 内的必要列，按账户组织有序时间戳数组并采用 `bisect_left`/`bisect_right` 定位 `[ts - 86400, ts]` 区间与 `set` 统计唯一对手方，复杂度降至 $O(\log K + W)$，并在局部内存推演同批次先序交易，提交前若发生任何异常或主键冲突则整批原子回滚。
3. **审计摘要流式导出（`aegis_app/audit_export.py`）**：
   - **原瓶颈**：`export_audit_digest` 全量拉取 `payload_json` 并做 JSON 反序列化与两次 `copy.deepcopy`，空间复杂度 $O(N \cdot P)$。
   - **改进方案**：仅查询 `log_id, event_type, severity, amount_cents, masked_account, ts` 6 个必要列，通过 `cur.fetchmany(1000)` 流式迭代单遍累加统计与更新 `SHA-256`，仅保留前 `capped_sample`（≤50）条样本，空间复杂度降为 $O(1)$。

## 2. 并发控制粒度与安全隔离缓存设计（性能—安全平衡）

### 2.1 高并发读写与防竞争锁粒度设计
- 摒弃全局大锁，在 `aegis_app/runtime.py` 中实现**两级细粒度锁**：
  1. `DBRuntime.get_tenant_lock(tenant_id)`：按租户隔离写操作（如批次风控、权限/ACL/文档隔离/策略更新），不同租户完全并行；
  2. `DBRuntime.get_resource_lock(tenant_id, resource_key)`：针对配额扣减（`quota:<quota_type>`）、单次应急令牌核销（`token:<token_id>`）与 Webhook 防重放（`webhook:<nonce>`）按资源键加锁，并配合 SQLite `BEGIN IMMEDIATE` 与原子条件更新（`WHERE remaining_quota >= ?`、`WHERE used = 0`），彻底消除高并发 TOCTOU 超扣与重复核销。
- 读路径（检索、查询决策、审计导出）基于 WAL 模式与不可变快照对象实现无锁并发读取。

### 2.2 缓存键空间隔离与实时失效一致性机制
- 在 `DBRuntime` 中按租户维度隔离三个缓存域及各自单调递增版本号（Epoch）：
  1. **权限与认证缓存**（键 `(tenant_id, user_id)`，受 `_perm_epochs[tenant_id]` 保护）：`revoke_or_grant_role` 提交后立即 `bump_epoch("perm", tenant_id)`；
  2. **文档倒排索引与 ACL 隔离墙缓存**（键 `tenant_id`，受 `_doc_epochs[tenant_id]` 保护）：`set_document_quarantine` 与 `configure_doc_acl_rule` 提交后立即 `bump_epoch("doc", tenant_id)`；
  3. **风控策略缓存**（键 `tenant_id`，受 `_policy_epochs[tenant_id]` 保护）：`update_tenant_policy` 提交后立即 `bump_epoch("policy", tenant_id)`。
- **防并发撤权回填竞态**：所有缓存加载前记录 `ep_before`，构建完成后通过 `put_*_cached(..., expected_epoch=ep_before)` 在锁内比对当前 Epoch，若加载期间发生变更则放弃回填，杜绝旧数据覆盖。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 注入、路径穿越、越权（IDOR）与敏感信息防泄漏
- **SQL 注入修复**：`aegis_app/search_service.py` 中将 `tenant_id` 与 `tag_filter` 改为 `?` 参数化绑定，并对 `sort_by`、`sort_dir` 实施严格白名单校验。
- **路径穿越修复**：`aegis_app/audit_export.py` 的 `read_compliance_snapshot` 拒绝空字节、反斜杠、盘符、绝对路径及多轮 URL 解码后的 `.` / `..` 路径段，并通过 `pathlib.Path.resolve()` 与 `is_relative_to(base_dir)` 封堵符号链接逃逸，越界直接返回 403。
- **横向/纵向越权修复**：`batch_get_documents` 强制校验 `tenant_id`、`not quarantined`、`clearance_level <= live_clearance` 与利益冲突隔离墙；`get_risk_decision_detail` 增加 `AND tenant_id = ?` 过滤。
- **敏感信息防泄漏**：`aegis_app/server.py` 移除 `/api/v1/health?debug=1` 诊断信息、禁用 `/api/v1/internal/diagnostics`（返回 403），并彻底删除 500 异常响应中的 `debug_context`（不再暴露 `MASTER_SIGNING_PEPPER`、`db_path`、密钥与堆栈）。

### 3.2 回调防重放与抗算法复杂度炸弹（ReDoS / 深层载荷 / 慢查询放大）
- **Webhook 加固（`aegis_app/auth.py` `process_settlement_webhook`）**：校验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS`（300 秒窗口），使用 `hmac.compare_digest` 恒定时间比对签名，并依托 `webhook_events(tenant_id, nonce)` 唯一索引捕获重放并返回 409。
- **ReDoS 消除（`aegis_app/rule_engine.py`）**：将 `validate_contact_email` 重构为基于 `@` 拆分后的无嵌套量词线性正则 `_EMAIL_LOCAL_RE` / `_EMAIL_DOMAIN_RE`；在 `_is_safe_regex` 中静态拦截嵌套量词、前瞻/后顾与反向引用并限制长度。
- **深层载荷与慢查询熔断**：`rule_engine.py` 强制限制规则树深度 `MAX_RULE_DEPTH = 16`、节点总数 `MAX_RULE_NODES = 256` 及批次大小 `MAX_BATCH_SIZE = 2000`；`search_service.py` 限制 `query` 长度 ≤512、词项 ≤32、`limit` 在 `[1, 200]`、`offset` 在 `[0, 100000]`、`batch_get` ≤200；`server.py` 限制请求体 ≤4MB。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 算法降维声明]**：`aegis_app/search_service.py` 中 `TenantDocIndex`、`search_documents` 采用预分词倒排索引与按 `regulation_code` 分桶的 `frozenset` Jaccard 去重；`aegis_app/rule_engine.py` 中 `evaluate_transaction_batch` 采用按 `(tenant_id, account_id, ts)` 索引批量预取与 `bisect_left`/`bisect_right` 滑动窗口定位（单事务 `executemany` 原子提交）；`aegis_app/audit_export.py` 中 `export_audit_digest` 采用轻量列投影与 `fetchmany(1000)` 流式摘要。
- **[C2 缓存隔离与失效声明]**：`aegis_app/runtime.py` 中 `DBRuntime` 维护按 `tenant_id` 隔离的 `_perm_epochs`/`_doc_epochs`/`_policy_epochs` 版本号及对应 `get_*_cached`/`put_*_cached` 双检查防竞态回填机制；在 `aegis_app/auth.py`（`revoke_or_grant_role`、`configure_doc_acl_rule`）、`aegis_app/search_service.py`（`set_document_quarantine`）与 `aegis_app/rule_engine.py`（`update_tenant_policy`）提交后立即调用 `bump_epoch` 实时失效。
- **[C3 并发原子性与锁粒度声明]**：`aegis_app/runtime.py` 提供 `get_tenant_lock` 与 `get_resource_lock` 分片细粒度锁；`aegis_app/auth.py` 中 `consume_tenant_quota` 与 `redeem_override_token` 在资源锁与 SQLite `BEGIN IMMEDIATE` 事务内执行原子条件更新（`WHERE remaining_quota >= ?` 与 `WHERE used = 0`）彻底防止 TOCTOU 超扣与重复核销。
- **[C4 注入/越权/路径边界防御声明]**：`aegis_app/search_service.py` 对 `search_documents` 参数化绑定 `tag_filter` 与白名单校验 `sort_by`/`sort_dir`，并在 `batch_get_documents` 强制执行租户、隔离、密级与利益冲突墙校验；`aegis_app/rule_engine.py` 中 `get_risk_decision_detail` 增加 `AND tenant_id = ?` 防跨租户 IDOR；`aegis_app/audit_export.py` 中 `read_compliance_snapshot` 通过多轮解码检查与 `resolve().is_relative_to(base_dir)` 封堵路径穿越；`aegis_app/server.py` 禁用内部诊断端点并移除 `debug_context` 密钥泄露。
- **[C5 抗复杂度炸弹熔断声明]**：`aegis_app/rule_engine.py` 中 `validate_contact_email` 消除嵌套量词改为线性分段匹配，`_is_safe_regex` 与 `_validate_rule_tree` 拦截 ReDoS 正则并强制限制 `MAX_RULE_DEPTH = 16`、`MAX_RULE_NODES = 256`、`MAX_BATCH_SIZE = 2000`；`aegis_app/search_service.py` 强制限制 `MAX_QUERY_LEN = 512`、`MAX_QUERY_TERMS = 32`、`MAX_PAGE_LIMIT = 200`、`MAX_PAGE_OFFSET = 100000`、`MAX_BATCH_GET_IDS = 200`。

## 5. 已知工程取舍与残余边界说明
1. **单机进程内缓存边界**：`DBRuntime` 的 Epoch 缓存驻留在当前 Python 进程内存中，适用于单网关进程多线程服务模型；若未来扩展为多进程/多节点共享同一外部数据库，需将 Epoch 版本协调替换为共享存储（如 Redis 或 SQLite 元数据版本号表）。
2. **SQLite 写并发特性**：在 WAL 模式下多租户读请求与跨租户写前计算可高度并行，但受限于 SQLite 单文件单写者机制，极高并发写事务在底层提交瞬间仍需通过 `BEGIN IMMEDIATE` 与 `busy_timeout` 排队，我们通过将滑动窗口计算移至批次事务内局部内存并采用 `executemany` 批量写入，将单次持写锁时间压缩至最低。
