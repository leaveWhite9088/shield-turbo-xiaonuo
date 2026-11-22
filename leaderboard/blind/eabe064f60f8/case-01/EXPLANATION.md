# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
- **缺失二级索引与 WAL 模式**：原版 `aegis_app/db.py` 仅建有主键而无任何二级索引，导致 `transactions(tenant_id, account_id, ts)`、`compliance_docs(tenant_id, status, quarantined, ...)`、`doc_citations(tenant_id, doc_id)`、`audit_logs(tenant_id, ts, log_id)`、`doc_acl_rules(tenant_id, active)` 及 `role_grants(tenant_id, user_id, active)` 全走全表扫描；同时默认回滚日志模式在并发读写下互相阻塞。我们在 `aegis_app/db.py` 中新增 `INDEX_SQL`（共 16 个索引，含 `webhook_events(tenant_id, nonce)` 唯一索引）与 `ensure_db_optimized()`，在 `AegisGateway.__init__` 启动时对存量数据库幂等开启 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL`、`temp_store=MEMORY`、`cache_size=-32000`、`mmap_size=67108864` 与 `busy_timeout=30000`，绝不清空已有业务数据。
- **连接风暴与 N+1 查询放大**：原版在 `resolve_org_ancestors`、`is_doc_blocked_by_acl`、`_get_doc_citation_count` 和 `evaluate_transaction_batch` 循环内反复调用 `sqlite3.connect()`/`close()`；单次 `search_documents` 会为每篇候选文档分别重查权限、ACL 规则和引用次数。我们在 `aegis_app/db.py` 实现了基于 `threading.local()` 的线程局部持久连接池 `get_thread_connection()`（`isolation_level=None` 配合显式 `BEGIN IMMEDIATE` 事务边界），并将组织树、租户 ACL、文档引用计数与策略改为按租户单次批量加载。
- **逐笔提交事务退化**：原版 `evaluate_transaction_batch` 在循环内逐笔 `INSERT` + `COMMIT`，不仅产生大量 fsync 开销，更破坏了整批原子性。重构后改为单次 `BEGIN IMMEDIATE` 事务内批量预拉取窗口历史 + `executemany` 一次性提交，冲突或异常时完整 `ROLLBACK`。

### 1.2 核心算法时间复杂度与流式内存治理
- **合规文档检索与去重降维（`aegis_app/search_service.py`、`aegis_app/runtime.py`）**：
  - 原版每次检索全表扫描文档、循环内 N+1 查权限/ACL/引用、重复正则分词，且去重使用 $O(N^2 \cdot L^2)$ 嵌套循环（先计算基于 `list` 的 Jaccard 再判断 `same_reg`）。
  - 我们在 `aegis_app/runtime.py` 与 `aegis_app/search_service.py` 中构建了租户级预分词倒排索引 `TenantDocIndex`（`_build_tenant_doc_index`），单次加载并预计算每篇文档的截断词频（`title_tf_capped`、`body_tf_capped`）、`frozenset` 词项集合 `token_set`、`base_score` 及 `inverted`/`by_category`/`by_tag` 索引。即使遭遇 100% 不重复参数的缓存穿透洪水（Cache-Busting Flood），查询复杂度仍从 $O(N \cdot L)$ 降至 $O(|P|)$（仅扫描倒排命中的候选下标）。
  - 去重函数 `_deduplicate_scored_docs` 按 `regulation_code` 分桶（不同法规代码间数学上绝不合并，同桶内严格保持 `(-score, -updated_at, doc_id)` 顺序贪心聚簇，与原版 100% 等价），结合集合大小下界剪枝（$\min(|A|,|B|) < 0.70 \times \max(|A|,|B|)$ 直接跳过）与 `frozenset` 位运算交集，将去重复杂度从 $O(N^2 \cdot L^2)$ 降至桶内均摊 $O(K^2 \cdot \min(|A|,|B|))$ 且实际绝大多数不同簇被下界剪枝 O(1) 跳过。
- **实时批次滑动时间窗降维（`aegis_app/rule_engine.py`）**：
  - 原版每笔交易全表扫 `transactions WHERE tenant_id = ?` 并对每行无用 `json.loads(metadata_json)`，复杂度 $O(B \cdot H)$。
  - 重构后按涉及账户的 `[min_ts - 86400, max_ts]` 边界走 `idx_tx_tenant_acct_ts` 索引范围查询，完全不读取/解析 `metadata_json`。在本次请求局部栈帧中按账户时间戳特征自动分发：单调非递减序列走 `_MonotonicAccountWindow`（`deque` + `Counter`，均摊 $O(1)$/笔）；存在乱序时间戳的账户走 `_GeneralAccountWindow`（`bisect_left`/`bisect_right` 精确区间统计），彻底保证与原版 24 小时闭区间滑窗及同批次先序依赖 100% 零失真，且批次失败回滚时局部栈对象随函数退出自动销毁，零内存幽灵状态残留。
- **审计摘要流式内存治理（`aegis_app/audit_export.py`）**：
  - 原版 `export_audit_digest` 全量 `fetchall()` 并解析无用的 `payload_json`，随后两次 `copy.deepcopy` 构造 `expanded_records` 与 `archive_mirror`，造成 $O(N)$ 数倍内存膨胀。
  - 重构后仅查询必要 6 列，通过 `cursor.fetchmany(1000)` 流式分块增量更新 `hashlib.sha256()`、分布计数器与最多 50 条样本，空间复杂度降至 $O(1)$，滚动摘要结果与原版比特级一致。

## 2. 并发控制粒度与安全隔离缓存设计（性能—安全平衡）

### 2.1 高并发读写与防竞争锁粒度设计
- **杜绝全局大锁**：`aegis_app/runtime.py` 中 `DatabaseRuntime` 仅在首次创建租户对象时短暂持有注册表锁，之后所有并发读写均按租户物理隔离在各自独立的 `TenantRuntime` 中。
- **细粒度资源分片锁 + SQLite 原子条件更新**：针对 `consume_tenant_quota` 与 `redeem_override_token` 的高并发 TOCTOU 穿盾风险，我们在 `TenantRuntime.get_resource_lock(resource_key)` 中按 `quota:{quota_type}` 与 `override_token:{token_id}` 分配细粒度锁（不同租户、同租户不同配额或不同令牌完全无锁竞争），并在 DB 层叠加 `BEGIN IMMEDIATE` 事务下的单条原子条件 `UPDATE`（`WHERE ... AND remaining_quota >= ?` 与 `WHERE ... AND used = 0`）检查 `rowcount == 1`，从应用层与存储层双重杜绝超扣或重复核销，同时 SQLite WAL 模式确保所有只读查询不被写事务阻塞。

### 2.2 缓存键空间隔离与实时失效一致性机制
- **分租户物理隔离与多维版本戳（Epoch）**：每个 `TenantRuntime` 独立维护 `doc_epoch`、`perm_epoch`、`acl_epoch`、`policy_epoch` 四个单调递增版本戳，缓存租户组织树 `org_tree`、用户权限 `perm_cache`、利益冲突墙快照 `acl_snapshot`、倒排文档索引 `doc_index`、风控策略 `policy_snapshot` 以及有界搜索结果缓存 `search_lru`（每租户上限 256 条防缓存穿透 OOM）。
- **用户/密级/利益冲突墙隔离键**：`search_documents` 的 `search_lru` 缓存键显式包含 `(doc_epoch, perm_epoch, acl_epoch, caller.user_id, live_clearance, query, category, tag_filter, deduplicate, sort_by, sort_dir, limit, offset)`，确保同租户、同密级但处于利益冲突墙两侧的平行团队（如 `analyst` 与 `researcher`）绝不串味。
- **写后即时失效 + Epoch CAS 防旧读回填竞态**：当管理员调用 `set_document_quarantine`、`revoke_or_grant_role`、`configure_doc_acl_rule` 或 `update_tenant_policy` 提交事务后，立即调用 `bump_doc_epoch()` / `bump_perm_epoch()` / `bump_acl_epoch()` / `bump_policy_epoch()` 递增对应版本戳并清空受影响缓存槽。所有读路径在加载 DB 前先捕获当前 epoch，回填缓存时（`put_cached_perm`、`put_cached_acl`、`put_cached_doc_index`、`put_cached_policy`、`put_search_lru`）均在锁内校验当前 epoch 仍等于读取前快照；若读取期间发生并发撤权或隔离，则直接丢弃本次回填，彻底消除“读后回填旧数据”竞态。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 注入、路径穿越、越权（IDOR）与敏感信息防泄漏
- **SQL 注入防御（`aegis_app/search_service.py`）**：彻底移除 `search_documents` 中对 `tenant_id`、`tag_filter` 和 `ORDER BY` 的字符串拼接；`sort_by` 强制白名单 `{"score", "updated_at", "risk_weight"}`，`sort_dir` 强制白名单 `{"asc", "desc"}`，非法值直接返回 `400`；所有 SQL 查询一律参数化。
- **多变体路径穿越防御（`aegis_app/audit_export.py`）**：重构 `read_compliance_snapshot`，通过多层循环 `urllib.parse.unquote` 拦截双重编码（如 `%252e%252e%252f`），拒绝空字节、斜杠、反斜杠、`..`、驱动器冒号，并施加单文件名正则白名单 `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`；同时叠加 `is_symlink()` 禁止符号链接与 `target_path.resolve().is_relative_to(base_dir.resolve())` 规范化目录边界硬校验。
- **横向与纵向越权（IDOR）封堵**：
  - `aegis_app/search_service.py` 的 `batch_get_documents` 强制增加 `tenant_id = ?`、`status = 'ACTIVE'`、`quarantined = 0`、`clearance_level <= live_clearance` 以及 `get_denied_doc_ids` 利益冲突隔离墙过滤，彻底堵住跨租户、跨密级、已隔离与隔离墙文档越权读取。
  - `aegis_app/rule_engine.py` 的 `get_risk_decision_detail` 在 `WHERE` 子句强制增加 `AND tenant_id = ?`，封堵跨租户风控决策查询 IDOR。
  - `aegis_app/auth.py` 认证凭证比对改用恒定时间 `hmac.compare_digest`。
- **内部诊断与异常密钥防泄漏（`aegis_app/server.py`）**：彻底删除 `_collect_diagnostics`、`/api/v1/health?debug=1` 敏感输出与 `/api/v1/internal/diagnostics` 暴露端点；移除全局 `except Exception` 中的 `debug_context`、`traceback`、`db_path`、`storage_dir` 与 `MASTER_SIGNING_PEPPER` 泄露，仅返回通用安全错误。

### 3.2 回调防重放与抗算法复杂度炸弹（ReDoS / 深层载荷 / 慢查询放大）
- **Webhook 签名、过期与原子防重放（`aegis_app/auth.py`、`aegis_app/db.py`）**：`process_settlement_webhook` 强制校验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS`（±300s 窗口），采用 `hmac.compare_digest` 恒定时间验证 HMAC-SHA256 签名，并在 `webhook_events(tenant_id, nonce)` 上建立数据库唯一索引 `idx_webhook_tenant_nonce`，并发或事后重放同一 Nonce 触发 `sqlite3.IntegrityError` 并原子映射为 `ConflictError`（HTTP `409`）。
- **抗 ReDoS 与畸形规则树熔断（`aegis_app/rule_engine.py`）**：
  - 彻底消除 `validate_contact_email` 原嵌套量词正则 `([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+`，拆分为按 `@` 分割后的无回溯线性正则 `_EMAIL_LOCAL_RE` 与 `_EMAIL_DOMAIN_RE`（长度上限 254），在任意恶意输入下严格 $O(n)$ 微秒级完成。
  - 新增 `validate_rule_tree` 与 `_compile_safe_regex`，对 `simulate_custom_rule` 与 `update_tenant_policy` 强制执行最大深度 `MAX_RULE_DEPTH = 16`、最大节点数 `MAX_RULE_NODES = 128`、最大子节点数 `MAX_RULE_CHILDREN = 32`、`IN` 列表最大长度 `64`、正则最大长度 `128` 及静态嵌套量词/反向引用/环视/多无界通配符检测（`_has_nested_quantifier`），恶意载荷毫秒级返回 `400`。
- **极端分页、通配符与超大载荷熔断（`aegis_app/search_service.py`、`aegis_app/server.py`）**：`search_documents` 强制限制 `0 <= limit <= 200`、`0 <= offset <= 10000`、`len(query) <= 512`、唯一词项 `<= 32`、通配符数量 `<= 8`；`batch_get_documents` 限制 `<= 200`；`evaluate_transaction_batch` 限制 `<= 2000`；HTTP 与网关层统一限制请求体大小 `<= 2MB`。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 算法降维声明]**：在 `aegis_app/search_service.py` 中通过 `_build_tenant_doc_index` 与 `_deduplicate_scored_docs` 构建租户级预分词内存倒排索引（`TenantDocIndex`）与按 `regulation_code` 分桶 + 集合大小下界剪枝的 `frozenset` Jaccard 去重，将检索与去重从 $O(N^2 \cdot L^2)$ 与 N+1 查询降至倒排候选集上的亚毫秒级运算；在 `aegis_app/rule_engine.py` 中通过 `evaluate_transaction_batch` 配合 `_MonotonicAccountWindow`（`deque` + `Counter`，均摊 $O(1)$）与 `_GeneralAccountWindow`（`bisect`）实现索引范围滑动窗口计算，并通过 `aegis_app/audit_export.py` 的 `export_audit_digest` 采用 `cursor.fetchmany(1000)` 流式聚合将内存复杂度从 $O(N)$ 降至 $O(1)$。
- **[C2 缓存隔离与失效声明]**：在 `aegis_app/runtime.py`（`TenantRuntime`）与 `aegis_app/search_service.py`（`search_documents`）中实现了按租户物理隔离的多维版本戳缓存体系，搜索缓存键包含 `(doc_epoch, perm_epoch, acl_epoch, caller.user_id, live_clearance, query, category, tag_filter, deduplicate, sort_by, sort_dir, limit, offset)`；当 `set_document_quarantine`、`revoke_or_grant_role`、`configure_doc_acl_rule`、`update_tenant_policy` 提交后立即调用 `bump_*_epoch()` 清空对应缓存，且所有回填方法（`put_search_lru`、`put_cached_perm`、`put_cached_acl`、`put_cached_doc_index`、`put_cached_policy`）均执行 epoch CAS 校验，杜绝并发撤权/隔离期间的旧读回填脏数据。
- **[C3 并发原子性与锁粒度声明]**：在 `aegis_app/runtime.py`（`TenantRuntime.get_resource_lock`）与 `aegis_app/auth.py`（`consume_tenant_quota`、`redeem_override_token`）中采用按租户与具体资源键（`quota:{quota_type}`、`override_token:{token_id}`）分片的细粒度锁，杜绝全局大锁阻塞跨租户并发；在 SQLite 层配合 WAL 模式与 `BEGIN IMMEDIATE` 下的单条原子条件 `UPDATE`（`WHERE ... AND remaining_quota >= ?` 与 `WHERE ... AND used = 0`）防高并发 TOCTOU 超扣，并在 `aegis_app/rule_engine.py` 的 `evaluate_transaction_batch` 中通过单事务 `executemany` + 局部栈窗口实现数据库与内存双原子回滚。
- **[C4 注入/越权/路径边界防御声明]**：在 `aegis_app/search_service.py` 的 `_validate_search_inputs` 强制 `ALLOWED_SORT_BY`/`ALLOWED_SORT_DIR` 白名单并在 `batch_get_documents` 强制校验 `tenant_id`、`status='ACTIVE'`、`quarantined=0`、`clearance_level <= live_clearance` 与 `get_denied_doc_ids` 利益冲突隔离墙；在 `aegis_app/rule_engine.py` 的 `get_risk_decision_detail` 增加 `AND tenant_id = ?` 封堵跨租户 IDOR；在 `aegis_app/audit_export.py` 的 `read_compliance_snapshot` 通过循环 `unquote`、文件名白名单正则 `_SAFE_SNAPSHOT_NAME_RE`、禁止符号链接与 `resolve().is_relative_to(base_dir)` 封堵多变体路径穿越；在 `aegis_app/server.py` 移除 `/api/v1/health?debug=1`、`/api/v1/internal/diagnostics` 及 500 响应中的密钥/路径/堆栈泄露。
- **[C5 抗复杂度炸弹熔断声明]**：在 `aegis_app/rule_engine.py` 中重构 `validate_contact_email` 彻底消除嵌套量词 ReDoS，并在 `validate_rule_tree` 与 `_compile_safe_regex`/`_has_nested_quantifier` 中对规则树强制施加 `MAX_RULE_DEPTH = 16`、`MAX_RULE_NODES = 128`、`MAX_RULE_CHILDREN = 32`、`MAX_IN_LIST_SIZE = 64`、正则长度 `<= 128` 及嵌套量词/反向引用/环视拦截；在 `aegis_app/search_service.py` 的 `_validate_search_inputs` 中强制限制 `limit <= 200`、`offset <= 10000`、`len(query) <= 512`、唯一词项 `<= 32` 及通配符 `<= 8`；在 `aegis_app/auth.py` 的 `process_settlement_webhook` 与 `aegis_app/db.py` 的 `idx_webhook_tenant_nonce` 唯一索引中实现 ±300s 时间窗、恒定时间签名比对与原子防重放。

## 5. 已知工程取舍与残余边界说明
1. **单机进程内缓存边界**：`DatabaseRuntime` 与 `TenantRuntime` 的版本戳与倒排索引维护在单进程内存中，适用于当前单进程多线程网关部署模型；若未来扩展为多进程/多节点水平集群，需将 `*_epoch` 版本戳与细粒度资源锁迁移至外部共享存储（如 Redis 或 SQLite 独立版本表）以维持跨进程强一致。
2. **SQLite 单写者吞吐上限**：尽管已开启 WAL 模式、分租户细粒度锁并将计算密集型校验与分词移出事务临界区，SQLite 在物理存储层同一时刻仍只允许一个活跃写事务（`BEGIN IMMEDIATE`）；极端跨租户纯写并发下会通过 `busy_timeout=30000` 排队串行提交。
3. **倒排索引冷启动与内存占用**：每个租户首次检索（或文档隔离状态变更后首次检索）会触发 `_build_tenant_doc_index` 单次加载并预分词该租户所有活跃文档，属于“以一次性低成本索引构建换取后续高并发及缓存穿透场景下的亚毫秒级响应”的经典空间换时间取舍；当单个租户文档数增长至十万级以上时，需进一步演进为 SQLite FTS5 或分片倒排存储。
