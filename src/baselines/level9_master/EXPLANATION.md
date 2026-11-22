# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
1. **线程本地持久连接与 WAL 并发优化**：原版每次请求与内部子查询均反复调用 `sqlite3.connect()` 并关闭连接，且默认回滚日志模式阻塞读写并发。在 `aegis_app/db.py` 中实现了 `get_thread_connection` 线程本地连接复用，并在建连时开启 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL` 与 `temp_store=MEMORY`。
2. **高频复合覆盖索引**：在 `init_schema` 中幂等补齐 `idx_opt_tx_tenant_acct_ts(tenant_id, account_id, ts)`、`idx_opt_docs_tenant_active(tenant_id, status, quarantined, category)`、`idx_opt_citations_tenant_doc`、`idx_opt_audit_tenant_log_ts` 及 `idx_opt_webhook_tenant_nonce` 唯一防重放索引。
3. **彻底消除 N+1 查询与逐笔落盘事务**：原版在文档检索循环内逐篇查组织权限树、逐篇查 `doc_citations`，在交易批次评估中逐笔全表扫描并逐笔 `commit()`。重构后单租户文档与引用计数合并为 2 条批量查询构建内存索引，批次风控合并为 1 次按账户集窗口预取 + 单事务 `executemany` 批量落盘。

### 1.2 核心算法时间复杂度与流式内存治理
1. **文档检索与近似修订簇折叠从 $O(N^2)$ 降维至 $O(K)$**：在 `aegis_app/search_service.py` 构建 `TenantDocIndex` 预分词倒排词项表（`postings`），查询时仅访问命中词项的候选文档；针对 `deduplicate=True` 的近似去重，利用“同 `regulation_code` 方可归并”的不变量，使用 `kept_by_reg` 按法规号哈希分桶并结合词集长度比上界 `min_len / max_len < 0.70` 剪枝，数学输出与原版 100% 严格同构。
2. **批次实时风控滑动时间窗预取**：在 `aegis_app/rule_engine.py` 的 `evaluate_transaction_batch` 中一次性预取批次涉及账户在 `[min_ts - 86400, max_ts]` 内的历史流水，并在内存中按序增量推进滑动窗口，严格保留同批次内先序交易对后续窗口的影响。
3. **审计报表游标流式化**：在 `aegis_app/audit_export.py` 的 `export_audit_digest` 中剔除无需读取的 `payload_json` 大字段，改用 `cur.fetchmany(256)` 流式迭代计算分布与 `rolling_sha256`，将内存峰值从全表深拷贝的线性膨胀降为常数级。

## 2. 并发控制粒度与安全隔离缓存设计（性能—安全平衡）

### 2.1 高并发读写与防竞争锁粒度设计
摒弃阻塞全站的全局锁，在 `aegis_app/db.py` 设计 64 路细粒度键级分片锁池 `get_striped_lock(db_path, tenant_id, scope)`，仅对同一租户同一特定写资源（如单类配额、单张应急令牌、单租户风控批次写入）互斥；跨租户并发读完全无锁并行。同时在 SQL 层配合 `BEGIN IMMEDIATE` 与条件原子更新（`WHERE remaining_quota >= ?`、`WHERE used = 0`），彻底杜绝 30 路并发条件竞争（TOCTOU）穿盾。

### 2.2 缓存键空间隔离与实时失效一致性机制
在 `aegis_app/db.py` 引入进程内原子租户纪元表 `_TENANT_EPOCHS`（含 `perm`、`doc`、`policy` 三个独立版本号）：
- 权限缓存键包含 `(db_key, tenant_id, perm_epoch, user_id)`；
- 检索结果缓存键包含 `(db_key, tenant_id, doc_epoch, perm_epoch, max_clearance, ...)`；
- 当执行 `revoke_or_grant_role`、`set_document_quarantine` 或 `update_tenant_policy` 提交事务后，立即调用 `bump_tenant_epoch` 原子递增对应维度纪元，确保撤权、隔离文档与更新策略在亚毫秒级对后续读取精准生效，零跨租户/跨密级串味、零撤权脏读。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 注入、路径穿越、越权（IDOR）与敏感信息防泄漏
1. **防 SQL 注入**：`search_service.py` 对 `sort_by`、`sort_dir`、`tag_filter` 实施严格枚举/正则白名单校验，所有 SQL 条件全量使用 `?` 参数化绑定。
2. **防路径穿越**：`server.py` 拦截 `%25` 双重编码，`audit_export.py` 的 `read_compliance_snapshot` 强制执行 `SAFE_SNAPSHOT_NAME_RE` 文件名白名单，并通过 `Path.resolve().is_relative_to(base_dir)` 锁死物理目录边界。
3. **防横向与纵向越权（IDOR）**：`batch_get_documents` 同时强制校验 `tenant_id = ?`、`quarantined = 0` 与 `clearance_level <= caller.max_clearance`；`get_risk_decision_detail` 强制绑定 `AND tenant_id = ?`。
4. **防密钥与内部路径泄露**：移除 `/api/v1/health?debug=1` 敏感诊断回显，禁用 `/api/v1/internal/diagnostics`，全局 500 错误拦截器隐藏内部堆栈、`db_path` 与 `MASTER_SIGNING_PEPPER`。

### 3.2 回调防重放与抗算法复杂度炸弹（ReDoS / 深层载荷 / 慢查询放大）
1. **Webhook 验签与防重放**：`process_settlement_webhook` 实施 `±300s` 时间窗校验、`hmac.compare_digest` 常量时间比对，并依托唯一索引 `idx_opt_webhook_tenant_nonce(tenant_id, nonce)` 原子拦截重放报文。
2. **抗三大复杂度炸弹**：
   - 邮箱校验改为纯线性扫描函数 `validate_contact_email`，彻底移除嵌套量词正则；
   - `validate_rule_tree_budget` 强制限制规则树深度 `<= 12`、节点总数 `<= 128`，并拦截危险自定义 `REGEX` 量词；
   - 检索接口强制约束 `1 <= limit <= 100`（封堵 SQLite `LIMIT -1` 全表扫描漏洞）、`0 <= offset <= 5000`、查询词数 `<= 16` 及通配符数量上限。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 算法降维声明]**：`aegis_app/search_service.py` 中的 `TenantDocIndex` 与 `_get_or_build_tenant_index` 构建预分词倒排表，并在 `search_documents` 中使用 `kept_by_reg` 哈希分桶与集合长度剪枝替代原版双重循环去重；`aegis_app/audit_export.py` 的 `export_audit_digest` 采用 `cur.fetchmany(256)` 流式聚合。
- **[C2 缓存隔离与失效声明]**：`aegis_app/db.py` 实现 `get_tenant_epochs` 与 `bump_tenant_epoch`；`search_service.py` 的 `_SEARCH_RESULT_CACHE` 严格绑定 `(db_key, tenant_id, doc_epoch, perm_epoch, max_clearance, ...)`，并在权限变更、文档隔离、策略更新时立即递增版本失效。
- **[C3 并发原子性与锁粒度声明]**：`aegis_app/db.py` 实现 64 路分片锁 `get_striped_lock`；`aegis_app/auth.py` 的 `consume_tenant_quota` 与 `redeem_override_token` 结合分片锁、`BEGIN IMMEDIATE` 与单条条件 `UPDATE`（检查 `cur.rowcount`）防御高并发 TOCTOU。
- **[C4 注入/越权/路径边界防御声明]**：`aegis_app/search_service.py` 的 `batch_get_documents` 强制绑定 `tenant_id` 与 `clearance_level <= caller.max_clearance`；`aegis_app/rule_engine.py` 的 `get_risk_decision_detail` 绑定 `tenant_id`；`aegis_app/audit_export.py` 的 `read_compliance_snapshot` 使用 `SAFE_SNAPSHOT_NAME_RE` 与 `Path.resolve().is_relative_to(base_dir)`。
- **[C5 抗复杂度炸弹熔断声明]**：`aegis_app/rule_engine.py` 用线性函数 `validate_contact_email` 消除回溯正则，并通过 `validate_rule_tree_budget` 限制深度 `MAX_RULE_DEPTH=12` 与节点数 `MAX_RULE_NODES=128`；`aegis_app/search_service.py` 强制限制 `1 <= limit <= 100`、`0 <= offset <= 5000` 与 `MAX_QUERY_TERMS=16`。

## 5. 已知工程取舍与残余边界说明
当前租户纪元版本与倒排索引维护在单进程内存中，适用于单网关实例多线程高并发场景；若未来横向扩展至多进程/多机集群，可将 `_TENANT_EPOCHS` 下沉至 SQLite 共享版本表并通过每次请求极轻量的主键版本读取触发跨进程缓存同步。
