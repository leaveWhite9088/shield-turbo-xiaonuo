# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
1. **有界 LIFO 连接池与 WAL 并发持久化（`aegis_app/db.py`）**：
   - 原版每次函数调用（甚至在 `acl_wall.get_org_lineage`、`delegation._collect_upstream_grantors`、`search_service.search_documents` 循环内部）均新建并销毁 SQLite 连接，引发海量文件句柄开销与锁竞争。
   - 重构后在 `aegis_app/db.py` 中实现 `PooledConnection` 与按规范化数据库路径隔离的有界连接池（`_CONN_POOLS`，单库最大容量 `_POOL_MAX_SIZE = 32`，全局最多缓存 64 个库池），连接初始化时统一启用 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL`、`temp_store=MEMORY`、`cache_size=-16000` 与 `busy_timeout=30000`，归还连接池前自动检测 `in_transaction` 并回滚未提交事务。
2. **核心表复合索引补齐（`aegis_app/db.py`）**：
   - 在 `SCHEMA_SQL` 中新增 15 个高频访问路径复合索引与唯一约束索引：`idx_users_tenant_user`、`idx_org_nodes_tenant_node`、`idx_role_grants_tenant_user`、`idx_delegation_grantee`、`idx_delegation_grantor`、`idx_doc_acl_tenant_doc`、`idx_docs_tenant_status`、`idx_citations_tenant_doc`、`idx_citations_tenant_ref`、`idx_tx_tenant_ts`、`idx_tx_tenant_acct_ts`、`idx_decisions_tenant_id`、`idx_audit_tenant_logid`、`idx_audit_tenant_ts` 以及防并发重放唯一索引 `idx_webhook_tenant_nonce`。
3. **消除 N+1 循环内查询与批量写入合并**：
   - `search_documents` 中彻底消除逐文档调用 `resolve_effective_permissions`、`is_doc_blocked_by_acl` 与 `_get_doc_citation_count` 的 $3N$ 次数据库往返；
   - `evaluate_transaction_batch` 将原本逐笔打开两次连接、全表拉取 `transactions` 并逐条反序列化 `metadata_json` 的模式，重构为单事务内内存增量评估 + `executemany` 批量持久化。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
1. **紧凑单篇增量倒排索引与 $O(\text{deg})$ 双向引用传播（`aegis_app/doc_indexer.py`）**：
   - 定义 `__slots__` 紧凑结构 `CompactDocNode`，仅存储预分词截断词频（`title_tf` 上限 5、`body_tf` 上限 12）、词项有序位置元组 `body_positions`、词袋集合 `vocab_set` 以及前 140 字符摘要 `snippet`，**彻底丢弃大体积原始全文 `body`**，使常驻堆内存降低一个数量级。
   - `TenantDocIndex` 维护倒排表 `inverted` 与内部引用反向依赖图 `reverse_dependents`（记录 `source_doc_id -> set[citing_doc_id]`）。当执行 `upsert_compliance_document`、`retire_compliance_document` 或 `set_document_quarantine` 时，仅对当前文档执行 $O(|T_{\text{doc}}|)$ 增量倒排挂载/卸载，并沿 `reverse_dependents` 以 $O(\text{deg})$ 局部重算直接引用方的 `effective_citation_count`，无需整表扫描或全量重建索引。
2. **双指针词距邻近度扫描与 `min_dist == 1` 早停（`aegis_app/doc_indexer.py`）**：
   - 原版 `compute_phrase_proximity_bonus` 对正文全量枚举两重循环 $O(|B|^2)$。重构后在 `compute_phrase_proximity_bonus_from_positions` 中直接读取 `CompactDocNode.body_positions` 的有序位置元组，执行 $O(|\text{pos}_a| + |\text{pos}_b|)$ 双指针线性归并扫描，并在发现最小距离 `min_dist == 1` 时立即 `break` 早停。
3. **双轨法规近似去重集合比值剪枝（`aegis_app/search_service.py`）**：
   - 原版对所有候选对重新分词并做 $O(K^2 \cdot L^2)$ 列表查重。重构后按归一化法规号 `_canon_reg` 分桶，桶内先执行集合大小比值剪枝（若 `min_l / max_l < 0.70` 则数学上 Jaccard 必小于 `0.70`，直接跳过），再基于预存 `frozenset` 词袋做 $O(|V|)$ 位集合交并计算。
4. **滑动窗口 $O(\log W)$ 动态中位数与乱序时间戳精确回退（`aegis_app/window_stats.py`）**：
   - 原版使用 $O(W^2)$ 冒泡排序。重构后 `AccountWindowTracker` 在单调时间推进下通过双端队列 `win_queue`、有序列表 `bisect.insort`（`win_sorted_amounts`）与对手方引用计数表 `win_cp_counts` 实现 $O(\log W)$ 滑窗推进与 $O(1)$ 中位数读取；当遇到乱序历史时间戳（`ts < max_ts`）时，自动在有序历史序列 `records` 上通过 `bisect_left` / `bisect_right` 精确截取 `[ts - 86400, ts]` 窗口，确保乱序与单调场景 100% 零失真。
5. **三跳受制裁实体传染有界双向邻域搜索（`aegis_app/contagion_graph.py`）**：
   - 原版每笔交易全表扫描并从所有黑名单源点跑全图 BFS。重构后 `TenantTxEngine` 维护活跃窗口边队列 `edge_queue` 与最新邻接时间戳字典 `adj_latest_ts`，评估时从当前交易两端 `(account_id, counterparty_id)` 出发最多向外扩展 2 层邻居（`nbrs_1` 及第二层邻居）测试是否命中 `sanctioned_set`，将时间复杂度从 $O(|S| \cdot (|V| + |E|))$ 降至 $O(d_{\text{avg}}^2)$，同样支持乱序时间戳二分切片回退。
6. **审计摘要 $O(1)$ 内存游标流式聚合（`aegis_app/audit_export.py`）**：
   - 原版在 `_compute_digest_from_records` 中 `SELECT payload_json`、全量 `fetchall()`、`json.loads` 并做两轮 `copy.deepcopy`。重构后 SQL 仅查询摘要所需的 6 个轻量标量列，通过 `_stream_digest_from_cursor` 逐行流式迭代游标计算 `rolling_sha256` 与分布统计，仅保留前 `min(sample_limit, 50)` 条样本，空间复杂度从 $O(N \cdot |P|)$ 降至 $O(1)$。

---

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
1. **租户级细粒度锁与全局严格锁偏序（`aegis_app/db.py`、`aegis_app/ledger_ops.py`、`aegis_app/rule_engine.py`）**：
   - 摒弃阻塞跨租户读写的全局大锁，按 `(db_path, tenant_id)` 划分细粒度可重入锁。
   - 所有涉及配额池（`consume_tenant_quota`、`transfer_tenant_quota`、`try_consume_realtime_alert_quota`）与批次风控告警配额联动（`evaluate_transaction_batch`）的操作，严格遵守同一全局加锁偏序：
     $$\text{TenantTxEngine.lock} \longrightarrow \text{TenantQuotaLock(db\_path, tenant\_id)} \longrightarrow \text{SQLite } \mathtt{BEGIN\ IMMEDIATE}$$
   - 严禁在持有 SQLite `BEGIN IMMEDIATE` 写事务后再反向等待任何 Python 线程锁；在 `transfer_tenant_quota` 中，对 `from_quota` 与 `to_quota` 按名称字典序（`first_q, second_q`）依次查询与校验，并在同一 `BEGIN IMMEDIATE` 事务内完成双池余额更新与流水落表，彻底根绝跨层死锁与并发超扣。
2. **失败批次四位一体强原子回滚（`aegis_app/rule_engine.py`）**：
   - `evaluate_transaction_batch` 先在无副作用阶段完成整批字段、严格整数、邮箱格式及批内 `tx_id` 唯一性校验；进入锁与 `BEGIN IMMEDIATE` 后，预检数据库既有 `tx_id` 冲突；若批处理中途发生任何异常，立即执行 `conn.rollback()` 回滚数据库事务（含 `transactions`、`risk_decisions` 与 `REALTIME_ALERT_POOL` 配额扣减），并调用 `tx_engine.build_from_db(db_path)` 从干净数据库状态恢复内存滑动窗口与三跳传染图，实现“数据库 + 滑动窗口 + 传染图 + 告警配额池”四位一体强原子回滚。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
1. **五维独立纪元计数器（`aegis_app/db.py`）**：
   - 通过 `get_domain_epoch(db_path, tenant_id, domain)` 与 `bump_domain_epoch(db_path, tenant_id, domain)` 将租户状态拆分为 5 个正交纪元域：`doc`（文档与引用）、`acl`（利益冲突隔离墙）、`perm`（用户角色与借调委托）、`policy`（风控策略）、`sanction`（制裁黑名单）。
   - 修改单条 `doc-acl` 规则仅递增 `acl` 纪元，绝不触发 `TenantDocIndex` 文档倒排索引重建；更新策略或黑名单仅分别递增 `policy` 或 `sanction` 纪元。
2. **二级借调委托链秒级窗口核验与有向环路免疫（`aegis_app/delegation.py`）**：
   - `_PermStateCache` 缓存租户组织继承原生角色与活跃委托边。在 `resolve_active_delegated_roles` 与 `_collect_upstream_grantors_cached` 中，每次按请求时刻 `at_ts` 实时校验每一跳 `starts_at <= at_ts < expires_at`、每一跳委托人 `active == 1` 以及源头委托人当前是否持有原生角色。
   - 当上游一级委托窗口自然跨过 `expires_at` 时，读取路径零写自动降级；当源头被 `revoke_or_grant_role` 撤权或上游委托被撤销时，`perm` 纪元递增使下游 1~2 跳立即级联失效。
   - 回溯时维护 `visited` 已访问集合并硬限制递归深度 `depth < MAX_DELEGATION_HOPS (2)`，对 `A -> B -> C -> A` 等任意有向委托环路 100% 免疫。

---

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
1. **一阶与双通道二阶 SQL 注入全面根除**：
   - 修复 `search_service.py` 中 `tenant_id`、`tag_filter` 的字符串拼接及 `sort_by` / `sort_dir` 的任意排序列注入（强制白名单 `_ALLOWED_SORT_FIELDS = {"score", "updated_at", "risk_weight"}` 与 `_ALLOWED_SORT_DIRS = {"asc", "desc"}`）；
   - 修复通道一（内部引用二阶 SQL 注入與跨租户侧信道）：在 `doc_indexer.py` 与 `search_service.py:_get_doc_citation_count` 中，对 `doc_` 前缀引用全部采用参数化查询且强制限定 `WHERE tenant_id = ? AND doc_id = ?`（内存索引仅在同租户 `self.docs` 字典内查找），彻底阻断通过 `cited_by_ref` 实施二阶注入或探测外租户文档存活状态的预言机侧信道；
   - 修复通道二（审计报表模板二阶 SQL 注入）：在 `audit_export.py:save_report_template` 与 `render_saved_report` 中对 `extra_event_filter` 实施正则白名单校验 `^[A-Z0-9_]{1,64}$`，并在查询 `audit_logs` 时改用 `?` 参数化绑定。
2. **报表模板沙箱化与防格式化宽度放大（`aegis_app/audit_export.py`）**：
   - 彻底移除 `str.format(..., env=RUNTIME_ENV)` 调用。在 `_validate_and_render_title_format` 中通过正则 `_BRACE_TOKEN_RE` 扫描所有花括号标记，仅允许字面精确匹配 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个占位符，任何属性访问（如 `{env.master_pepper}`）、索引或宽度格式符（如 `{tenant_id:0>200000}`）均在保存与渲染双阶段直接拒绝（返回 `400`），并使用纯字面 `.replace()` 完成渲染。
3. **归档快照多变体目录穿越防护（`aegis_app/audit_export.py`）**：
   - 在 `read_compliance_snapshot` 中拒绝包含 `%`、`/`、`\`、`..` 或空字节的 `snapshot_name`，验证双重 `urllib.parse.unquote` 前后恒等，强制校验文件名白名单 `^[a-zA-Z0-9_-]{1,64}\.json$`，并通过 `pathlib.Path.resolve()`、`target_path.relative_to(base_dir)`、`target_path.parent == base_dir` 与 `not target_path.is_symlink()` 四重物理边界锚定。
4. **多维越权（IDOR）与内部密钥泄密封堵**：
   - `server.py` 移除 `/api/v1/health?debug=1` 诊断输出，直接禁用 `/api/v1/internal/diagnostics`（返回 `403`），并在 `500` 异常响应中彻底移除包含 `db_path`、`storage_dir`、`master_pepper` 与 `traceback` 的 `debug_context`；
   - `search_service.py:batch_get_documents` 强制绑定 `tenant_id`、过滤 `status == 'ACTIVE'` 且 `quarantined == 0`、核验 `clearance_level <= live_clearance` 及 `is_doc_blocked_by_acl` 三级利益冲突墙；
   - `rule_engine.py:get_risk_decision_detail` 强制校验 `WHERE tenant_id = ? AND decision_id = ?`。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
1. **Webhook 常量时间验签、时间窗与并发 Nonce 防重放（`aegis_app/auth.py`）**：
   - 无论租户或用户是否存在，`authenticate_caller` 与 `process_settlement_webhook` 均使用 `_DUMMY_TOKEN_HASH` / `_DUMMY_WEBHOOK_SECRET` 执行 `hmac.compare_digest` 常量时间比对；
   - 严格校验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS (300)`；
   - 通过 `idx_webhook_tenant_nonce` 唯一索引 + `BEGIN IMMEDIATE` 事务原子拦截串行与高并发重复 Nonce 重放。
2. **消除 ReDoS 回溯正则与多维载荷硬预算熔断（`aegis_app/middleware.py`、`aegis_app/rule_engine.py`、`aegis_app/config.py`）**：
   - `validate_contact_email` 替换为无正则回溯的 $O(N)$ 确定性字符分段校验器；
   - `_validate_safe_regex_pattern` 对自定义规则树中的 `REGEX` 模式执行静态语法扫描，拦截嵌套量词（如 `(a+)+`）、分支重叠量词（如 `(a|aa)+`）、反向引用（`\1`）及超过 64 的花括号量词上界（如 `a{1,50000}`）；
   - `middleware.py:_check_json_raw_nesting_depth` 在调用 `json.loads` **之前**对原始 JSON 字符串做单遍词法括号深度预检（超过 `MAX_JSON_NESTING_DEPTH = 24` 或体积超过 512KB 立即熔断）；
   - `_validate_rule_tree_budget` 限制规则树节点数 `<= 64`、深度 `<= 12`；`upsert_compliance_document` 限制单篇引用数 `<= 64`；`search_documents` 限制唯一查询词 `<= 16`。
3. **严格整数与特殊数值类型守卫（`aegis_app/config.py:parse_strict_int`）**：
   - 全局所有金额、配额、时间戳、密级、权重与分页参数均通过 `parse_strict_int` 解析，显式拦截 `isinstance(val, bool)`（防止 Python 中 `True == 1` 类型混淆）、浮点数、`NaN`/`Inf` 以及超出 `[-((1<<62)-1), (1<<62)-1]` 的超大整数（防止 SQLite `OverflowError` 导致 500 崩溃）。

---

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/doc_indexer.py` 中实现了使用 `__slots__` 且不保留原始全文 `body` 的 `CompactDocNode` 与 `TenantDocIndex`（含 `apply_upsert` / `apply_status_change` 单篇增量倒排更新与 `reverse_dependents` $O(\text{deg})$ 反向引用计数传播），在 `compute_phrase_proximity_bonus_from_positions` 中实现了双指针线性扫描与 `min_dist == 1` 早停；在 `aegis_app/search_service.py:search_documents` 中实现了 `min_l / max_l < DEDUP_JACCARD_THRESHOLD` 集合大小比值剪枝；在 `aegis_app/window_stats.py:AccountWindowTracker` 与 `aegis_app/contagion_graph.py:TenantTxEngine` 中实现了 $O(\log W)$ 滑窗中位数维护、2 层有界邻域制裁传染搜索及乱序时间戳二分回退；在 `aegis_app/audit_export.py:_stream_digest_from_cursor` 中实现了不加载 `payload_json` 的 $O(1)$ 内存游标流式摘要。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/db.py` 中通过 `get_domain_epoch` 与 `bump_domain_epoch` 实现了 `doc`、`acl`、`perm`、`policy`、`sanction` 五维独立纪元解耦；在 `aegis_app/acl_wall.py:_AclWallCache` 与 `get_blocked_doc_ids_for_user` 中实现了隔离墙独立缓存（更新 ACL 绝不清空文档倒排索引）；在 `aegis_app/delegation.py:_PermStateCache`、`_collect_upstream_grantors_cached` 与 `resolve_active_delegated_roles` 中实现了最多 2 跳借调链的秒级窗口实时核验、上游过期零写自动降级、源头撤权级联失效及 `visited` 有向环路免疫。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/db.py:get_tenant_quota_lock`、`aegis_app/ledger_ops.py`（`consume_tenant_quota`、`transfer_tenant_quota`、`try_consume_realtime_alert_quota`）与 `aegis_app/rule_engine.py:evaluate_transaction_batch` 中严格执行 `tx_engine.lock -> tenant_quota_lock -> BEGIN IMMEDIATE` 全局统一锁偏序（且 `transfer_tenant_quota` 内按配额名升序访问）；在 `evaluate_transaction_batch` 异常处理块中通过 `conn.rollback()` 与 `tx_engine.build_from_db(db_path)` 实现了数据库、滑动窗口、三跳传染图与 `REALTIME_ALERT_POOL` 配额池的四位一体强原子回滚。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/audit_export.py` 的 `_validate_and_render_title_format`、`save_report_template` 与 `render_saved_report` 中强制校验 `_EVENT_FILTER_RE` 参数化查询与 3 个字面占位符白名单（彻底移除 `str.format`）；在 `aegis_app/doc_indexer.py:TenantDocIndex` 与 `aegis_app/search_service.py:_get_doc_citation_count` 中将内部 `doc_` 引用严格锚定于本租户活跃未隔离文档；在 `aegis_app/audit_export.py:read_compliance_snapshot` 中实施文件名白名单与 `target_path.relative_to(base_dir)` 路径锚定；在 `aegis_app/search_service.py:batch_get_documents` 与 `aegis_app/rule_engine.py:get_risk_decision_detail` 中补齐了租户、状态、隔离、密级与利益冲突墙校验。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/rule_engine.py` 中用确定性线性解析函数 `validate_contact_email` 替换了回溯正则，并在 `_validate_safe_regex_pattern` 與 `_validate_rule_tree_budget` 中拦截嵌套/分支量词、反向引用、花括号大上界（`> 64`）及超限规则树；在 `aegis_app/middleware.py:_check_json_raw_nesting_depth` 中实现了 `json.loads` 前的原始字符串嵌套深度预检；在 `aegis_app/config.py:parse_strict_int` 中统一拦截了 `bool`、`float`/`NaN` 与超 64 位整数。

---

## 5. 已知工程取舍与残余边界说明
1. **单进程内存索引与多进程扩展取舍**：当前 `TenantDocIndex`、`TenantTxEngine` 与五维纪元计数器驻留在网关单进程内存中，针对单机多线程并发与 SQLite 本地存储达到极致吞吐；若未来扩展至多进程/多机无共享集群，需将纪元版本号下沉至共享内存或数据库元数据表。
2. **批次异常回滚的恢复策略**：在 `evaluate_transaction_batch` 中，由于预先完成了整批输入格式、类型与主键冲突校验，执行期触发数据库异常的概率极低；一旦触发异常，采用 `conn.rollback()` 配合 `tx_engine.build_from_db(db_path)` 重建租户滑窗与传染图，以简洁可靠的逻辑保证 100% 零内存脏状态残留。
