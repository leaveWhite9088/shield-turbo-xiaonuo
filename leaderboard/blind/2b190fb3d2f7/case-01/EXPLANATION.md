# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
- **原始瓶颈**：原系统在每次查询甚至循环内部反复调用 `sqlite3.connect`（如 `acl_wall.py` 沿组织树逐级重连、`search_service.py` 逐文档查权限/隔离墙/引用、`rule_engine.py` 逐笔全表扫描 `transactions` 并逐笔提交），且 17 张核心业务表完全缺乏复合索引，在并发读写下频繁发生表锁竞争与全表扫描。
- **重构方案**：
  - 在 `aegis_app/db.py` 的 `SCHEMA_SQL` 中新增 19 个针对高频查询路径的复合索引与唯一索引（包括 `idx_docs_tenant_status_q`、`idx_doc_citations_tenant_doc`、`idx_tx_tenant_acct_ts`、`idx_tx_tenant_ts`、`idx_audit_logs_tenant_ts_id` 以及 `idx_webhook_events_tenant_nonce` 唯一索引）。
  - 在 `aegis_app/db.py` 与 `aegis_app/runtime_state.py` 中启用 SQLite `WAL` 模式、`synchronous=NORMAL`、`temp_store=MEMORY`、`cache_size=-16384`、`mmap_size=0` 与 `busy_timeout=30000`，实现按 `db_path` 隔离的有界连接池 `borrow_connection`（上限 16 连接，全局运行时表 LRU 上限 16）与统一写事务原语 `write_transaction`（`BEGIN IMMEDIATE`）。
  - 将 `auth.py` 认证收敛为单条 `tenants LEFT JOIN users` 池化查询，并将批次风控落盘由逐笔提交重构为单次 `BEGIN IMMEDIATE` 内的 `executemany` 批量写入。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
- **紧凑增量倒排与双向引用传播（`aegis_app/search_service.py`、`aegis_app/doc_writer.py`）**：
  - 使用 `__slots__` 定义紧凑索引节点 `_DocIndexNode`，**不常驻原始正文 `body`**（仅保留 140 字符 `snippet`），并通过 `sys.intern` 驻留高频词项与枚举字段，将常驻堆内存大幅压缩；正文词频直接复用 `len(body_pos[tok])`，避免重复存储 `body_tf` 字典。
  - `TenantDocIndex` 维护 `inverted` 倒排表、`active_valid_docs` 集合与 `reverse_dependents` 反向引用图。单篇 `docs/upsert`、`docs/retire`、`docs/quarantine` 仅执行 $O(|\text{tokens}| + \deg)$ 局部增量更新，并通过 `_propagate_validity_change` 以 $O(\deg)$ 即时联动更新所有引用方的 `citation_count`（彻底消除整库重建与全表扫描）。
- **双指针词距邻近度（`aegis_app/doc_indexer.py`）**：
  - `compute_phrase_proximity_from_positions` 利用预建升序位置元组 `body_pos` 执行 $O(|P_a| + |P_b|)$ 双指针扫描，并在命中 `min_dist == 1` 时立即早停（原版为 $O(L + |P_a| \cdot |P_b|)$ 嵌套扫描）。
- **双轨法规近似去重降维（`aegis_app/search_service.py`、`aegis_app/doc_indexer.py`）**：
  - 按 `canonicalize_regulation_code` 归一化后的 `canon_reg` 分桶聚类，仅在同法规号桶内比对；`jaccard_similarity_sets` 引入 $O(1)$ 集合大小比值上界剪枝（`min_l / max_l < 0.70` 直接跳过），将最坏 $O(N^2 \cdot |V|)$ 降至桶内剪枝比对，同时 100% 保持原版贪心簇代表顺序与 `cluster_size` 计数。
- **滑动窗口精确动态中位数（`aegis_app/window_stats.py`、`aegis_app/rule_engine.py`）**：
  - 将 `compute_exact_median_cents` 由 $O(W^2)$ 冒泡排序替换为 $O(W \log W)$ Timsort，并在 `AccountSlidingWindow` 中实现基于大顶堆 + 小顶堆 + 惰性删除的 `DualHeapMedian`，使单调时间戳路径的窗口更新与中位数读取降至 $O(\log W)$ / $O(1)$；针对乱序时间戳（`ts < max_ts`），提供基于 `idx_tx_tenant_acct_ts` 索引与批次暂存记录的精确回退 `_compute_window_out_of_order`，保证结果分毫不差。
- **三跳制裁传染追踪（`aegis_app/contagion_graph.py`）**：
  - `TenantContagionGraph` 维护 24 小时增量无向邻接表（单调窗口 $O(1)$ 均摊淘汰），并将原版“从所有受制裁实体执行 `pop(0)` BFS”的 $O(|S| \cdot (V + E))$ 复杂度重构为从 `{account_id, counterparty_id}` 出发的反向深度 2 BFS（`_reverse_bfs_2hop`），保留 `LEGACY_SOVEREIGN_EXEMPT` 与所有打分规则 100% 零失真。
- **流式审计摘要导出（`aegis_app/audit_export.py`）**：
  - `_compute_digest_streaming` 仅查询所需 6 列（不读取大体积 `payload_json`，彻底移除双份 `copy.deepcopy`），以 `cursor.fetchmany(512)` 流式滚动计算 `rolling_sha256` 与统计分布，峰值内存由 $O(N)$ 降至 $O(1)$。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
- **无全局大锁的租户级并发架构**：在 `aegis_app/runtime_state.py` 的 `TenantState` 中按租户隔离各域细粒度锁（`risk_lock`、`quota_locks`、`doc_lock`、`acl_lock`、`perm_lock`、`meta_lock`），不同租户读写互不阻塞；SQLite WAL 模式允许并发读请求无阻塞穿透。
- **严格三级全局锁偏序（消除跨层 AB-BA 死锁）**：
  - **Level 1**：`TenantState.risk_lock`（仅 `evaluate_transaction_batch` 获取）；
  - **Level 2**：`TenantState.acquire_quota_locks(*buckets)` 按配额池名称**字典序**获取细粒度桶锁（`consume_tenant_quota` 获取单桶锁，`transfer_tenant_quota` 按字典序获取双桶锁，`evaluate_transaction_batch` 在进入数据库事务前获取 `REALTIME_ALERT_POOL` 锁）；
  - **Level 3**：SQLite `BEGIN IMMEDIATE` 写事务（`write_transaction`），永远在所有必需 Python 锁获取完毕后才开启。
  - 该严格偏序从数学上杜绝了双向跨池调拨死锁及 `transfer` 与 `evaluate-batch` 之间的跨层锁死锁。
- **四位一体强原子提交/回滚（`aegis_app/rule_engine.py`）**：
  - `evaluate_transaction_batch` 先无锁预检整批交易字段与批内重复 `tx_id`；随后在 `L1 -> L2 -> L3` 单一 `BEGIN IMMEDIATE` 事务内逐笔评估并暂存 `REALTIME_ALERT_POOL` 扣减量，批尾一次性 `executemany` 落盘并扣减告警配额。若任一环节异常（如主键冲突），SQLite 自动回滚交易、决策与配额，且 `except` 块调用 `tstate.invalidate_risk_state()` 清空内存滑窗与传染图，实现“数据库 + 滑窗 + 三跳传染图 + 告警配额池”四位一体强原子回滚。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
- **五维独立纪元解耦**：`TenantState` 分别维护 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch`。修改 `admin/doc-acl` 仅递增 `acl_epoch` 并刷新轻量 `AclSnapshot`，**绝不触发 `TenantDocIndex` 文档倒排索引重建**；更新黑名单或风控策略仅刷新对应缓存。
- **2 跳受控借调链与零写自然过期（`aegis_app/delegation.py`）**：
  - `PermSnapshot`（绑定 `perm_epoch`）缓存租户原生角色及所有 `active=1` 借调边的 `(grantor, role, starts_at, expires_at)`。
  - `resolve_active_delegated_roles` 在内存中按请求 `at_ts` 实时执行深度上限 `MAX_DELEGATION_HOPS=2`、带 `visited` 集合环路免疫的 BFS 回溯：每段边均须满足 `starts_at <= at_ts < expires_at` 且源头持有原生角色，实现上游一级窗口自然到期零写降级与源头撤权即时级联失效。
  - `create_or_revoke_delegation` 通过 `_has_directed_path` 在建边时即拒绝有向闭环。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
- **一阶与双通道二阶 SQL 注入修复**：
  - `search_service.py` 彻底消除动态拼接 `tenant_id` / `custom_tag` / `ORDER BY`，改由内存倒排检索并对 `sort_by` / `sort_dir` 实施严格白名单校验；
  - 通道一（引用二阶注入 + 跨租户侧信道）：`search_service.py` 中 `_get_doc_citation_count` 全参数化并追加 `tenant_id = ?`，且内存 `TenantDocIndex.active_valid_docs` 严格按租户隔离，彻底阻断二阶 SQLi 与跨租户 `doc_` 状态探测预言机；
  - 通道二（报表模板二阶注入）：`audit_export.py` 在 `save_report_template` 与 `render_saved_report` 对 `extra_event_filter` 执行 `^[A-Z0-9_]{1,64}$` 校验并全参数化查询 `event_type = ?`。
- **报表模板防反射与宽度放大阻断（`aegis_app/audit_export.py`）**：
  - 彻底移除 `str.format(..., env=RUNTIME_ENV)`，通过 `_validate_title_format` 仅放行字面占位符 `{tenant_id}`、`{total_records}`、`{total_amount_cents}`（拦截 `{env.master_pepper}`、`{tenant_id.__class__}` 及 `{tenant_id:0>200000}` 等格式说明符放大），并由 `_render_title_safely` 使用纯字面 `.replace` 渲染。
- **多变体路径穿越阻断（`aegis_app/audit_export.py`）**：
  - `read_compliance_snapshot` 对原始及双重解码路径统一拦截 `\x00`、`/`、`\`、`..`、`:`、`%` 并执行安全文件名正则校验，拒绝符号链接，并使用 `Path.resolve()` 锚定 `target_path.parent == base_dir` 且 `is_relative_to(base_dir)`。
- **多维越权与敏感信息泄密封堵**：
  - `server.py` 移除 `/api/v1/health?debug=1` 诊断输出与 `/api/v1/internal/diagnostics` 路由，500 响应剥离所有路径、主密钥与堆栈；
  - `rule_engine.py` 的 `get_risk_decision_detail` 强制增加 `tenant_id = ?` 隔离；
  - `search_service.py` 的 `batch_get_documents` 补齐租户、`ACTIVE`、`quarantined = 0`、实时密级与三级利益冲突墙全维度校验；
  - `auth.py` 认证与 Webhook 验签全部改用 `hmac.compare_digest` 并对未知租户/用户执行 dummy 哈希/HMAC 常量时间掩蔽。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
- **Webhook 防重放与时间窗（`aegis_app/auth.py`、`aegis_app/db.py`）**：强制校验 `abs(now_ts - callback_ts) <= 300`，并依靠 `UNIQUE(tenant_id, nonce)` 索引在 `BEGIN IMMEDIATE` 事务内原子拦截串行与高并发 Nonce 重放（返回 409）。
- **单次令牌与配额原子防超扣（`aegis_app/ledger_ops.py`）**：`redeem_override_token` 采用 `UPDATE ... WHERE used = 0`，`consume_tenant_quota` 采用 `UPDATE ... WHERE remaining_quota >= ?`，在并发冲击下严格防重与防负。
- **多变体复杂度炸弹毫秒级熔断**：
  - 消除 `rule_engine.py` 中 `PARTNER_EMAIL_PATTERN` 嵌套量词 ReDoS，改用线性时间无回溯正则并限制长度 `<= 254`；
  - `runtime_state.py` 的 `validate_safe_regex` 静态拦截嵌套量词、大花括号上界（`> 50`）、反向引用与环视；`rule_engine.py` 限制规则树深度 `<= 16`、节点总数 `<= 128`；
  - `middleware.py` 在 `json.loads` 之前调用 `check_raw_json_depth` 线性预检嵌套深度（`<= 32`）与载荷体积（`<= 2MB`），并通过 `parse_constant` 拒绝 `NaN`/`Infinity`；
  - `doc_writer.py` 限制单次 `upsert` 引用数 `<= 100`，`search_service.py` 限制查询词项 `<= 64` 与批量读取 `<= 200`。
- **严格数值与类型守卫（`aegis_app/runtime_state.py`）**：全链路采用 `parse_strict_int` 与 `parse_strict_number`，拒绝 `bool` 混入整数、拒绝超 64 位整数溢出及 `NaN`/`Inf` 比较。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/search_service.py` 中通过 `__slots__` 定义紧凑节点 `_DocIndexNode`（不保留原始 `body`，仅存 140 字符 `snippet` 与 `sys.intern` 词项）和 `TenantDocIndex`，在 `apply_upsert` / `apply_retire` / `apply_quarantine` 中实现单篇增量倒排维护及基于 `reverse_dependents` 的 $O(\deg)$ 双向引用传播；在 `aegis_app/doc_indexer.py` 中通过 `compute_phrase_proximity_from_positions` 实现 `min_dist == 1` 早停双指针词距扫描，通过 `jaccard_similarity_sets` 实现 `min_l / max_l < 0.70` 集合尺寸比剪枝；在 `aegis_app/window_stats.py` 中通过 `DualHeapMedian` 与 `AccountSlidingWindow` 实现 $O(\log W)$ 滑窗中位数；在 `aegis_app/contagion_graph.py` 中通过 `TenantContagionGraph` 与 `_reverse_bfs_2hop` 实现反向 2 跳制裁传染追踪；在 `aegis_app/audit_export.py` 中通过 `_compute_digest_streaming` 实现 `fetchmany(512)` 流式 $O(1)$ 内存导出。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/runtime_state.py` 的 `TenantState` 中解耦维护 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch` 五维独立纪元；`aegis_app/acl_wall.py` 的 `upsert_doc_acl_rule` 仅递增 `acl_epoch` 并刷新 `AclSnapshot`，不触碰 `TenantDocIndex`；`aegis_app/delegation.py` 的 `resolve_active_delegated_roles` 基于 `PermSnapshot` 在内存中执行带 `visited` 环路免疫与 `MAX_DELEGATION_HOPS=2` 边界的 BFS，按 `at_ts` 实时校验每段 `[starts_at, expires_at)` 实现上游自然到期零写降级与源头撤权级联失效，并在 `create_or_revoke_delegation` 中通过 `_has_directed_path` 阻断闭环创建。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/runtime_state.py`（`TenantState.risk_lock` 与按字典序加锁的 `acquire_quota_locks`）、`aegis_app/ledger_ops.py`（`consume_tenant_quota`、`transfer_tenant_quota`）和 `aegis_app/rule_engine.py`（`evaluate_transaction_batch`）中统一遵循 `Level 1 (risk_lock) -> Level 2 (字典序 quota_locks) -> Level 3 (write_transaction BEGIN IMMEDIATE)` 全局锁偏序消除跨层与双向调拨死锁；`evaluate_transaction_batch` 在单一 `BEGIN IMMEDIATE` 事务内原子提交交易、决策与 `REALTIME_ALERT_POOL` 扣减，异常时由 `write_transaction` 回滚数据库并调用 `tstate.invalidate_risk_state()` 清空内存滑窗与传染图实现四重强原子回滚。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/search_service.py`（`_get_doc_citation_count` 与租户隔离的 `TenantDocIndex.active_valid_docs`）与 `aegis_app/audit_export.py`（`save_report_template` / `render_saved_report` 对 `extra_event_filter` 标识符校验与参数化查询）中阻断双通道二阶 SQL 注入与跨租户引用侧信道；`aegis_app/audit_export.py` 通过 `_validate_title_format` 与 `_render_title_safely` 纯字面替换彻底移除 `str.format` 反射与宽度放大，并通过 `read_compliance_snapshot` 路径锚定与符号链接拦截封堵目录穿越；`aegis_app/search_service.py`（`batch_get_documents`）、`aegis_app/rule_engine.py`（`get_risk_decision_detail`）、`aegis_app/auth.py`（`hmac.compare_digest` 与 dummy 掩蔽 + `idx_webhook_events_tenant_nonce` 唯一防重放）与 `aegis_app/server.py`（移除内部诊断与 500 堆栈泄密）形成完整纵深隔离边界。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/rule_engine.py` 中用线性无回溯正则重构 `PARTNER_EMAIL_PATTERN` 并在 `validate_rule_tree` / `_eval_rule_node_bounded` 中实施深度（16）、节点数（128）限制与 `aegis_app/runtime_state.py` 的 `validate_safe_regex` 静态正则审计（拦截嵌套量词、大花括号上界 `> 50`、反向引用与环视）；在 `aegis_app/middleware.py` 的 `parse_json_payload` 中调用 `check_raw_json_depth` 在 `json.loads` 前预检嵌套深度（32）与体积（2MB）并禁用 `NaN`/`Infinity`；在 `aegis_app/doc_writer.py` 限制单次引用数（100）；全链路通过 `parse_strict_int` 与 `parse_strict_number` 拒绝 `bool` 混淆、64 位整数溢出及非有限浮点数。

## 5. 已知工程取舍与残余边界说明
1. **单机进程内存缓存边界**：本实现面向单进程多线程嵌入式网关部署，`TenantDocIndex`、`AclSnapshot`、`PermSnapshot` 与滑窗/传染图缓存在当前进程内强一致；若外部进程绕过网关直接修改同一 SQLite 文件，需重启网关或触发运行时重置。
2. **SQLite 写事务串行特性**：SQLite 在 WAL 模式下支持高并发无阻塞读，但跨租户物理写提交在底层仍受单库文件写锁串行化约束；通过合并批次写入为单次 `BEGIN IMMEDIATE` 与纯内存读路径已将写锁持有时间压至极低。
3. **极端乱序风控批次回退**：当交易时间戳严格逆序（`ts < max_ts`）时，滑窗与传染图会回退至基于复合索引的精确查询以保证 100% 语义等价，其单笔延迟略高于单调递增快路径，但仍保持毫秒级可控。
