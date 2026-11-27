# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
- **缺失复合与唯一索引**：原 `aegis_app/db.py` 仅含主键，所有租户隔离查询与时间窗扫描均触发全表扫描。我们在 `SCHEMA_SQL` 中补全了 `idx_org_nodes_tenant_node`、`idx_users_tenant_user`、`idx_role_grants_tenant_user_active`、`idx_delegations_grantee`、`idx_delegations_grantor`、`idx_doc_acl_tenant_doc_active`、`idx_sanctions_tenant_active`、`idx_docs_tenant_status_q`、`idx_doc_citations_tenant_doc`、`idx_doc_citations_tenant_ref`、`idx_tx_tenant_acct_ts`、`idx_tx_tenant_ts`、`idx_risk_dec_tenant_id`、`idx_audit_tenant_*` 及防重放唯一索引 `idx_webhook_tenant_nonce ON webhook_events(tenant_id, nonce)`。
- **高频连接开闭与写锁竞争**：在 `aegis_app/db.py` 开启 `WAL`、`synchronous=NORMAL`、`busy_timeout=30000`、`temp_store=MEMORY` 与 `cache_size=-16384`，并在 `aegis_app/state.py` 实现有界线程安全连接池 `ConnectionPool`（上限 16 连接，归还前自动回滚未提交事务），消除请求内循环反复 `connect`/`close` 开销。
- **循环内 N+1 查询治理**：将 `search_documents` 内逐篇调用的权限解析、隔离墙逐跳查询、`doc_` 引用核验，以及 `evaluate_transaction_batch` 内逐笔全表拉取 `transactions`（及无效 `json.loads(metadata_json)`）全部消除。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
- **紧凑增量倒排与双向引用传播（`aegis_app/doc_store.py`）**：
  - 使用 `__slots__` 定义 `CompactDocEntry`，通过 `TokenInterner` 将词元驻留为整数 ID，正文词序以紧凑 `array('I')` 存储，仅保留 `body[:140]` 的 `snippet`，彻底不把大体积原始全文 `body` 常驻内存。
  - `upsert_compliance_document`、`retire_compliance_document`、`set_document_quarantine` 仅对单篇文档增量更新 `TenantDocIndex.inverted_index`，并通过反向依赖图 `reverse_dependents` 在 $O(\text{deg})$ 内精确联动更新被引用文档的 `valid_citation_count`（时间复杂度由每次全表重建 $O(N \cdot L)$ 降至单篇 $O(L + \text{deg})$）。
- **双指针词距与集合剪枝去重（`aegis_app/doc_indexer.py`、`aegis_app/search_service.py`）**：
  - `compute_phrase_proximity_bonus` 与 `compute_phrase_proximity_bonus_from_seq` 采用单遍位置收集 + 有序下标双指针扫描 `_min_two_pointer_dist`，遇距离 `1` 立即早停（由 $O(|body|^2)$ 降至 $O(|pos_a| + |pos_b|)$）。
  - 近似修订簇折叠先按归一化法规编号 `canon_reg` 过滤，再通过 `jaccard_similarity_from_sets` 执行集合大小比值剪枝（`min_l / max_l < 0.70` 直接跳过），将复杂度由 $O(M^2 \cdot L^2)$ 降至均摊 $O(M \cdot \min(|A|, |B|))$。
- **双堆滑窗精确中位数（`aegis_app/window_stats.py`）**：
  - `compute_exact_median_cents` 改用 Timsort（$O(W \log W)$）；`AccountWindowTracker` 在单调时间戳流下采用 `_TwoHeapMedian`（大小堆 + 懒惰删除计数）实现 $O(\log W)$ 维护与 $O(1)$ 中位数查询，遇乱序时间戳则通过 `bisect` 切片精确回退，保证与原版 100% 数值一致。
- **三跳传染 2 层邻域 BFS（`aegis_app/contagion_graph.py`）**：
  - `compute_hop_from_graph` 从交易两端 `{account_id, counterparty_id}` 出发执行单次最多 2 层 `deque` 邻域 BFS（时间窗边按 `bisect_left` 判定），替代从全部受制裁实体出发的多源全图 `pop(0)` BFS。
- **流式游标审计导出（`aegis_app/audit_export.py`）**：
  - `_stream_digest_from_cursor` 不查询 `payload_json`，去除 `json.loads` 与两次 `copy.deepcopy`，以 `fetchmany(512)` 恒定 $O(1)$ 内存流式计算 `rolling_sha256` 与分桶统计。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
- **租户级细粒度锁与全局严格偏序（`aegis_app/state.py`、`aegis_app/ledger_ops.py`、`aegis_app/rule_engine.py`）**：
  - 每个租户拥有独立的 `risk_lock`、`quota_lock`、`doc_lock`、`perm_lock`、`acl_lock`、`policy_lock`、`sanction_lock`，不同租户完全并行互不阻塞。
  - 跨模块共享资源严格遵守单一偏序：`risk_lock -> quota_lock -> SQLite BEGIN IMMEDIATE`（绝不在持有 `BEGIN IMMEDIATE` 后再去请求 Python 锁），彻底消除 `transfer_tenant_quota`、`consume_tenant_quota` 与 `evaluate_transaction_batch` 扣减 `REALTIME_ALERT_POOL` 时的交叉死锁与丢失更新。
- **四重强原子提交/回滚（`aegis_app/rule_engine.py`）**：
  - `evaluate_transaction_batch` 先对整批交易完成严格字段与类型预校验，随后在 `risk_lock -> quota_lock -> BEGIN IMMEDIATE` 内执行交易入库、`risk_decisions` 入库、`try_consume_realtime_alert_quota_in_tx` 条件扣减以及内存滑窗/传染图增量更新（记录 `undo_win` 与 `undo_edges`）；任一笔异常时同步回滚 SQLite 事务（含告警配额）并撤销内存增量状态。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
- **五维独立纪元（`aegis_app/state.py`）**：将 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch` 彻底解耦。修改单条 `doc-acl` 规则仅递增 `acl_epoch` 并刷新 `acl_cache`，完全不清空 `TenantDocIndex` 倒排索引。
- **二级受控借调链时效核验与防环路（`aegis_app/delegation.py`）**：`TenantPermCache` 按 `perm_epoch` 缓存租户原生角色、组织树与活跃借调表，`resolve_active_delegated_roles_from_cache` 在每次请求时刻 `at_ts` 实时核验 1~2 跳链路上每一段的 `starts_at <= at_ts < expires_at`、中间/源头节点 `active == 1` 与源头原生角色持有状态（上游自然到期即刻零写降级，撤权递增 `perm_epoch` 即刻级联失效），并通过 `visited` 集合与 `_would_create_cycle` 彻底免疫有向环路。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
- **消除全部一阶与二阶 SQL 注入**：`search_documents` 中的 `tag_filter`/`tenant_id` 参数化、`sort_by`/`sort_dir` 白名单校验；`doc_store.py` 与 `doc_writer.py` 对 `doc_` 引用严格限定本租户且参数化；`audit_export.py` 的 `save_report_template` 与 `render_saved_report` 对 `extra_event_filter` 执行 `EVENT_FILTER_RE` 校验并在 SQL 中使用 `?` 参数化。
- **字面报表模板沙箱**：`aegis_app/validation.py` 的 `validate_literal_template` 与 `render_literal_template` 彻底移除 `str.format` 与 `RUNTIME_ENV`，仅允许 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个字面占位符并直接字面替换，阻断属性反射泄密与 `:0>200000` 宽度放大。
- **路径穿越与信息泄露治理**：`read_compliance_snapshot` 多轮 URL 解码后拦截 `\x00`、`/`、`\`、`..` 及符号链接，并以 `Path.resolve().is_relative_to(base_dir)` 强制锚定租户 `snapshots/` 目录；移除 `/api/v1/health?debug=1` 诊断输出与 500 `debug_context`，`/api/v1/internal/diagnostics` 强制管理员鉴权且不返回密钥与物理路径。
- **跨租户与权限边界补全**：`batch_get_documents` 补全租户过滤、活跃/未隔离校验、实时密级与隔离墙裁决；`get_risk_decision_detail` 强制 `AND tenant_id = ?`；`authenticate_caller` 对未知租户/用户执行 `_DUMMY_TOKEN_HASH` 常量时间 `hmac.compare_digest` 掩蔽。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
- **Webhook 验签与并发防重放（`aegis_app/auth.py`）**：补全 `±300s` 时间窗校验与 `hmac.compare_digest` 常量时间比对，依托 `idx_webhook_tenant_nonce` 唯一索引在 `BEGIN IMMEDIATE` 中原子拦截串行/并发重复 Nonce（返回 409）。
- **抗复杂度炸弹与严格类型守卫（`aegis_app/validation.py`、`aegis_app/rule_engine.py`、`aegis_app/middleware.py`）**：
  - `check_json_depth_and_size` 在 `json.loads` 前以 $O(N)$ 线性预检字节上限与嵌套深度（`<= 64`）；
  - `PARTNER_EMAIL_PATTERN` 消除嵌套量词，`compile_safe_regex` 拦截长度超限、反向引用、环视、大上界 `{m,n}`（`> 100`）与嵌套量词回溯正则；
  - `eval_rule_node` 限制规则树深度（`<= 16`）、总节点数（`<= 128`）与子节点数；`upsert_compliance_document` 限制单次引用数（`<= 200`）；
  - `parse_strict_int` 与 `parse_strict_number` 统一拒绝 `bool`、`NaN`/`Inf`、非整数浮点及超出 64 位有符号整数范围的数值。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/doc_store.py`（`CompactDocEntry`、`TenantDocIndex`）中以 `__slots__`、词元整数驻留及 `array('I')` 紧凑存储实现单篇增量倒排与基于 `reverse_dependents` 的 $O(\text{deg})$ 双向引用传播；在 `aegis_app/doc_indexer.py`（`compute_phrase_proximity_bonus_from_seq`、`jaccard_similarity_from_sets`）实现双指针早停词距与集合大小比值剪枝去重；在 `aegis_app/window_stats.py`（`AccountWindowTracker`、`_TwoHeapMedian`）实现 $O(\log W)$ 滑窗中位数及乱序精确回退；在 `aegis_app/contagion_graph.py`（`compute_hop_from_graph`）实现 2 层邻域 BFS；在 `aegis_app/audit_export.py`（`_stream_digest_from_cursor`）实现 `fetchmany(512)` 恒定内存流式摘要。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/state.py`（`TenantState`）解耦 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch`；`aegis_app/acl_wall.py`（`upsert_doc_acl_rule`、`_get_acl_cache`）仅递增 `acl_epoch` 而不重建文档索引；`aegis_app/delegation.py`（`TenantPermCache`、`_collect_upstream_grantors_mem`、`_would_create_cycle`）在 `at_ts` 实时核验 1~2 跳借调窗口、源头撤权级联失效并阻断有向环路。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/state.py`、`aegis_app/ledger_ops.py`（`transfer_tenant_quota`、`consume_tenant_quota`、`try_consume_realtime_alert_quota_in_tx`、`redeem_override_token`）与 `aegis_app/rule_engine.py`（`evaluate_transaction_batch`）中强制按 `risk_lock -> quota_lock -> SQLite BEGIN IMMEDIATE` 单一偏序加锁，并在异常时同步回滚 SQLite 交易/决策、`REALTIME_ALERT_POOL` 配额及内存滑窗/传染图状态。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/validation.py`（`validate_literal_template`、`render_literal_template`）与 `aegis_app/audit_export.py`（`save_report_template`、`render_saved_report`、`read_compliance_snapshot`）中实现字面占位符白名单渲染、二阶 SQL 参数化及 `is_relative_to` 路径锚定；在 `aegis_app/search_service.py`（`batch_get_documents`）、`aegis_app/rule_engine.py`（`get_risk_decision_detail`）与 `aegis_app/auth.py`（`authenticate_caller`、`process_settlement_webhook`）中补全租户/密级/ACL 隔离、常量时间掩蔽及唯一索引防重放。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/validation.py`（`check_json_depth_and_size`、`compile_safe_regex`、`parse_strict_int`、`parse_strict_number`）、`aegis_app/middleware.py`（`parse_json_payload`）、`aegis_app/rule_engine.py`（`PARTNER_EMAIL_PATTERN`、`eval_rule_node`）与 `aegis_app/doc_writer.py`（`MAX_CITATIONS_PER_UPSERT`）中落地 JSON 深度预检、无回溯/环视/大上界正则校验、规则树与引用预算上限及严格 64 位整数/有限数守卫。

## 5. 已知工程取舍与残余边界说明
- 单机进程内为每个活跃 `db_path` 维护 `GatewayState` 内存增量索引与滑窗/图状态（进程重启后首次访问按租户懒加载重建），并在单租户写操作时依赖 SQLite `WAL` + `BEGIN IMMEDIATE` 串行提交；若外部进程绕过网关直接修改同一 SQLite 文件，进程内缓存不会自动感知。
