# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
原版系统在存储与 I/O 层存在五类显著瓶颈：
1. **频繁短连接与隐式锁升级**：几乎每次子查询（包括 `get_org_lineage`、`is_doc_blocked_by_wall`、`_collect_upstream_grantors`、`_get_doc_citation_count` 与批次逐笔写入）都反复调用 `sqlite3.connect` 并新建/销毁连接，且默认回滚日志与隐式事务在高并发下极易触发 `SQLITE_BUSY` 与写锁升级冲突。我们在新增的 `aegis_app/runtime.py` 中实现了按规范化 `db_path` 隔离的**有界连接池 `BoundedConnectionPool`**（上限 `MAX_POOL_CONNECTIONS = 32`，避免连接泄漏），统一启用 `PRAGMA journal_mode = WAL`、`PRAGMA synchronous = NORMAL`、`PRAGMA temp_store = MEMORY`、`PRAGMA cache_size = -16384` 与 `isolation_level = None`，通过 `read_conn()` 与显式 `BEGIN IMMEDIATE` 的 `write_tx()`（含偶发 BUSY 指数退避重试与异常自动 `ROLLBACK`）管理读写事务；同时 `GatewayRuntime` 由上限 `MAX_RUNTIMES = 16` 的有界注册表维护。
2. **复合索引全面缺失**：在 `aegis_app/db.py` 的 `INDEXES_SQL` 中幂等补充了覆盖全部高频过滤、联查与范围扫描路径的 20 条复合索引（包括 `compliance_docs(tenant_id, status, quarantined, clearance_level, updated_at)`、`doc_citations(tenant_id, doc_id)`、`doc_citations(tenant_id, cited_by_ref)`、`transactions(tenant_id, account_id, ts)`、`transactions(tenant_id, ts)`、`audit_logs(tenant_id, ts/severity/event_type, log_id)`、`delegation_grants` 双方向索引等），以及防并发重放的 `UNIQUE INDEX idx_webhook_tenant_nonce ON webhook_events(tenant_id, nonce)`；在保持 `init_schema` / `seed_dataset` 与存量表结构 100% 兼容的前提下绝不清空存量数据。
3. **循环内 $N+1$ 查询与逐笔提交**：
   - `search_service.py` 原版每篇候选文档循环内重复调用 `resolve_effective_permissions`、`is_doc_blocked_by_acl` 与 `_get_doc_citation_count`；
   - `rule_engine.py` 原版每笔交易独立开连接全表扫描 `transactions`（还无意义 `json.loads(metadata_json)`）、独立全表扫 `contagion_graph`、独立扣减告警配额并逐笔 `commit`。
   重构后均收口为租户级内存增量数据结构与整批单次 `BEGIN IMMEDIATE` 事务。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
1. **紧凑单篇增量倒排索引与常驻堆内存控制（`aegis_app/doc_indexer.py`, `aegis_app/doc_writer.py`, `aegis_app/search_service.py`）**：
   - 节点 `_CompactDocNode` 全面采用 `__slots__`，**绝不在内存中常驻完整原始正文 `body`**，仅保留前 140 字符 `snippet = body[:140]`（`batch-get` 仍走 SQLite 主键点查完整正文）；
   - 租户内维护词表整数 ID 映射 `term_to_id`，正文词出现下标以紧凑 4 字节 `array('I')` 存于 `body_pos`，并直接复用 `len(body_pos[tid])` 作为 `body_tf`，省去独立词频字典；仅活跃且未隔离文档挂载于倒排表 `postings`、分类集合 `by_category` 与标签集合 `by_tag`，首次加载采用 `fetchmany(256)` 流式构建后立即丢弃大正文；
   - 文档 `upsert` / `retire` / `quarantine` 仅通过 `TenantDocIndex.apply_upsert` 与 `apply_status_change` 执行**单篇增量更新**（摘除旧词项、插入新词项），时间复杂度从整库重建 $O(N_{doc} \cdot L)$ 降至 $O(|doc| + \text{deg})$；
   - **反向引用图局部传播**：`TenantDocIndex` 维护 `doc_valid_status`（严格按 `tenant_id` 隔离）与内存反向引用图 `reverse_dependents: dict[str, set[str]]`。当内部源文档 `D` 的有效状态（`ACTIVE` 且 `quarantined == 0`）翻转时，`_propagate_source_status_change` 仅遍历 `reverse_dependents.get(D)` 在 $O(\text{deg}(D))$ 内增减受影响文档的 `citation_count`，彻底消除重查库与全表重算。
2. **短语词距邻近度双指针降维（`aegis_app/doc_indexer.py`）**：
   - `compute_min_pair_distance` 对相邻查询词对的单调递增位置数组执行双指针线性扫描，并在遇到 `min_dist == 1` 时**立即早停**；单对词距复杂度由原版 $O(L + |P_a|\cdot|P_b|)$ 降至 $O(|P_a| + |P_b|)$，直接读取紧凑节点的 `body_pos` 实现零重新分词。
3. **双轨法规近似修订簇折叠降维（`aegis_app/search_service.py`, `aegis_app/doc_indexer.py`）**：
   - 严格保留 `legacy_compat.canonicalize_regulation_code` 历史法规号映射；`_deduplicate_candidates` 先按非空归一化法规号 `canon_reg` 分桶（不同法规号零比较），同桶内调用 `jaccard_similarity_sets` 先执行**集合大小比值数学剪枝**（`min_l / max_l < DEDUP_JACCARD_THRESHOLD - 1e-12` 直接跳过求交），再对紧凑 `frozenset[int]` 执行 C 级集合求交，保留与原版 100% 相同的贪心代表顺序与簇计数。
4. **滑动窗口精确动态中位数与乱序回退（`aegis_app/window_stats.py`）**：
   - 将原版 $O(N^2)$ 冒泡排序替换为 `sorted()` $O(N \log N)$，并在 `AccountSlidingWindow` 中实现**双堆（大顶堆 `low` + 小顶堆 `high`）+ 惰性删除计数 `SlidingMedianTracker`**；
   - 单调递增时间戳走均摊 $O(\log W)$ 快路径（窗口弹出与入窗均摊对数复杂度、$O(1)$ 读取四维指标）；当遇到**乱序时间戳 `ts < max_ts`** 时自动切入二分切片 `[ts - 86400, ts]` 精确回退路径并同步维护快路径状态，保证任意乱序输入下与原版全表扫描 100% 零失真。
5. **三跳受制裁资金传染图降维（`aegis_app/contagion_graph.py`）**：
   - `TenantContagionGraph` 维护按时间戳滑窗更新的多重计数邻接表 `adj`（单调路径 $O(1)$ 均摊弹出过期边，乱序路径二分切片精确回退）；
   - 将原版从所有制裁源点 `pop(0)` BFS 全图改为**端点侧 2 跳交集早停** `_check_hop_in_adj`（先 $O(1)$ 判 `hop=1`，再判两端点 1 跳邻接与 `sanctioned` 是否相交 `hop=2`，最后仅扫 1 跳邻居的邻接与 `sanctioned` 交集并在命中 `hop=3` 时早停），复杂度由 $O(B \cdot N_{tx} + |S|(V+E))$ 降至接近 $O(\text{deg}(a) + \text{deg}(b))$。
6. **流式审计摘要常量内存导出（`aegis_app/audit_export.py`）**：
   - 彻底移除 `fetchall()`、无用的 `payload_json` 读取与两次 `copy.deepcopy`，改由 `_stream_audit_digest` 仅查询 6 个必要列并通过 `cur.fetchmany(512)` 单遍流式计算滚动 SHA-256、分布统计与前 `sample_limit` 样本，空间复杂度由 $O(N)$ 降至 **$O(1)$**。

---

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
为同时消除跨接口竞争、双向调拨死锁与全局粗暴大锁，我们在 `aegis_app/runtime.py`、`aegis_app/ledger_ops.py` 与 `aegis_app/rule_engine.py` 中确立了**租户分片 + 三级严格全局锁偏序**（所有代码路径必须由小到大获取，绝不逆序）：
- **Level 1**：`rt.risk_lock(tenant_id)`（仅 `evaluate_transaction_batch` 获取，隔离单租户风控内存状态与回滚，不同租户完全并发）；
- **Level 2**：`rt.acquire_quota_locks(tenant_id, buckets)`（按配额池名称**字典序升序去重加锁**：`transfer_tenant_quota` 对 `(from_quota, to_quota)` 按字典序加锁，`consume_tenant_quota` 锁 `(quota_type,)`，`evaluate_transaction_batch` 在进入 SQLite 事务前预先获取 `(ALERT_QUOTA_BUCKET,)` 锁）；
- **Level 3**：`rt.write_tx()`（显式 `BEGIN IMMEDIATE` 写事务，在所有必需的 Python 细粒度锁获取之后才进入，彻底消除“事务内反过来抢 Python 锁”的跨层 AB-BA 死锁）。
- **四位一体强原子提交与回滚**：`evaluate_transaction_batch` 在阶段 0 先完成无锁全量输入预校验；进入 `Level 1 -> Level 2 -> Level 3` 后，在单次 `BEGIN IMMEDIATE` 事务内顺序完成滑窗计算、三跳传染计算、告警配额暂扣、写入 `transactions` / `risk_decisions` 与批次结束统一更新 `REALTIME_ALERT_POOL`，并同步记录 `added_by_acct` 与 `added_edges` 回滚日志。一旦任意一笔发生主键冲突或异常，`write_tx()` 自动 `ROLLBACK` 撤销全部 DB 交易、决策与告警配额扣减，同时 `except` 块调用 `risk_state.graph.rollback_edges` 与 `acct_win.rollback_entries` 精准清除内存增量，确保零半截落盘、零配额泄漏、零内存污染。
- 应急令牌 `redeem_override_token` 与配额扣减均配合 SQLite 条件原子更新（`WHERE used = 0` / `WHERE remaining_quota >= ?`）与 `rowcount == 1` 校验，确保高并发下零超扣、严格单次核销。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
1. **五维完全解耦纪元（`aegis_app/runtime.py` `TenantEpochs`）**：
   - 每个租户独立维护 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch`；
   - `upsert_doc_acl_rule` 仅增量更新 `TenantAclIndex` 并递增 `acl_epoch`，**绝不触发 `doc_epoch` 变更或重建文档倒排索引**；检索结果有界 LRU 缓存 `BoundedLRUCache`（每租户上限 128 条）将 `(doc_epoch, acl_epoch, caller.user_id, live_clearance, ...)` 纳入缓存键，兼顾命中率与零脏读。
2. **2 跳受控借调链实时核验、零写到期降级与环路免疫（`aegis_app/delegation.py`, `aegis_app/auth.py`）**：
   - `TenantPermState` 缓存租户活跃用户、组织继承与显式授予角色（`user_base_org_roles` 与 `user_explicit_grants` 分离存储）及 `delegations_by_grantee` 图；
   - `active_delegated_roles(grantee_user_id, at_ts)` 每次按请求的实时 `at_ts` 执行深度上限 `MAX_DELEGATION_HOPS = 2` 且携带路径 `visited` 集合的受限 BFS，逐段核验 `starts_at <= at_ts < expires_at`、`active` 状态及源头仍持有原生角色；因此即使上游一级借调窗口自然到期且无任何写操作，下游二级受托人也会**自动零写降级**；源头被 `revoke_or_grant_role` 撤权后增量更新 `user_explicit_grants` 并递增 `perm_epoch`，下游 1~2 跳立即级联失效；
   - `create_or_revoke_delegation` 创建委托前调用 `would_create_cycle` 执行反向可达检测，显式拒绝任意长度有向环路，同时校验 2 跳受托人不可再发起 3 跳借调。

---

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
1. **一阶与双通道二阶 SQL 注入全面参数化**：
   - `search_service.py` 彻底移除 `sort_by`/`sort_dir`/`tag_filter`/`tenant_id` SQL 字符串拼接，对 `sort_by`（`score`/`updated_at`/`risk_weight`）和 `sort_dir`（`asc`/`desc`）实施严格白名单校验；
   - **二阶通道一（文档引用）**：`doc_indexer.py` 与 `search_service._get_doc_citation_count` 对 `doc_` 内部引用实施全参数化查询并强制附加 `tenant_id = ?` 隔离；
   - **二阶通道二（报表模板）**：`audit_export.save_report_template` 对 `extra_event_filter` 实施 `^[A-Z0-9_]{1,64}$` 写入白名单校验，`render_saved_report` 读取侧执行全参数化 `WHERE tenant_id = ?` 与 `AND event_type = ?`。
2. **跨租户引用侧信道与多维越权（IDOR/密级/隔离墙）阻断**：
   - 内部 `doc_` 引用有效性严格限制在本租户 `TenantDocIndex.doc_valid_status` 与 `WHERE tenant_id = ?` 范围内，引用他租户 `doc_id` 恒计 0 且不随他租户状态变化；
   - `search_service.batch_get_documents` 补全 `tenant_id = ?`、`status = 'ACTIVE'`、`quarantined = 0`、`clearance_level <= live_clearance` 与 `acl_idx.is_blocked` 全维鉴权；
   - `rule_engine.get_risk_decision_detail` 补齐 `AND tenant_id = ?` 阻断跨租户决策 IDOR；
   - `server.py` 移除 `/api/v1/health?debug=1` 诊断泄露与 `/api/v1/internal/diagnostics` 未授权接口，脱敏 500 兜底响应，零泄露路径、堆栈与 `MASTER_SIGNING_PEPPER`。
3. **模板沙箱彻底废弃 `str.format`（零反射、零宽度放大）**：
   - `audit_export._validate_and_render_title` 在写入与渲染双端均以纯手写词法扫描器仅放行 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个精确字面占位符并做字面替换，彻底阻断 `{env.master_pepper}`、`{tenant_id.__class__...}` 反射泄密及 `{tenant_id:0>200000}` 宽度放大 DoS。
4. **多变体目录穿越锚定（`audit_export.read_compliance_snapshot`）**：
   - 迭代 URL 解码最多 3 次检测并阻断任何编码隐藏的 `..`/`/`/`\`/`\x00`/`:`，强制匹配单级文件名正则 `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`，拒绝符号链接，并使用 `resolved.is_relative_to(base_dir)` 严格锚定于租户 `snapshots/` 目录内。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
1. **认证与 Webhook 常量时间验签 + ±300s 时间窗 + 并发防重放（`aegis_app/auth.py`）**：
   - `authenticate_caller` 对未知/停用租户与未知/停用用户均执行预先 `hash_api_token` 与 `hmac.compare_digest(_DUMMY_TOKEN_HASH, provided_hash)` 常量时间掩蔽；
   - `process_settlement_webhook` 强制校验 `abs(now_ts - callback_ts) <= 300`，未知租户执行 dummy HMAC 常量时间掩蔽，使用 `hmac.compare_digest` 验签，并依托 `webhook_events(tenant_id, nonce)` `UNIQUE` 索引 + `BEGIN IMMEDIATE` 原子插入拦截串行与并发重放（409 Conflict）。
2. **抗多变体复杂度炸弹（`middleware.py`, `rule_engine.py`, `doc_writer.py`, `search_service.py`）**：
   - **JSON 深度与体量预检**：`middleware._precheck_json_depth` 在调用 `json.loads` 之前以 $O(N)$ 状态机拦截超过 `MAX_JSON_DEPTH = 32` 的千层嵌套载荷，配合 `parse_constant=_reject_json_constant` 禁用 `NaN`/`Infinity`、限制 `MAX_PAYLOAD_BYTES = 2 MiB` 与迭代对象预算 `MAX_JSON_NODES = 20000`；
   - **消除邮箱与规则树多变体 ReDoS**：`rule_engine.validate_contact_email` 替换为无嵌套量词线性正则；`_compile_safe_regex` 静态拒绝反向引用（`\1`..`\9`, `(?P=...)`）、环视/条件语法、花括号大上界（`> 20`）、分组嵌套量词（如 `(a+)+`）、带重复的交替分组（如 `(a|aa)+`）、相邻可变重复量词（如 `.*.*`）与过量通配重复；
   - **规则树与列表硬预算**：`validate_rule_tree` 迭代校验深度 `<= 16`、节点总数 `<= 128`、`IN` 列表 `<= 100`；限制 `citations <= 64`、`batch-get <= 200`、`query_terms <= 32`、`evaluate-batch <= 2000`。
3. **严格数值与类型边界守卫（`aegis_app/middleware.py` & `aegis_app/server.py`）**：
   - 全路由与核心服务接入 `parse_strict_int` / `parse_strict_bool` / `parse_strict_finite_number`，明确拒绝 `bool` 冒充整数（防止 `isinstance(True, int)` 绕过）、拒绝超出 64 位有符号整数 `[-2^63, 2^63 - 1]` 导致 SQLite `OverflowError`、拒绝 `NaN`/`Infinity` 与字符串伪布尔值。

---

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/doc_indexer.py` 中以 `__slots__` 实现不常驻完整 `body` 的 `_CompactDocNode`（仅存 140 字 `snippet`、词表整数 ID 与 `array('I')` 位置表）及 `TenantDocIndex`，在 `apply_upsert` / `apply_status_change` 中完成单篇增量倒排更新与基于 `reverse_dependents` 的 $O(\text{deg})$ 内部引用传播；`compute_min_pair_distance` 实现双指针且 `min_dist == 1` 早停词距计算，`jaccard_similarity_sets` 实现集合大小比值剪枝；`aegis_app/window_stats.py` 的 `SlidingMedianTracker` + `AccountSlidingWindow` 实现双堆惰性删除 $O(\log W)$ 精确动态中位数及乱序时间戳二分回退；`aegis_app/contagion_graph.py` 的 `TenantContagionGraph` 实现滑窗邻接表与端点侧 2 跳交集早停 `_check_hop_in_adj`；`aegis_app/audit_export.py` 的 `_stream_audit_digest` 以 `fetchmany(512)` 实现 $O(1)$ 常量内存流式审计摘要。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/runtime.py` 中以 `TenantEpochs` 解耦 `doc_epoch` / `acl_epoch` / `perm_epoch` / `policy_epoch` / `sanction_epoch`，`aegis_app/acl_wall.py` 的 `upsert_doc_acl_rule` 仅增量更新 `TenantAclIndex` 并递增 `acl_epoch` 而不触碰 `doc_epoch` 或重建倒排索引；`aegis_app/delegation.py` 的 `TenantPermState.active_delegated_roles` 按请求实时 `at_ts` 执行带路径 `visited` 防环且受 `MAX_DELEGATION_HOPS = 2` 约束的核验，天然支持上游借调窗自然到期零写降级与源头撤权级联失效，`create_or_revoke_delegation` 通过 `would_create_cycle` 在建边阶段即拦截任意有向环路。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/runtime.py` 中定义三级无死锁偏序锁——Level 1 `risk_lock(tenant_id)`、Level 2 按配额池字典序升序加锁的 `acquire_quota_locks(tenant_id, buckets)`、Level 3 显式 `BEGIN IMMEDIATE` 的 `write_tx()`；`aegis_app/ledger_ops.py` 的 `transfer_tenant_quota` / `consume_tenant_quota` 严格遵循 Level 2 -> Level 3 锁序，`aegis_app/rule_engine.py` 的 `evaluate_transaction_batch` 严格遵循 Level 1 -> Level 2 (`REALTIME_ALERT_POOL`) -> Level 3 锁序，在单次 SQLite 事务内完成交易、决策与告警配额池提交，异常时自动回滚数据库并按 `added_edges` / `added_by_acct` 回滚内存传染图与滑动窗口，实现四位一体强原子性。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/audit_export.py` 中以 `_validate_and_render_title` 彻底取代 `str.format`（仅放行 `{tenant_id}`/`{total_records}`/`{total_amount_cents}` 纯字面替换，阻断反射与宽度放大），`save_report_template` 与 `render_saved_report` 对 `extra_event_filter` 执行正则白名单与全参数化查询，`read_compliance_snapshot` 通过迭代解码拦截、单级文件名白名单、拒绝符号链接与 `is_relative_to(base_dir)` 锚定彻底堵死目录穿越；`aegis_app/doc_indexer.py` 与 `aegis_app/search_service.py` 对 `doc_` 内部引用实施同租户参数化隔离并补齐 `batch_get_documents` 的租户/状态/隔离/密级/隔离墙鉴权；`aegis_app/rule_engine.py` 的 `get_risk_decision_detail` 强制 `AND tenant_id = ?`；`aegis_app/server.py` 清除 `/api/v1/health?debug=1` 与 `/api/v1/internal/diagnostics` 泄密并脱敏 500 错误；`aegis_app/auth.py` 实现常量时间比对、未知租户/用户 dummy 掩蔽、Webhook `±300s` 时间窗及 `idx_webhook_tenant_nonce` 唯一约束防重放。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/middleware.py` 中以 `_precheck_json_depth` 在 `json.loads` 之前完成 $O(N)$ 嵌套深度熔断（`MAX_JSON_DEPTH = 32`），通过 `_reject_json_constant` 禁用 `NaN`/`Infinity` 并以 `parse_strict_int` / `parse_strict_bool` / `parse_strict_finite_number` 拒绝 `bool` 冒充整数与超 64 位整数；`aegis_app/rule_engine.py` 以线性正则 `validate_contact_email` 消除邮箱 ReDoS，以 `_compile_safe_regex` 静态拒绝嵌套量词、反向引用、大上界花括号（`> 20`）、重复交替与相邻通配链，以 `validate_rule_tree` 限制规则深度 `<= 16` 与节点数 `<= 128`；`aegis_app/doc_writer.py` 与 `aegis_app/search_service.py` 限制 `citations <= 64`、`batch-get <= 200` 与 `query_terms <= 32`。

---

## 5. 已知工程取舍与残余边界说明
1. **单进程内存索引假设**：本网关面向单机嵌入式 SQLite 部署，增量倒排索引、ACL 索引、权限图与风控滑窗/传染图维护在当前 Python 进程内存中（按 `db_path` 与文件 inode 隔离并在 `create_gateway` / `seed_dataset` 时重置）。若外部独立进程在网关运行期间绕过网关直接修改同一 SQLite 文件，当前进程不会主动轮询外部写事件（需重新挂载或通过网关 API 写入）。
2. **SQLite 单写者串行边界**：WAL 模式下多租户并发读操作与内存计算完全并行，但 SQLite 存储引擎本身在 `BEGIN IMMEDIATE` 落盘提交阶段为文件级单写者串行；我们通过合并批次事务、仅在持有必要细粒度锁后短暂开启写事务及 BUSY 指数退避重试，最大限度压缩了写事务临界区。
3. **规则正则静态审查保守边界**：`_compile_safe_regex` 为零误放任意 ReDoS 变体，显式禁止环视、反向引用、超过 20 次的花括号重复及带重复量词的交替分组；极少数合法但高度复杂的正则写法会被保守拒绝（400），在金融合规风控场景下以确定性微秒级求值作为优先取舍。
