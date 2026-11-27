# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

通过对 `aegis_app/` 全部 16 个模块的逐行剖析，初始系统在存储与 I/O 层存在以下核心瓶颈：
1. **高频连接创建销毁与缺少 WAL 并发配置**：原 `db.open_connection` 在每次请求甚至循环内部（如 `acl_wall.get_org_lineage` 逐级上溯、`delegation._collect_upstream_grantors` 递归回溯、`search_service.search_documents` 逐篇查询有效引用与权限、`rule_engine.evaluate_transaction_batch` 逐笔查询与提交）反复打开并关闭 SQLite 文件句柄，默认日志模式下读写互斥严重。
2. **全表缺失二级复合索引与宽行回表开销**：初始 17 张业务表除主键外无任何二级索引，导致文档过滤、引用统计、账户交易窗口扫描、制裁关联边查询及审计流水检索全部退化为全表扫描；且 `audit_logs` 查询拉取了大体积但摘要并不使用的 `payload_json` 列。
3. **跨模块 N+1 查询放大与逐笔独立事务刷盘**：`search_documents` 在候选循环内对每篇文档重复调用权限解析、ACL 查询与逐条 `doc_` 引用查表；`evaluate_transaction_batch` 对批次内每笔交易分别执行全表读取、无用 `metadata_json` 反序列化及多次独立 `COMMIT` 落盘。

**重构方案（主要落位于 `aegis_app/db.py`、`aegis_app/rule_engine.py`、`aegis_app/audit_export.py`）**：
- **有界连接池与高性能 PRAGMA**：在 `db.py` 中实现 `BoundedConnectionPool`（`__slots__`，单库容量上限 `DB_POOL_MAX_SIZE = 16`，全局运行时注册表 `_RUNTIMES` 受 `DB_RUNTIME_CACHE_MAX = 16` LRU 约束并自动检测数据库文件 `st_ctime_ns` 重建失效），连接初始化统一启用 `journal_mode=WAL`、`synchronous=NORMAL`、`temp_store=MEMORY` 与 `cache_size=-8000`，归还时自动检测并回滚异常未决事务。
- **复合索引与窄列覆盖索引体系**：在 `db.py` 的 `INDEX_SQL`（由 `init_schema` 与 `DatabaseRuntime.ensure_indexes` 幂等保障）中补齐 17 条复合与唯一索引；针对审计摘要专门建立剥离 `payload_json` 的窄列覆盖索引 `idx_audit_covering_scan`、`idx_audit_evt_covering`、`idx_audit_sev_covering`，使滚动摘要直接走覆盖索引顺序扫描，彻底消除主表大字段回表与临时排序。
- **批量单事务合并**：在 `evaluate_transaction_batch` 中将整批交易的落盘、风控决策写入与告警配额池更新合并至单次 `BEGIN IMMEDIATE` 事务的 `executemany` 中，消除逐笔刷盘开销。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

1. **紧凑单篇增量倒排索引与 `reverse_dependents` 双向引用传播（`aegis_app/doc_indexer.py`）**：
   - **常驻堆内存压缩**：设计带 `__slots__` 的 `CompactDocNode`，**彻底剥离大体积原始全文 `body` 常驻内存**，仅保留 `snippet = body[:140]`、经 `intern_term` 整数化编码后的标题受限词频 `title_tf: dict[int, int]`、正文递增位置元组 `body_pos: dict[int, tuple[int, ...]]` 及唯一词项集 `uniq_terms: frozenset[int]`；`batch_get_documents` 按主键索引按需点查正文；所有租户级缓存均置于 `BoundedLRUMap(64)` 有界容器内。
   - **增量更新与 $O(\text{deg})$ 引用联动**：`TenantDocIndex` 维护 `inverted` 倒排表与内存反向内部引用图 `reverse_dependents: dict[str, set[str]]`。`upsert`、`quarantine`、`retire` 分别通过 `apply_upsert`、`apply_quarantine`、`apply_retire` 做单篇词项集 $O(|T_{\text{doc}}|)$ 原地挂载/卸载，无需重查整表或重建整租户索引；当内部 `doc_` 引用源文档发生创建激活、隔离/解封或退役状态翻转时，`_propagate_source_validity_change` 沿 `reverse_dependents` 仅对依赖它的文档做 $O(\text{deg})$ 局部引用计数增减。
2. **双指针早停词距邻近度（`aegis_app/doc_indexer.py`）**：
   - 将原版双重嵌套循环 $O(|P_a| \cdot |P_b|)$ 降维为 `_min_distance_two_pointers` 有序位置元组双指针线性扫描 $O(|P_a| + |P_b|)$，且一旦观测到理论最小正整数距离 `min_dist == 1` 立即早停返回。
3. **双轨法规分桶与集合大小比值剪枝去重（`aegis_app/doc_indexer.py`、`aegis_app/search_service.py`）**：
   - 检索候选使用轻量元组排序并延迟到分页切片后再物化输出字典；聚类阶段先按 `canonicalize_regulation_code` 归一化编号分桶隔离不同法规，同桶比较在 `is_jaccard_cluster_match` 中先执行集合大小比值上界剪枝 `min_l / max_l < 0.70`（$O(1)$ 排除不可能达标对），通过后再对 `frozenset[int]` 求交，严格保持贪心消费顺序与二次排序 100% 零失真。
4. **滑动窗口 $O(\log W)$ 对顶双堆动态中位数与乱序回退（`aegis_app/window_stats.py`）**：
   - 移除原版 $O(W^2)$ 冒泡排序与逐笔全表扫描，实现支持分离延迟删除计数的对顶双堆 `DualHeapMedian`（`__slots__`，最大堆 `lower` + 最小堆 `upper` + `delayed_lower`/`delayed_upper`）：单调流下过期驱逐与新笔插入均为 $O(\log W)$，精确中位数读取为 $O(1)$；当遇到乱序时间戳 `ts < state.max_ts` 时，自动切换至有序历史数组 `bisect_left`/`bisect_right` 精确区间 `[ts - 86400, ts]` 计算，确保任意时间戳序列 100% 零失真。
5. **三跳制裁传染双向邻域交集搜索（`aegis_app/contagion_graph.py`）**：
   - `TenantContagionGraph` 维护 24 小时滑动活跃边队列与引用计数邻接表 `adj_counts`；利用无向图最短路对称性，将原版全表重建 + 多源队列 BFS $O(|S|(|V|+|E|))$ 降维为 `_compute_hop_from_adj` 的自适应双向邻域交集检测（端点直中 `hop=1`、端点与制裁集相邻 `hop=2`、端点 1 步邻域与制裁集 1 步邻域相交 Meet-in-the-Middle `hop=3`），单笔耗时降至局部度数级，并同样支持乱序时间戳 `bisect` 精确回退。
6. **游标流式审计摘要导出（`aegis_app/audit_export.py`）**：
   - `_stream_digest_from_cursor` 采用原生元组游标 `fetchmany(512)` 分块流式扫描窄覆盖索引，彻底移除 `fetchall()`、无用 `payload_json` 解析与双重 `copy.deepcopy`，将空间复杂度从 $O(N)$ 压缩至严格 $O(1)$。

---

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

为同时消除全局大锁串行瓶颈、单池并发超扣、跨池双向交叉调拨死锁（`A -> B` vs `B -> A`）以及 Python 层锁与 SQLite 写事务锁的跨层逆序死锁，在 `aegis_app/db.py` 的 `DatabaseRuntime` 中建立了**内存恒定有界（固定槽位条带锁）的三层严格单向锁偏序（Layer 1 $\to$ Layer 2 $\to$ Layer 3）**：
- **Layer 1（租户风控评估条带锁 `_risk_stripes`，128 固定槽位）**：由 `acquire_risk_lock(tenant_id)` 获取，保证单租户内并发批次窗口与传染图演进的顺序性，跨租户请求并行无阻。
- **Layer 2（租户配额桶条带锁 `_quota_stripes`，256 固定槽位）**：由 `acquire_quota_locks(tenant_id, *bucket_names)` 获取；当 `transfer_tenant_quota` 涉及两个配额池时，内部对映射槽位号去重并严格按升序 `sorted(...)` 依次加锁、逆序释放，从图论上根除双向调拨环路死锁；且固定大小锁数组使恶意随机桶名请求下的锁内存增长恒为 0。
- **Layer 3（SQLite `BEGIN IMMEDIATE` 写事务锁）**：由 `write_tx()` 获取。**全局铁律**：任何路径（含 `evaluate_transaction_batch`、`transfer_tenant_quota`、`consume_tenant_quota`）必须在进入 `BEGIN IMMEDIATE` **之前**完成所需的 Layer 1 / Layer 2 加锁与只读缓存预热，绝不在持有 SQLite 写锁期间反向申请上层 Python 锁。

**失败批次四位一体强原子回滚（`aegis_app/rule_engine.py`）**：
`evaluate_transaction_batch` 先在无锁阶段完成整批字段、严格整数、邮箱格式与批内重复 `tx_id` 预检；随后在 `Layer 1 -> Layer 2(REALTIME_ALERT_POOL) -> Layer 3(BEGIN IMMEDIATE)` 保护下，以局部事务变量暂存告警配额扣减，并用 `WindowBatchUndo` 与 `ContagionBatchUndo` 记录滑窗和传染图变更，最后一次性写入 `transactions`、`risk_decisions` 与 `tenant_quotas`。一旦任一笔触发规则异常或主键冲突（`sqlite3.IntegrityError`），`except` 块立即调用 `window_mgr.rollback(win_undo)` 与 `contagion_graph.rollback(cg_undo)` 精确还原内存结构，并由 `write_tx` 执行 SQLite `ROLLBACK`，实现**数据库、滑动窗口、三跳传染图与告警配额池**四位一体零残留强原子回滚。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

系统将租户内存状态拆分为五个正交解耦的独立纪元模块，杜绝“牵一发而动全身”的缓存雪崩：
1. `TenantAuthState`（`auth_epoch`，`delegation.py`）：维护用户、预计算无环组织祖先链 `org_lineage`、继承角色、显式角色授予与活跃借调边表。
2. `TenantAclState`（`acl_epoch`，`acl_wall.py`）：独立维护每篇文档的 `DocAclEntry`（`user_allow`/`user_deny`/`org_allow`/`org_deny`）。调用 `/api/v1/admin/doc-acl` 修改单条隔离墙规则时，仅 $O(1)$ 更新目标文档规则集并递增 `acl_epoch`，**完全不触碰、不清空、不重建文档倒排索引 `TenantDocIndex`**。
3. `TenantDocIndex`（`doc_epoch`，`doc_indexer.py`）：独立维护文档紧凑特征与双向引用图。
4. `TenantContagionGraph`（`sanctions_epoch`，`contagion_graph.py`）：制裁名单变更仅原地增删 `sanctioned_set` 并递增 `sanctions_epoch`。
5. `policy_cache`（`policy_version`，`rule_engine.py`）：策略热更新原地替换该租户策略字典。

**二级受控借调链与防环核验（`aegis_app/delegation.py`）**：
- 写路径 `create_or_revoke_delegation`：核验发起人具备原生角色或当前时刻有效的一级受托资格（阻断三级及以上转借调），并通过受限 BFS `_has_active_delegation_path` 检测同角色未过期委托有向图可达性，毫秒级阻断 `A -> B -> ... -> A` 有向环路创建。
- 读路径 `resolve_delegated_roles_in_memory`：严格在最多 `MAX_DELEGATION_HOPS = 2` 层内按请求时刻 `at_ts` 核验每一跳 `starts_at <= at_ts < expires_at` 及源头委托人实时 `native_roles_of`。当上游一级借调窗口自然跨过 `expires_at` 时无需任何数据库写操作即实时自动降级；当源头角色被 `revoke_or_grant_role` 撤回或上游委托被撤销时，下游 1~2 跳立即同步级联失效。

---

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

1. **一阶与双通道二阶 SQL 注入根除**：
   - `search_service.py`：移除 `tenant_id`、`tag_filter` 与动态 `ORDER BY` 拼接，检索全面切换至内存倒排与白名单排序字段（`_ALLOWED_SORT_BY` / `_ALLOWED_SORT_DIR`），`batch_get_documents` 100% 参数化绑定。
   - **二阶通道一（文档内部引用）**：移除原 `_get_doc_citation_count` 中 `WHERE doc_id = '{ref}'` 的字符串拼接 SQL，在 `doc_writer.py` 入口限制引用条数与长度，并在 `TenantDocIndex` 内部严格限定仅当 `ref` 属于**同一租户**、`status == 'ACTIVE'` 且 `quarantined == 0` 时计入有效引用，同时堵死二阶盲注与**跨租户文档存在性/隔离态侧信道预言机**。
   - **二阶通道二（审计报表模板过滤词）**：在 `audit_export.save_report_template` 与 `render_saved_report` 双端强制校验 `extra_event_filter` 匹配 `^[A-Z0-9_]{1,64}$`，且底层 SQL 100% 使用 `?` 参数化查询。
2. **报表模板零反射与防宽度填充放大（`aegis_app/audit_export.py`）**：
   - **彻底弃用 `str.format`** 且绝不传入 `RUNTIME_ENV`；实现单趟词法状态机 `_validate_and_render_title`，仅接受 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个精确字面占位符（支持 `{{`/`}}` 转义），任何属性反射（如 `{env.master_pepper}`）或格式化宽度放大载荷（如 `{tenant_id:0>200000}`）均在保存与渲染双阶段直接拒绝（400）。
3. **多变体目录穿越阻断（`aegis_app/audit_export.py`）**：
   - `read_compliance_snapshot` 对输入执行最多 4 轮收敛 `urllib.parse.unquote` 递归解码检查，拦截含 `/`、`\`、`:`、`..`、空字节或非 `^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$` 的文件名，拒绝符号链接（`is_symlink()`），并通过 `Path.resolve()` 强制断言 `target_path.parent == base_dir` 且 `target_path.is_relative_to(base_dir)`。
4. **多维越权与内部诊断泄密封堵**：
   - `server.py` & `middleware.py`：移除 `/api/v1/health?debug=1` 诊断回显，禁用 `/api/v1/internal/diagnostics`（返回 403），清除 500 异常响应中的 `debug_context`、`master_pepper`、物理路径与栈追踪。
   - `search_service.batch_get_documents`：补全 `tenant_id`、`status='ACTIVE'`、`quarantined=0`、`clearance_level <= live_clearance` 与 `is_doc_blocked_in_memory`（三级利益冲突隔离墙）全部五道防线。
   - `rule_engine.get_risk_decision_detail`：补全 `AND tenant_id = ?` 阻断跨租户风控决策 IDOR。
   - `doc_writer.upsert_compliance_document`：补全对已存在文档的利益冲突墙阻断校验。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

1. **常量时间验签、枚举时序掩蔽与并发 Nonce 防重放（`aegis_app/auth.py`）**：
   - `authenticate_caller` 与 `process_settlement_webhook` 全部改用 `hmac.compare_digest`；针对未知/停用租户或未知/停用用户，统一先对 `_DUMMY_TOKEN_HASH` / `_DUMMY_WEBHOOK_SECRET` 执行一次常量时间摘要比对后再返回错误，消除身份枚举时序侧信道。
   - `process_settlement_webhook` 强制校验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS (300)`，并在 `BEGIN IMMEDIATE` 写事务查重 + `idx_webhook_tenant_nonce_uniq` 唯一索引双重约束下拦截串行与高并发重复 Nonce 重放（返回 409）。
   - `redeem_override_token` 采用 `BEGIN IMMEDIATE` 内带 `AND used = 0` 条件原子更新并核验 `rowcount == 1`，确保高并发下严格单次核销。
2. **多变体复杂度炸弹与严格类型边界熔断（`aegis_app/middleware.py`、`aegis_app/rule_engine.py`）**：
   - **消除回溯正则**：将 `PARTNER_EMAIL_PATTERN` 改写为等价无嵌套量词线性正则 `^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$`；自定义规则 `REGEX` 经 `_compile_safe_regex` 与 `_inspect_regex_ast`（基于标准库 `re._parser` AST）静态审计，拦截嵌套量词、重复体内非单字面互斥分支、花括号大上界量词（`> 64`）、反向引用与环视断言。
   - **JSON 预检深度与规则/载荷预算**：`middleware.precheck_json_depth` **在调用 `json.loads` 之前**执行单趟词法括号深度预检（`MAX_JSON_DEPTH = 24`）与字节上限控制（2MB），并通过 `parse_constant` 直接拒绝 `NaN`/`Infinity`；`validate_rule_tree` 限制规则树深度 `<= 12`、节点数 `<= 128`、`IN` 列表 `<= 128`。
   - **严格数值与布尔守卫**：`strict_int`、`strict_bool`、`strict_finite_number` 全局拦截 `bool` 伪装 `int`（`isinstance(val, bool)`）、超 64 位整数溢出、畸形超长数字串及比较运算中的 `bool`/`int` 类型混淆（`_safe_equals` / `_safe_numeric_pair`）。

---

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/doc_indexer.py` 中，`CompactDocNode` 使用 `__slots__` 且剥离原始全文 `body`（仅存 140 字符 `snippet` 与整数词项特征），`TenantDocIndex` 通过 `apply_upsert`、`apply_quarantine`、`apply_retire` 与内存反向引用图 `reverse_dependents`（`_propagate_source_validity_change`）实现单篇增量更新与 $O(\text{deg})$ 引用计数联动；`_min_distance_two_pointers` 实现双指针词距扫描并在 `min_dist == 1` 早停，`is_jaccard_cluster_match` 实现集合大小比值剪枝（`min_l / max_l < threshold`）；在 `aegis_app/window_stats.py` 与 `aegis_app/contagion_graph.py` 中分别通过 `DualHeapMedian` 对顶双堆（$O(\log W)$）及 `TenantContagionGraph._compute_hop_from_adj` 双向邻域交集搜索降维滑窗中位数与三跳传染计算，且均兼容乱序时间戳 `bisect` 精确回退。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/delegation.py`（`TenantAuthState.auth_epoch`）、`aegis_app/acl_wall.py`（`TenantAclState.acl_epoch`）、`aegis_app/doc_indexer.py`（`TenantDocIndex.doc_epoch`）与 `aegis_app/contagion_graph.py`（`TenantContagionGraph.sanctions_epoch`）中实现多维纪元正交解耦，`upsert_doc_acl_rule` 仅局部更新 `DocAclEntry` 而不清空文档倒排索引；`delegation.py` 中 `resolve_delegated_roles_in_memory` 严格执行最多 2 跳 `[starts_at, expires_at)` 时效窗与源头原生角色核验（上游到期零写降级、源头撤权级联失效），`create_or_revoke_delegation` 通过 `_has_active_delegation_path` 受限 BFS 阻断有向委托环路。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/db.py` 的 `DatabaseRuntime` 中定义固定槽位单向锁偏序 `acquire_risk_lock`（Layer 1）$\to$ `acquire_quota_locks`（Layer 2，多配额池按升序槽位号加锁）$\to$ `write_tx`（Layer 3，`BEGIN IMMEDIATE`）；`aegis_app/ledger_ops.py` 的 `transfer_tenant_quota` 与 `aegis_app/rule_engine.py` 的 `evaluate_transaction_batch` 严格遵循该锁序，且 `evaluate_transaction_batch` 在异常时同步执行 SQLite `ROLLBACK`、`window_mgr.rollback(win_undo)` 与 `contagion_graph.rollback(cg_undo)`，保证数据库、滑窗、传染图与 `REALTIME_ALERT_POOL` 四位一体强原子回滚。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/audit_export.py` 中，`save_report_template` 与 `render_saved_report` 通过 `_EVENT_FILTER_RE` 校验与 `?` 参数化查询根除模板二阶 SQL 注入，通过词法状态机 `_validate_and_render_title` 弃用 `str.format` 仅放行三个字面占位符（阻断反射与宽度放大），`read_compliance_snapshot` 通过循环 URL 解码校验、禁符号链接与 `Path.resolve().is_relative_to` 锚定租户沙盒；在 `aegis_app/doc_indexer.py` 与 `aegis_app/search_service.py` 中，内部 `doc_` 引用严格限定本租户活跃未隔离文档以阻断二阶注入与跨租户侧信道，`batch_get_documents` 强制执行租户、状态、隔离、密级与 `is_doc_blocked_in_memory` 五重校验，`rule_engine.get_risk_decision_detail` 强制校验 `tenant_id`。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/middleware.py` 中，`precheck_json_depth` 在调用 `json.loads` 之前完成词法括号深度预检（`<= 24`）并拒绝 `NaN`/`Infinity`，`strict_int` 与 `strict_bool` 拦截 `bool` 子类混淆与超 64 位整数；在 `aegis_app/rule_engine.py` 中，`PARTNER_EMAIL_PATTERN` 消除嵌套量词回溯，`_compile_safe_regex` 与 `_inspect_regex_ast` 基于 `re._parser` AST 拦截嵌套量词、重复体内重叠分支、大上界花括号量词与反向引用，`validate_rule_tree` 限制规则树深度与节点预算。

---

## 5. 已知工程取舍与残余边界说明

1. **单进程内分片缓存与外部直改数据库边界**：内存倒排索引、滑动窗口与传染图围绕单网关进程高并发吞吐设计，通过 `DatabaseRuntime` 检测数据库文件重建并在 `create_gateway` / `seed_dataset` 时自动刷新；若多独立操作系统进程共享同一 SQLite 文件且绕过网关直接写表，需引入跨进程版本号表对账。
2. **SQLite 单写者串行物理上限**：开启 WAL 模式并合并批量写入后，读写并发与跨池无死锁吞吐大幅提升，但极端写密集场景下底层仍受单文件 SQLite `BEGIN IMMEDIATE` 写锁物理串行约束。
3. **正则安全子集策略**：`_inspect_regex_ast` 为彻底根除指数与高阶多项式 ReDoS，采取保守白名单策略拒绝了反向引用、环视断言及重复体内的复杂多分支交替；合法业务中的常规前缀、字符类、单层量词与外层分支交替（如 `^(WIRE|ACH)_[0-9]{2,8}$`）均完全兼容。
