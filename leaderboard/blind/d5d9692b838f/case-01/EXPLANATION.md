# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

原版系统在存储与 I/O 层存在严重的重复连接创建、缺失复合索引、循环内 N+1 查询以及逐笔独立事务刷盘开销：

1. **有界 WAL 连接池与零系统调用热路径（`aegis_app/db.py`）**：
   - 原版每次数据库操作均调用 `sqlite3.connect()` 新建并关闭连接，且处于默认回滚日志模式。重构后在 `DbRuntimeHub` 中维护容量上限为 32 的有界连接池 `queue.LifoQueue(maxsize=32)`，启用 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL`、`temp_store=MEMORY` 与 `cache_size=-8000`，读请求通过 `borrow_connection()` 无阻塞并发读取，写请求通过 `write_transaction()` 在 `sqlite_write_lock` 内执行 `BEGIN IMMEDIATE` 原子提交，避免 SQLite 默认 `busy_handler` 毫秒级退避休眠导致的长尾延迟毛刺。
   - 全局注册表 `_HUB_REGISTRY` 采用容量上限为 4 的有界 LRU 管理多库实例，并在已解析路径热路径上消除每次请求的 `Path.resolve()` / `stat()` 文件系统调用。
2. **复合索引补齐（`aegis_app/db.py` 中 `INDEX_SQL`）**：
   - 针对高频查询条件补齐 14 条复合索引及 1 条唯一防重放索引，覆盖 `org_nodes(tenant_id, node_id)`、`users(tenant_id, user_id)`、`role_grants(tenant_id, user_id, active)`、`delegation_grants(tenant_id, grantee_user_id/grantor_user_id, active)`、`doc_acl_rules(tenant_id, doc_id, active)`、`compliance_docs(tenant_id, status, quarantined, updated_at DESC)`、`doc_citations(tenant_id, doc_id)`、`transactions(tenant_id, account_id, ts)`、`transactions(tenant_id, ts)`、`risk_decisions(decision_id, tenant_id)`、`webhook_events(tenant_id, nonce)`（唯一索引）及 `audit_logs` 多维过滤顺序扫描索引。
3. **消除跨模块 N+1 循环查询与逐笔落盘（`search_service.py`、`rule_engine.py`、`audit_export.py`）**：
   - 原版 `search_documents` 在候选文档循环内逐篇重复递归查库计算操作员实时权限、组织继承链、隔离墙规则及逐条引用源状态；重构后每次检索仅在入口执行 1 次内存权限快照与隔离墙快照读取，引用计数直接 $O(1)$ 读取内存增量状态。
   - 原版 `evaluate_transaction_batch` 对批次内每笔交易全表拉取 `transactions`、逐行反序列化无用的 `metadata_json` 并逐笔独立开启连接 `COMMIT`；重构后整批合并为单次 `BEGIN IMMEDIATE` + `executemany` 批量写入。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

1. **紧凑单篇增量倒排索引与 $O(\text{deg})$ 双向引用联动（`aegis_app/doc_indexer.py`、`doc_writer.py`、`search_service.py`）**：
   - **常驻堆内存压缩**：`DocIndexNode` 采用 `__slots__` 布局，仅保留 `snippet = body[:140]` 摘要，**绝不将原始大体积 `body` 常驻堆内存**（完整正文仅在 `/api/v1/docs/batch-get` 时按主键参数化读取）；同租户词项通过租户级词表 `_vocab` 驻留复用单份字符串对象，正文词位置序列采用紧凑 `array('H')`（超 65535 词自动切换 `array('I')`，每位置仅占 2 字节）；文档 `retire` 下架时立即调用 `strip_retired_payload()` 释放词频与位置载荷。
   - **单篇增量更新与反向引用传播**：`TenantDocIndex` 维护 `postings`、`by_category`、`by_tag` 以及双向引用图（`external_refs`、`internal_refs`、`reverse_dependents`、`active_ref_sources`、`valid_citation_count`）。`upsert`、`quarantine`、`retire` 分别调用 `apply_upsert`、`apply_quarantine`、`apply_retire` 仅挂载/摘除目标单篇文档词项（`quarantine` 甚至无需重读正文或重新分词），并在本租户 `doc_` 引用源可用状态翻转时沿 `reverse_dependents` 以 **$O(\text{deg})$** 局部增减被引用文档的 `valid_citation_count`，彻底消除整表重查与整库索引重建。
2. **双指针词距邻近度加分与 `min_dist == 1` 早停（`aegis_app/doc_indexer.py`）**：
   - 原版 `compute_phrase_proximity_bonus` 每次重扫全文并做双重循环 $O(|B| + P_a \cdot P_b)$。重构后 `compute_proximity_from_positions` 直接在预构建的有序位置数组 `array('H')` 上执行双指针线性扫描，时间复杂度降至 **$O(|\text{pos}(q_m)| + |\text{pos}(q_{m+1})|)$**，且一旦发现 `min_dist == 1`（相邻词紧邻出现，理论最大加分上界）立即 `break` 早停。
3. **法规号分桶 + 集合大小比值剪枝去重（`aegis_app/search_service.py`、`doc_indexer.py`）**：
   - 原版去重对所有候选对 $(i, j)$ 重复分词并用列表线性查找求交并集，复杂度高达 $O(M^2 \cdot L^2)$。重构后先按非空归一化法规号 `canon_reg` 分桶（不同法规号或空法规号零比较），桶内利用上界不等式 $\text{Jaccard}(A,B) \le \min(|A|,|B|)/\max(|A|,|B|)$ 执行 `min_l / max_l < 0.70` 常数时间剪枝，仅对通过比值剪枝的同法规号文档对在预存 `frozenset` 上做 C 层交集计算，且严格保持 `(-score, -updated_at, doc_id)` 代表元选取顺序与 `cluster_size` 100% 零失真。
4. **$O(\log W)$ 对顶双堆动态中位数与乱序时间戳精确定位（`aegis_app/window_stats.py`）**：
   - 原版 `compute_exact_median_cents` 使用 $O(W^2)$ 冒泡排序。重构后设计 `DualHeapWindow`（最大堆 `_low` + 最小堆 `_high` + 分离惰性删除表 `_del_low`/`_del_high` + 墓碑占空比压缩重建）与 `AccountWindowTracker`：单调时间流下通过游标推进实现单笔均摊 **$O(\log W)$** 维护四维统计（笔数、总额、`cp_counts` 唯一对手方数、精确整数中位数）；遇到乱序/回拨时间戳 `ts < prev_ts` 时，基于有序历史序列 `bisect_left(ts - 86400)` / `bisect_right(ts)` 精确回退/前移区间边界，确保与全表时间窗过滤语义 100% 一致。
5. **双向前沿折半三跳制裁传染追踪（`aegis_app/contagion_graph.py`）**：
   - 原版每笔交易全表扫描 `transactions` 并用 `list.pop(0)` 从每个黑名单实体做 BFS。重构后 `TenantContagionGraph` 增量维护 `[ts - 86400, ts]` 活跃无向邻接计数表 `adj`（同样支持乱序时间戳精确定位与回滚），`query_hop` 采用双向前沿折半（Meet-in-the-Middle）：1 跳 $O(1)$ 集合判属，2 跳比较端点度与制裁集大小择小遍历，3 跳动态比较 $\deg(u)+\deg(v)$ 与 $\sum_{s \in S}\deg(s)$ 并始终展开度更小的一侧，查询复杂度降至 **$O(\min(\deg(u)+\deg(v), \deg(S)))$**，彻底免疫超级中心节点退化。
6. **$O(1)$ 内存游标流式审计摘要导出（`aegis_app/audit_export.py`）**：
   - 原版 `fetchall()` 全量拉取 `payload_json` 并做两次全表 `copy.deepcopy`，空间复杂度 $O(N \cdot |\text{payload}|)$。重构后 `_stream_audit_digest` 在 SQL 层直接省略无用的 `payload_json` 列，通过 `cur.fetchmany(512)` 流式迭代计算 `rolling_sha256`、分布统计与前 `min(sample_limit, 50)` 条样本，常驻内存降至 **$O(1)$**。

---

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

1. **去除全局粗粒度大锁，采用有界条带细粒度锁 + WAL 读写并发（`aegis_app/db.py`）**：
   - 所有锁池均采用启动时预分配的固定长度哈希条带数组（`_risk_stripes[128]`、`_quota_stripes[256]`、`_token_stripes[64]`、`_doc_stripes[128]`、`_meta_stripes[128]`），既实现跨租户并发操作互不阻塞，又保证面对海量伪造租户/配额名攻击时锁对象内存严格 $O(1)$ 零增长。
2. **严格三层全局锁偏序（彻底根除跨层死锁与双向交叉调拨死锁）**：
   - 全系统所有涉及共享状态与数据库写入的路径严格遵守由外向内的全序加锁协议：
     - **Layer 1**：`hub.tenant_risk_lock(tenant_id)`（租户风控批次与滑窗/传染图状态锁）；
     - **Layer 2**：`hub.quota_locks(tenant_id, *quota_types)`（将涉及的 1 个或多个配额池映射为条带下标集合并**按升序排序去重后依次加锁**，彻底消除 `A -> B` 与 `B -> A` 双向并发 `transfer_tenant_quota` 死锁，同时与 `evaluate_transaction_batch` 扣减 `REALTIME_ALERT_POOL` 及 `consume_tenant_quota` 严格同序）；
     - **Layer 3**：`write_transaction(db_path)`（获取 `hub.sqlite_write_lock` 后立即执行 `BEGIN IMMEDIATE`，绝不在持有 SQLite 写事务期间反向请求任何 Python 业务锁）。
3. **四位一体强原子提交与逆序回滚（`aegis_app/rule_engine.py` 中 `evaluate_transaction_batch`）**：
   - 阶段 1 在无锁状态下完成整批字段类型、严格整数边界、无回溯邮箱、元数据体积与批内重复 `tx_id` 校验；
   - 阶段 2 按 `Layer 1 -> Layer 2 (REALTIME_ALERT_POOL) -> Layer 3 (BEGIN IMMEDIATE)` 加锁后，预检存量 `transactions` / `risk_decisions` 主键冲突，逐笔推进 `TenantContagionGraph` 与 `AccountWindowTracker` 并记录精确插入位置撤销日志 `graph_undo_log` 与 `window_undo_log`，在事务末尾一次性 `executemany` 落盘并更新 `REALTIME_ALERT_POOL`；
   - 一旦批次内任一笔触发校验异常、数值溢出或主键冲突，`write_transaction` 立即 `ROLLBACK` 数据库与配额变更，同时 `except BaseException` 块严格按**逆序**调用 `tracker.undo_insert(w_pos)` 与 `state.graph.undo_insert(g_pos)`（并清理新建空账户追踪器），实现**数据库、滑动窗口、三跳传染图与实时告警配额池**四位一体零残留强原子回滚。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

1. **五维独立纪元解耦（`aegis_app/db.py` 中 `TenantEpochs`）**：
   - 每个租户独立维护 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch` 五个正交纪元计数器：
     - 修改 `/api/v1/admin/doc-acl` 仅递增 `acl_epoch` 刷新 `TenantAclSnapshot`（**绝不清空或重建 `TenantDocIndex` 文档倒排索引**）；
     - 角色授撤与借调变更仅递增 `perm_epoch` 刷新 `TenantPermSnapshot`；
     - 文档 `upsert`/`quarantine`/`retire` 在 `tenant_doc_lock` 内递增 `doc_epoch` 并原地单篇增量演进索引；
     - 策略与制裁名单更新分别仅递增 `policy_epoch` 与 `sanction_epoch`。
2. **二级受控转借调时效窗口、上游到期零写降级、源头撤权级联失效与防环路（`aegis_app/delegation.py`、`acl_wall.py`）**：
   - `TenantPermSnapshot` 预计算组织上溯链 `org_lineage`（带 `seen_nodes` 防环）与活跃操作员原生角色集 `native_roles`；
   - `resolve_delegated_roles_at(grantee_user_id, at_ts)` 在内存中执行带路径集合 `path_seen` 去重、深度硬限 `MAX_DELEGATION_HOPS = 2` 的逆向搜索：要求每一跳均满足 `starts_at <= at_ts < expires_at`、中间受托人与源头委托人均 `active=1` 且源头当前持有该原生角色。当上游一级借调跨过 `expires_at` 时，读路径条件自动不成立，实现**零数据库写入秒级自动降级**；当源头被 `grants/revoke` 撤权时，`perm_epoch` 递增使下游 1~2 跳受托资格立即级联失效；
   - 在写入口 `create_or_revoke_delegation` 中通过 `has_overlapping_cycle`（BFS 检测重叠时间窗 `[max(s1,s2) < min(e1,e2)]` 有向可达性）直接以 400 拒绝有向委托环路写入，且读路径同样通过 `path_seen` 与 2 跳上界双重免疫存量环路死循环；
   - `TenantAclSnapshot.is_blocked` 严格按「个人显式 `ALLOW` > 个人显式 `DENY` > 组织树由近及远首个有规则节点（同节点 `DENY` 优先于 `ALLOW`） > 默认放行」三级优先级在纳秒级内存字典上完成裁决。

---

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

1. **一阶与双通道跨模块二阶 SQL 注入全面根除**：
   - **一阶注入**：`aegis_app/search_service.py` 彻底移除 `tenant_id`、`tag_filter`、`sort_by`、`sort_dir` 的字符串拼接 SQL，改为内存倒排精确匹配 + 严格排序字段/方向白名单校验（非法字段直接返回 400）。
   - **二阶注入通道 1（文档内部引用 `doc_`）**：原版 `search_service.py` 从 `doc_citations` 取出 `cited_by_ref` 后直接拼接 `f"WHERE doc_id = '{ref}'"`；重构后在 `TenantDocIndex` 内存引用图与参数化加载中完全消除动态 SQL 拼接。
   - **二阶注入通道 2（审计报表模板 `extra_event_filter`）**：原版 `audit_export.py` 在 `render_saved_report` 中直接拼接 `tpl['extra_event_filter']`；重构后在 `save_report_template` 与 `render_saved_report` 双端执行正则白名单 `^[A-Z][A-Z0-9_]{1,63}$` 校验，并在查询中使用 `?` 参数化绑定。
2. **报表模板沙箱：废除 `str.format`，阻断属性反射泄密与 `:0>200000` 宽度放大（`aegis_app/audit_export.py`）**：
   - 彻底移除 `str.format(..., env=RUNTIME_ENV)` 调用，编写纯字符扫描解析器 `_parse_safe_title_template` 与 `_render_safe_title`，仅允许 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个精确字面占位符（支持 `{{`/`}}` 转义），任何属性访问（如 `{env.master_pepper}`）、下标访问或格式说明符（如 `{tenant_id:0>200000}`）在保存与渲染双阶段均立即抛出 `ValueError`（400）。
3. **诊断后门清理、异常脱敏与多维越权/侧信道封堵**：
   - `aegis_app/server.py` 移除 `/api/v1/health?debug=1` 诊断泄露分支与未授权 `/api/v1/internal/diagnostics` 路由，净化 500 异常响应（绝不回显 `db_path`、`storage_dir`、`MASTER_SIGNING_PEPPER` 或堆栈），并将 `middleware.collect_internal_diagnostics` 脱敏为纯存活摘要；
   - `aegis_app/search_service.py` 中 `batch_get_documents` 强制核验 `tenant_id = ?`、`status = 'ACTIVE'`、`quarantined = 0`、实时有效密级 `clearance_level <= live_clearance` 及三级利益冲突隔离墙 `acl_snap.is_blocked`；`doc_writer.py` 更新存量文档时同步核验租户归属、密级与隔离墙；
   - `aegis_app/rule_engine.py` 中 `get_risk_decision_detail` 增加 `AND tenant_id = ?` 阻断跨租户风控决策越权读取；
   - `aegis_app/doc_indexer.py` 中 `active_ref_sources` 严格限定为同租户内部活跃未隔离文档，彻底阻断通过跨租户 `doc_` 引用探测其他租户文档存在性与隔离状态的侧信道预言机；
   - `aegis_app/auth.py` 在未知/停用租户与未知/停用操作员分支统一执行 `_DUMMY_TOKEN_HASH` / `_DUMMY_WEBHOOK_SECRET` + `hmac.compare_digest` 常量时间掩蔽，消除认证耗时侧信道；
   - `aegis_app/audit_export.py` 中 `read_compliance_snapshot` 拒绝 `%`（双重编码）、空字节、`/`、`\`、`:`（盘符与 NTFS 备选数据流）、`..` 及符号链接 `is_symlink()`，并通过 `resolve()` + `target_path.parent == base_dir` + `is_relative_to(base_dir)` 严格锚定租户快照目录。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

1. **清算 Webhook 验签、时间窗与并发原子防重放（`aegis_app/auth.py`、`db.py`）**：
   - `process_settlement_webhook` 使用 `hmac.compare_digest` 校验签名，强制核验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS (300s)`，并通过 `write_transaction`（`BEGIN IMMEDIATE`）内查重 + `webhook_events(tenant_id, nonce)` 唯一索引双重保障高并发下重复 Nonce 严格仅入账一次（重放返回 409）。
2. **消除回溯正则与自定义规则 `REGEX` 语法树沙箱（`aegis_app/rule_engine.py`）**：
   - 将灾难性回溯的 `PARTNER_EMAIL_PATTERN` 重写为等价的线性无回溯正则 `^[a-zA-Z0-9]+(?:[._-][a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$`（限制长度 $\le 254$）；
   - 通过 `re._parser.parse` 构建 `_inspect_regex_ast` 静态 AST 审计器（配合 `@lru_cache(maxsize=256)` 缓存 `compile_safe_regex`），在编译前毫秒级拦截嵌套量词（如 `(a+)+$`）、零宽重复、量词内重叠首字符分支（如 `(a|aa)+$`）、反向引用（`\1`、`(?P=...)`）、环视断言、大上界花括号重复（`> 64`，如 `a{1,50000}`）及多段通配符链。
3. **JSON 预检深度、规则/查询/引用预算与严格类型守卫（`aegis_app/middleware.py`、`rule_engine.py`）**：
   - `_precheck_json_structure` 在调用 `json.loads` **之前**单遍扫描原始文本拦截嵌套深度 `> 32`、容器节点 `> 50000` 或体积 `> 2MB` 的畸形载荷，并传入 `parse_constant=_reject_json_constant` 拒绝 `NaN`/`Infinity`（对进程内 `dict` 直传同步执行 `_validate_python_payload_tree` 与 `allow_nan=False`）；
   - `validate_rule_tree` 限制规则树深度 $\le 16$、总节点 $\le 256$、`IN` 列表 $\le 256$；文档引用限制 $\le 256$ 条、查询词项 $\le 64$ 个、`batch-get` $\le 200$ 篇、交易批次 $\le 500$ 笔；
   - `strict_int` 显式拦截 `isinstance(value, bool)`（防止 Python 中 `True/False` 被当作 `1/0` 混入金额、配额、密级、时间戳）、`float`、非数字串以及超出 SQLite 64 位有符号整数 `[-(1<<63), (1<<63)-1]` 范围的超大整数，杜绝类型混淆与底层 `OverflowError` 500 崩溃。

---

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/doc_indexer.py` 中，`DocIndexNode` 采用 `__slots__` 仅保存 140 字符 `snippet` 与 `array('H'/'I')` 词位置数组而不常驻原始 `body`；`TenantDocIndex` 通过 `apply_upsert`、`apply_quarantine`、`apply_retire` 实现单篇增量倒排更新，并借助内存反向引用表 `reverse_dependents` 在 `_update_ref_source_availability` 中以 $O(\text{deg})$ 局部联动更新被引用文档计数；`compute_proximity_from_positions` 实现双指针词距扫描并在 `min_dist == 1` 时立即早停；`aegis_app/search_service.py` 的 `search_documents` 按 `canon_reg` 分桶并执行 `(min_l / max_l) < DEDUP_JACCARD_THRESHOLD` 比值剪枝；`aegis_app/window_stats.py` 的 `DualHeapWindow` 与 `AccountWindowTracker` 实现 $O(\log W)$ 精确动态中位数且通过 `bisect_left`/`bisect_right` 兼容乱序时间戳；`aegis_app/contagion_graph.py` 的 `TenantContagionGraph.query_hop` 实现双向前沿折半三跳追踪；`aegis_app/audit_export.py` 的 `_stream_audit_digest` 使用 `fetchmany(512)` 游标流式摘要。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/db.py` 的 `TenantEpochs` 中将租户状态解耦为 `doc_epoch`、`acl_epoch`、`perm_epoch`、`policy_epoch`、`sanction_epoch` 五个独立计数器，使得 `aegis_app/acl_wall.py` 的 `upsert_doc_acl_rule` 仅递增 `acl_epoch` 刷新 `TenantAclSnapshot` 而不触碰 `TenantDocIndex`；在 `aegis_app/delegation.py` 的 `TenantPermSnapshot.resolve_delegated_roles_at` 中支持最多 2 跳受控借调链时效窗口核验（上游跨过 `expires_at` 读路径零写自动降级、源头撤权随 `perm_epoch` 级联失效，并通过 `path_seen` 免疫环路），同时在 `create_or_revoke_delegation` 中调用 `has_overlapping_cycle` 拦截重叠窗口有向环路。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/db.py` 的 `DbRuntimeHub`、`aegis_app/ledger_ops.py` 的 `transfer_tenant_quota`/`consume_tenant_quota` 与 `aegis_app/rule_engine.py` 的 `evaluate_transaction_batch` 中，严格按 `Layer 1: tenant_risk_lock -> Layer 2: quota_locks（按哈希条带下标升序去重加锁） -> Layer 3: write_transaction（sqlite_write_lock + BEGIN IMMEDIATE）` 全局偏序加锁；当批次评估任意环节抛错或主键冲突时，`write_transaction` 原子回滚 SQLite 写入与 `REALTIME_ALERT_POOL` 配额扣减，`evaluate_transaction_batch` 的异常处理块逆序执行 `window_undo_log`（`AccountWindowTracker.undo_insert`）与 `graph_undo_log`（`TenantContagionGraph.undo_insert`），确保数据库、滑窗、传染图与告警配额四位一体零泄漏回滚。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/audit_export.py` 中，`save_report_template` 与 `render_saved_report` 双端使用 `_SAFE_EVENT_FILTER_RE` 校验事件名并以 `event_type = ?` 参数化查询，同时以纯字符解析器 `_parse_safe_title_template` / `_render_safe_title` 替代 `str.format`，仅放行 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 字面占位符；`read_compliance_snapshot` 拦截编码/分隔符变体并用 `resolve()` + `is_relative_to(base_dir)` 锚定路径；`aegis_app/search_service.py` 的 `batch_get_documents` 强制校验本租户、`ACTIVE`、未隔离、实时密级与隔离墙，且 `TenantDocIndex` 仅计入本租户活跃内部 `doc_` 引用；`aegis_app/rule_engine.py` 的 `get_risk_decision_detail` 强制校验 `decision_id = ? AND tenant_id = ?`；`aegis_app/auth.py` 对未知租户/用户与回调验签统一执行常量时间 dummy 掩蔽并强制校验 `±300s` 窗口与原子 Nonce 防重放。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/middleware.py` 中，`_precheck_json_structure` 在 `json.loads` 之前单遍预检括号嵌套深度（`<= 32`）与容器预算并通过 `_reject_json_constant` 拦截 `NaN`/`Infinity`，`strict_int` 与 `strict_bool` 全局拒绝 `bool` 混充整数、浮点数与超 64 位整数；在 `aegis_app/rule_engine.py` 中，`PARTNER_EMAIL_PATTERN` 消除嵌套量词回溯，`_inspect_regex_ast` 基于 `re._parser` 拦截嵌套量词、反向引用、环视、歧义分支及 `> 64` 的花括号重复上界，`validate_rule_tree` 硬限规则树深度 `<= 16` 与节点数 `<= 256`。

---

## 5. 已知工程取舍与残余边界说明

1. **单进程内存索引与多进程部署边界**：当前五维解耦纪元、`TenantDocIndex` 增量倒排索引及 `TenantRiskRuntimeState` 滑窗/传染图针对评测契约的单网关实例多线程并发模型做了极致内存驻留优化；若未来扩展至多进程共享同一 SQLite 文件，需将纪元号持久化至 SQLite 共享状态表以便跨进程感知失效。
2. **SQLite 单写者物理串行边界**：在开启 WAL 模式后读操作已完全无锁并发，但 SQLite 底层同一时刻仍仅允许单一写事务提交；本实现通过预计算与预校验将所有非 I/O 逻辑移出 `write_transaction`，并用 `executemany` 合并批次写入，将单次写锁持有时间压缩至亚毫秒级。
3. **乱序交易历史保留取舍**：为支持任意跨度的乱序/回补时间戳 `ts` 在滑动窗口与三跳传染图上实现 100% 精确回退定位，内存按每笔仅存 `(ts, amount_cents, counterparty_id)` 与 `(ts, u, v)` 紧凑标量序列（不保留 `metadata_json` 等大字段），在确保乱序零失真的同时保持极低内存占用。
