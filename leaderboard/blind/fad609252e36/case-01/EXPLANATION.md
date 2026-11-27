# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
通过对 `aegis_app/` 全部 16 个源码模块的逐行剖析，定位并根治了以下存储与 I/O 层瓶颈：
1. **高频重复建连与缺省事务同步开销**：原版 `aegis_app/db.py` 的 `open_connection()` 每次调用均执行全新 `sqlite3.connect()` 并在用后销毁；在单次 `/api/v1/docs/search` 或 `/api/v1/risk/evaluate-batch` 请求中，跨模块循环反复打开关闭数十至数百次连接。重构后在 `aegis_app/db.py` 中实现了按规范化数据库路径隔离的有界 LIFO 连接池（`_PooledConnection`，单库上限 16 连接，支持异常/关闭时自动检查 `in_transaction` 并安全 `rollback` 归还），统一开启 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL`、`temp_store=MEMORY`、`cache_size=-16000` 与 `busy_timeout=30000`。
2. **全表缺索引导致的线性扫描**：原版 `SCHEMA_SQL` 除主键外无任何二级或复合索引。重构后在 `aegis_app/db.py` 的 `SCHEMA_SQL` 中新增 20 项高频访问路径复合索引与唯一约束索引（包括 `idx_docs_tenant_status`、`idx_citations_tenant_doc`、`idx_citations_tenant_ref`、`idx_doc_acl_tenant_doc`、`idx_delegation_grantee`、`idx_tx_tenant_acct_ts`、`idx_audit_tenant_ts_log` 以及防并发重放唯一索引 `idx_webhook_tenant_nonce`）。
3. **跨模块循环内 N+1 查询与逐笔落盘放大**：
   - 原版 `aegis_app/search_service.py` 在遍历候选文档循环内逐篇调用 `resolve_effective_permissions()`、`is_doc_blocked_by_acl()` 和 `_get_doc_citation_count()`，而下层 `delegation.py` 与 `acl_wall.py` 又在递归/循环内逐跳开启连接查表。重构后通过五维解耦纪元驱动的内存快照（`TenantAuthSnapshot`、`_TenantAclSnapshot`、`TenantDocIndex`），将单次检索期间的 SQLite 查询次数降至 **0 次**。
   - 原版 `aegis_app/rule_engine.py` 在 `evaluate_transaction_batch()` 循环内逐笔全表扫描 `transactions` 两次并逐笔执行两次独立 `commit()`。重构后将整批交易的数据库写入合并至单个 `BEGIN IMMEDIATE` 事务内通过 `executemany()` 一次性批量落盘。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
1. **紧凑单篇增量倒排索引与 $O(\text{deg})$ 双向引用传播（`aegis_app/doc_indexer.py`）**：
   - **常驻堆内存压缩**：`DocIndexNode` 与 `TenantDocIndex` 全面采用 `__slots__` 消除实例 `__dict__` 开销；节点内**绝不常驻完整原始大正文 `body`**，仅保留 140 字符摘要 `snippet = body[:140]`、标题词频 `title_tf`、正文词项升序位置元组映射 `body_positions: dict[str, tuple[int, ...]]`（元组长度直接复用为正文词频 `body_tf`）以及去重词集 `dedup_tokens: frozenset[str]`。完整正文仅在 `/api/v1/docs/batch-get` 时按主键按需参数化回表读取。
   - **单篇增量更新与反向引用图局部传播**：`TenantDocIndex` 维护词项倒排表 `inverted_index: dict[str, set[str]]` 与内部引用反向依赖图 `reverse_dependents: dict[str, set[str]]`（记录每个内部 `doc_X` 被本租户哪些文档所引用）。当执行 `docs/upsert`、`docs/retire` 或 `docs/quarantine` 时，仅通过 `upsert_single_doc()` 或 `update_doc_state()` 对单篇文档的倒排词条做 $O(|T_{\text{doc}}|)$ 增量增删，并沿 `reverse_dependents[doc_id]` 对引用了该文档的直接邻居执行 $O(\text{deg}(doc\_id))$ 局部有效引用计数重算，彻底消除整表重查与整租户索引推倒重建。
2. **短语词距邻近度双指针早停（`aegis_app/doc_indexer.py`）**：
   - 改进前：每次检索对正文分词列表做全量扫描，并用双重循环 $O(|P_a| \times |P_b|)$ 枚举下标差。
   - 改进后：`compute_proximity_bonus_from_positions()` 直接读取预构建的升序位置元组 `pos_a` 与 `pos_b`，采用双指针线性扫描，时间复杂度降至 $O(|P_a| + |P_b|)$，且一旦发现理论下界 `min_dist == 1` 立即 `break` 早停。
3. **双轨法规近似去重比值剪枝（`aegis_app/doc_indexer.py`）**：
   - 改进前：在二重循环中重复对两篇文档拼接标题与全文分词，再通过列表线性查重计算交并集，单次比对耗时 $O(L^2)$。
   - 改进后：`jaccard_similarity_from_token_sets()` 直接复用节点预计算的 `dedup_tokens: frozenset[str]`，并在求集合交集前先校验集合大小比值上界 `min_l / max_l < threshold (0.70)`；若不满足上界直接 $O(1)$ 剪枝跳过，交集计算复杂度降至 $O(\min(|A|, |B|))$。
4. **滑动窗口 $O(\log W)$ 动态中位数与乱序时间戳兼容（`aegis_app/window_stats.py`）**：
   - 改进前：每笔交易全表扫描 `transactions` 并对所有历史记录反序列化 `metadata_json`，再用 $O(W^2)$ 冒泡排序计算中位数。
   - 改进后：`AccountWindowTracker` 为每个账户维护按时间戳排序的 `all_events`、活跃双端队列 `win_deque`、窗口金额累加和 `win_sum`、对手方引用计数表 `cp_counts` 以及有序金额数组 `sorted_amounts`。在单调时间流（`ts >= max_ts`）下通过 `win_deque.popleft()` 滑出过期项、用 `bisect.insort` / `bisect_left` 维护有序金额数组并以 $O(1)$ 下标读取精确中位数，单笔维护复杂度从 $O(N_{\text{tx}} + W^2)$ 降至 $O(\log W)$；当遇到乱序时间戳（`ts < max_ts`）时，自动回退至 `all_events` 上的 `bisect` 二分范围切片 `[ts - 86400, ts]`，确保乱序场景下输出与原版 100% 零失真。
5. **三跳受制裁实体传染增量邻接表与两步邻域交集（`aegis_app/contagion_graph.py`）**：
   - 改进前：每笔交易全表查询 `transactions` 重建邻接表，并从所有受制裁节点执行 `list.pop(0)` 广度优先搜索，单笔耗时 $O(N_{\text{tx}} + |S| \cdot (|V| + |E|))$。
   - 改进后：`TenantContagionGraph` 在内存中维护 24 小时活跃边队列 `edge_deque` 与带引用计数的无向邻接表 `adj_counts`。利用三跳无向最短路对称性：先判定端点是否直接命中活跃制裁集 $S$（`hop = 1`），再收集 $S$ 的一跳邻居集合 $N_1(S)$；若交易任一端点属于 $N_1(S)$ 则 `hop = 2`；若交易任一端点的邻居集合与 $N_1(S)$ 相交则 `hop = 3`，否则为 `0`。单笔查询复杂度降至 $O(|S| \cdot \bar{d})$。
6. **流式游标审计摘要导出（`aegis_app/audit_export.py`）**：
   - 改进前：`_compute_digest_from_records()` 使用 `fetchall()` 拉取全表（含大字段 `payload_json`），逐行 `json.loads()` 并执行两次全量 `copy.deepcopy()`，空间复杂度 $O(N_{\text{audit}})$。
   - 改进后：`_stream_audit_digest_query()` 在 SQL 层剔除无关列 `payload_json` 与 `actor_id`，使用 `cur.fetchmany(512)` 分块流式扫描并在线更新 `hashlib.sha256()` 与前 `capped_sample (<= 50)` 条样本，常驻内存空间复杂度从 $O(N_{\text{audit}})$ 降至 **$O(1)$**。

---

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
1. **摒弃全局大锁，实行租户与子域细粒度锁隔离（`aegis_app/db.py`）**：
   - 所有锁均按 `(normalized_db_path, tenant_id, domain)` 细粒度划分（`risk`、`doc`、`auth`、`acl`、`token`、`webhook` 及配额池锁 `(db_key, tenant_id, quota_type)`），不同租户之间的读写以及同租户不相关子域（如文档检索与配额扣减）完全并行无阻塞。
2. **全局三级严格锁偏序（Global Lock Partial Order）**：
   - **Level-1**：租户风控评估锁 `get_tenant_risk_lock(db_path, tenant_id)`（仅 `evaluate_transaction_batch` 等风控写路径获取）；
   - **Level-2**：配额池细粒度锁 `acquire_quota_locks(db_path, tenant_id, *quota_types)`，内部强制对涉及的所有 `quota_type` 去重并按**字典序升序（`sorted`）**依次加锁、逆序释放；
   - **Level-3**：SQLite 写事务锁 `conn.execute("BEGIN IMMEDIATE")`。
   - **无死锁铁律**：任何路径严禁在开启 `BEGIN IMMEDIATE` 之后再去反向申请 Python 层锁。在双向交叉调拨（`transfer(A->B)` 与 `transfer(B->A)`）及并发 `evaluate_transaction_batch`（扣减 `REALTIME_ALERT_POOL`）同时进行时，所有线程均按相同字典序获取配额池锁后再进入 `BEGIN IMMEDIATE`，从拓扑上彻底消除了环路等待与跨层死锁。
3. **交易批次四位一体强原子提交/回滚（`aegis_app/rule_engine.py`）**：
   - `evaluate_transaction_batch()` 首先对全批次做完整静态校验与批内重复 `tx_id` 检查；随后按 `Level-1 -> Level-2 (REALTIME_ALERT_POOL) -> Level-3 (BEGIN IMMEDIATE)` 加锁，预检数据库中是否存在任一 `tx_id` 或 `decision_id` 冲突，并在局部变量 `staged_alert_quota` 中暂存告警配额余额。
   - 逐笔评估过程中，`TenantContagionGraph.stage_and_evaluate()` 与 `AccountWindowTracker.stage_and_query()` 每一步内存状态变更均向 `undo_log` 压入精确逆向回滚闭包。
   - 若批次内任一笔交易触发异常或冲突，`except` 块立即执行 `conn.rollback()` 回滚 SQLite 事务（零交易落盘、零 `REALTIME_ALERT_POOL` 配额扣减），并逆序执行 `undo_log` 中的全部撤销闭包，将内存滑动窗口与三跳传染图精确恢复至批次前状态。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
1. **五维物理分离纪元（`TenantEpochs` in `aegis_app/db.py`）**：
   - 为每个租户独立维护 `doc_epoch`、`acl_epoch`、`auth_epoch`、`policy_epoch`、`sanction_epoch` 五个单调递增计数器：
     - 修改单条利益冲突墙规则（`upsert_doc_acl_rule`）仅递增 `acl_epoch`，仅刷新 `_TenantAclSnapshot.verdict_cache`，**绝不触发 `TenantDocIndex` 文档倒排索引清空或重建**；
     - 角色授予/撤回或借调变更仅递增 `auth_epoch`；
     - 风控策略更新仅递增 `policy_epoch`；
     - 制裁黑名单变更仅递增 `sanction_epoch` 并同步更新内存集合。
2. **二级受控借调时效边界窗口缓存与零写自然过期降级（`aegis_app/delegation.py`）**：
   - `TenantAuthSnapshot` 在内存中收集当前租户全部有效借调记录的 `starts_at` 与 `expires_at` 时间戳，构建有序边界元组 `window_boundaries`。
   - `resolve_cached_effective_permissions()` 在评估时刻 `eval_ts` 利用 `bisect.bisect_right(window_boundaries, eval_ts)` 切出当前时刻所属的恒定权限时间区间 `[v_from, v_until)`，并将 `(v_from, v_until, effective_roles, max_clearance)` 缓存于 `perm_window_cache[user_id]`。
   - 当请求时间仍在 `[v_from, v_until)` 内时直接 $O(1)$ 命中返回；一旦时间跨过上游一级借调或自身二级借调的 `expires_at`（即 `eval_ts >= v_until`），缓存条件自动失效并在内存中重算借调链，实现**上游窗口自然到期零数据库写操作自动降级**；当源头委托人被撤回角色时，`bump_auth_epoch` 使快照立即刷新，下游 1~2 跳受托资格同步级联失效。
   - 在借调回溯（`_collect_upstream_grantors_from_snap`）与创建（`_would_create_delegation_cycle`）中同时植入 `visited` 集合与 `depth < MAX_DELEGATION_HOPS (2)` 硬上界，彻底免疫有向借调环路死循环。

---

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
1. **一阶与双通道跨模块二阶 SQL 注入根治**：
   - **检索一阶注入（`aegis_app/search_service.py`）**：对 `sort_by`（白名单 `score`/`updated_at`/`risk_weight`）与 `sort_dir`（白名单 `asc`/`desc`）执行严格枚举校验，移除拼接 SQL，改由内存倒排索引精确匹配 `category` 与 `custom_tag`。
   - **通道一 · 文档内部引用二阶注入与跨租户侧信道（`aegis_app/doc_indexer.py` & `doc_writer.py`）**：原版 `_get_doc_citation_count` 将落库的 `cited_by_ref` 用 `f"WHERE doc_id = '{ref}'"` 拼接查询且未限定 `tenant_id`，既存在二阶 SQL 注入，又允许攻击者通过引用其他租户文档 ID 探测其是否存在及是否被隔离。重构后所有引用写入均使用参数化查询，且内部 `doc_` 引用计数仅在当前租户自身的 `TenantDocIndex.docs` 字典中按精确键查找并核验 `status == 'ACTIVE' and not quarantined`，彻底阻断二阶注入与跨租户状态侧信道。
   - **通道二 · 审计报表模板 `extra_event_filter` 二阶注入（`aegis_app/audit_export.py`）**：在 `save_report_template()` 与 `render_saved_report()` 中双重校验 `_VALID_EVENT_FILTER_RE`（`^[A-Z][A-Z0-9_]{1,31}$`），并在 `render_saved_report()` 中改用全参数化查询 `WHERE tenant_id = ? AND event_type = ?`。
2. **报表模板格式化反射与宽度放大阻断（`aegis_app/audit_export.py`）**：
   - 彻底移除 `str.format()` 调用及 `env=RUNTIME_ENV` 参数暴露。在 `_validate_title_format()` 中通过 `_VALID_PLACEHOLDER_RE`（仅匹配字面 `{tenant_id}`、`{total_records}`、`{total_amount_cents}`）剥离合法占位符后，拒绝任何残留 `{` 或 `}` 的模板（直接拦截 `{env.master_pepper}` 属性反射与 `{tenant_id:0>200000}` 宽度填充放大），并在 `_render_safe_title()` 中使用正则字面替换完成渲染。
3. **多变体目录穿越阻断（`aegis_app/audit_export.py`）**：
   - `read_compliance_snapshot()` 对 `snapshot_name` 执行最多 3 轮循环 `urllib.parse.unquote()` 解码，拒绝包含 `..`、`/`、`\`、`:`、`\x00` 或不符合 `^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.json$` 白名单的名称，拒绝符号链接（`is_symlink()`），并通过 `pathlib.Path.resolve()` 严格校验 `target_path.parent == base_dir` 与 `target_path.is_relative_to(base_dir)`。
4. **多维越权（IDOR / 密级 / 隔离墙）与诊断泄密修复**：
   - `/api/v1/docs/batch-get`（`aegis_app/search_service.py`）：补齐 `tenant_id = ?`、`status = 'ACTIVE'`、`quarantined = 0`、`clearance_level <= live_clearance` 以及 `not is_doc_blocked_by_acl()` 全套校验。
   - `/api/v1/risk/decisions/<id>`（`aegis_app/rule_engine.py`）：校验 `row["tenant_id"] == caller.tenant_id`，阻断跨租户决策详情越权读取。
   - `/api/v1/health`、`/api/v1/internal/diagnostics` 与异常捕获（`aegis_app/server.py` & `middleware.py`）：移除未授权内部诊断路由与 `debug=1` 诊断输出，屏蔽 500 响应中的 `debug_context`、`MASTER_SIGNING_PEPPER`、物理路径与堆栈回溯。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
1. **常量时间验签、Dummy 掩蔽与 Webhook 并发防重放（`aegis_app/auth.py`）**：
   - `authenticate_caller()` 与 `process_settlement_webhook()` 统一使用 `hmac.compare_digest()`；当租户或用户不存在/停用时，仍对 `_DUMMY_TOKEN_HASH` 或 `_DUMMY_WEBHOOK_SECRET` 执行一次常量时间摘要比对，消除未知租户/用户探测的时序侧信道。
   - `process_settlement_webhook()` 严格校验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS (300)`，并通过 `get_tenant_webhook_lock` + `BEGIN IMMEDIATE` + 数据库唯一索引 `idx_webhook_tenant_nonce` 拦截串行与高并发重复 Nonce 重放。
2. **毫秒级抗复杂度炸弹熔断**：
   - **邮箱与自定义规则 ReDoS 防护（`aegis_app/rule_engine.py`）**：将 `PARTNER_EMAIL_PATTERN` 重写为无回溯歧义的线性时间正则；新增 `validate_safe_regex_pattern()` 静态扫描括号分组栈，毫秒级拒绝嵌套量词（如 `(a+)+`）、带量词分支（如 `(a|aa)+`）、花括号大上界（`> 32`）、反向引用（`\1`）及后行断言。
   - **JSON 解析前嵌套深度预检（`aegis_app/middleware.py`）**：在调用 `json.loads()` **之前**，通过 `_precheck_json_depth()` 对原始 JSON 字符串执行单遍状态机扫描（深度上限 `MAX_JSON_DEPTH = 24`、体积上限 `512 KB`），杜绝深层嵌套触发 `RecursionError`。
   - **规则树与引用洪水预算（`aegis_app/rule_engine.py` & `doc_writer.py`）**：`validate_rule_tree()` 限制最大深度 12、最大节点数 128、单节点扇出 32 及环路检测；`_validate_citations()` 限制单篇引用数 `<= 128`、单条长度 `<= 128`。
3. **严格整数与布尔类型守卫（`aegis_app/middleware.py`）**：
   - `strict_int()` 显式拦截 `isinstance(val, bool)`（防止 Python 中 `True == 1` / `False == 0` 混淆）、浮点数、非数字字符串以及超出 64 位有符号整数范围 `[-2^63, 2^63 - 1]` 的超大整数；`json.loads` 绑定 `parse_constant=_reject_nonfinite_constant` 并在规则比较中通过 `math.isfinite()` 彻底拒绝 `NaN` 与 `±Infinity`。

---

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/doc_indexer.py` 中，`DocIndexNode` 与 `TenantDocIndex` 均使用 `__slots__` 且仅保存 140 字符 `snippet`（不驻留原始 `body`），通过 `TenantDocIndex.upsert_single_doc()`、`update_doc_state()` 与 `_propagate_reverse_dependents()` 利用反向引用图 `reverse_dependents` 实现单篇增量倒排更新与 $O(\text{deg})$ 引用计数局部传播；`compute_proximity_bonus_from_positions()` 实现升序位置双指针线性扫描并在 `min_dist == 1` 时早停，`jaccard_similarity_from_token_sets()` 实现 `min_l / max_l < threshold` 集合大小比值剪枝；在 `aegis_app/window_stats.py` 的 `AccountWindowTracker.stage_and_query()` 中实现基于 `bisect.insort` 的 $O(\log W)$ 单调滑动窗口动态中位数维护及乱序时间戳二分切片回退；在 `aegis_app/contagion_graph.py` 的 `TenantContagionGraph.stage_and_evaluate()` 中实现基于 24 小时活跃边队列与一跳邻居集 $N_1(S)$ 交集的三跳传染增量判定；在 `aegis_app/audit_export.py` 的 `_stream_audit_digest_query()` 中通过 `cur.fetchmany(512)` 实现 $O(1)$ 内存流式摘要计算。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/db.py` 的 `TenantEpochs` 中将 `doc_epoch`、`acl_epoch`、`auth_epoch`、`policy_epoch`、`sanction_epoch` 五维物理分离，`aegis_app/acl_wall.py` 的 `upsert_doc_acl_rule()` 仅调用 `bump_acl_epoch()` 刷新 `_TenantAclSnapshot`，绝不触发 `TenantDocIndex` 重建；在 `aegis_app/delegation.py` 的 `TenantAuthSnapshot`、`resolve_cached_effective_permissions()`、`_collect_upstream_grantors_from_snap()` 与 `_would_create_delegation_cycle()` 中实现基于 `window_boundaries` 二分切分的 `[v_from, v_until)` 时效窗口权限缓存（上游一级窗口自然过期时零写操作自动失效降级，源头撤权通过 `bump_auth_epoch()` 级联失效）及 `MAX_DELEGATION_HOPS = 2` 与 `visited` 集合防环路保护。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/db.py` 的 `get_tenant_risk_lock()` 与 `acquire_quota_locks()` 中建立 `Level-1 (tenant_risk_lock) -> Level-2 (按 quota_type 字典序排序的配额池锁) -> Level-3 (SQLite BEGIN IMMEDIATE)` 全局严格锁偏序，应用于 `aegis_app/ledger_ops.py` 的 `transfer_tenant_quota()`、`consume_tenant_quota()` 与 `aegis_app/rule_engine.py` 的 `evaluate_transaction_batch()`；当 `evaluate_transaction_batch()` 内任一笔交易校验失败或主键冲突时，通过 `conn.rollback()` 与逆序执行 `undo_log` 闭包，实现数据库、滑动窗口（`AccountWindowTracker`）、三跳传染图（`TenantContagionGraph`）与 `REALTIME_ALERT_POOL` 配额池的四位一体强原子回滚。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/doc_indexer.py` 的 `TenantDocIndex._recompute_node_citations()` 与 `aegis_app/doc_writer.py` 中对文档引用实行全参数化落库，且内部 `doc_` 引用仅匹配本租户 `self.docs` 中 `status == 'ACTIVE' and not quarantined` 的节点，阻断引用通道二阶注入与跨租户状态侧信道；在 `aegis_app/audit_export.py` 的 `_validate_title_format()`、`_render_safe_title()` 与 `render_saved_report()` 中通过 `_VALID_PLACEHOLDER_RE` 字面正则替换（零 `str.format` 调用）及 `_VALID_EVENT_FILTER_RE` + 参数化 `event_type = ?` 阻断模板反射、宽度放大与二阶 SQL 注入；在 `read_compliance_snapshot()` 中实现多轮 `unquote`、白名单正则与 `Path.resolve()` 目录锚定；在 `aegis_app/search_service.py` 的 `batch_get_documents()` 与 `aegis_app/rule_engine.py` 的 `get_risk_decision_detail()` 中严格强制租户、状态、隔离、密级与利益冲突墙边界。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/middleware.py` 的 `_precheck_json_depth()` 中于 `json.loads()` 前执行原始 JSON 字符串括号嵌套深度预检（`<= 24`），在 `strict_int()` 与 `strict_bool()` 中严格拦截 `bool` 冒充整数、浮点数、`NaN`/`Infinity` 及超 64 位整数；在 `aegis_app/rule_engine.py` 的 `PARTNER_EMAIL_PATTERN`、`validate_safe_regex_pattern()` 与 `validate_rule_tree()` 中拦截回溯正则、嵌套/分支量词、花括号大上界（`> 32`）、反向引用及超深/超宽规则树；在 `aegis_app/auth.py` 的 `authenticate_caller()` 与 `process_settlement_webhook()` 中实现未知租户/用户 Dummy 常量时间掩蔽、`±300s` 时间窗校验及并发 Nonce 防重放。

---

## 5. 已知工程取舍与残余边界说明
1. **单进程内存索引与多进程扩展边界**：当前五维纪元（`TenantEpochs`）、增量文档索引（`TenantDocIndex`）、滑动窗口（`TenantWindowState`）与传染图（`TenantContagionGraph`）驻留于单机网关进程内存中，在单实例多线程并发与 SQLite WAL 模式下具有微秒级读写性能与强一致性；若未来扩展至多进程或多机无状态集群部署，需将纪元版本号与增量变更事件下沉至共享内存或分布式缓存层。
2. **乱序时间戳与单调流的双轨折中**：滑动窗口与传染图针对绝大多数按时间单调递增的在线交易流采用双端队列 + 二分有序数组实现 $O(\log W)$ 均摊更新；当出现跨度较大的乱序历史补录交易（`ts < max_ts`）时，为保证 100% 业务零失真，系统会在该账户/租户历史有序事件列表上执行 `bisect` 二分窗口切片与活跃状态对齐，以极小概率乱序路径的局部重算换取主路径的极致吞吐与绝对精确。
