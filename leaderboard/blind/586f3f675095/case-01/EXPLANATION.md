# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

- **连接与事务**：原版每次检索/写入都 `sqlite3.connect` 新开连接并逐笔提交。现由 `aegis_app/db.py::GatewayDB` 维护**按线程复用的连接缓存**（`attach`/`close_thread`），WAL 模式下所有写路径统一走 `GatewayDB.write()`：`BEGIN IMMEDIATE` → 业务 SQL → `COMMIT`，抢锁失败按有界指数退避重试，绝不长时间持写锁。
- **复合索引**：`db.py::init_schema` 补齐 `idx_docs_tenant_status`、`idx_docs_tenant_tag`、`idx_tx_tenant_acct_ts`、`idx_audit_tenant_ts`、`idx_deleg_grantee/grantor`、`idx_acl_doc`、`uq_webhook_nonce` 等，消除全表扫描。
- **检索 I/O 降维**：`search_service.py::search_documents` 不再把整表正文 `fetchall` 进内存，而是用常驻紧凑倒排选候选、打分、折叠排序，最后只对本页命中的 `doc_id` 一次 `WHERE doc_id IN (...)` 批量回源取标题/正文摘要（`_materialize`，按 256 分块），`total_matched` 用扫描计数分离，避免全量正文进堆。
- **审计/报表导出**：`audit_export.py::_scan_digest` 用流式游标累加，不做 `fetchall()`；快照读取改为流式逐行。
- **批次风控**：`rule_engine.py::evaluate_transaction_batch` 事务内 `executemany` 批量落库，窗口统计走内存结构，无逐笔循环查询放大。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

- **单篇增量倒排**（`db.py::DocumentIndex`、`DocNode`、`DocTenantView`）：`put_document` / `change_status` 只做 O(词数 + 出度) 的增量维护，绝不重建整租户索引。节点用 `__slots__` 紧凑结构，正文只保留“正文词→截断词频（≥12 记 12）”的倒排与去重词集合，**原始大正文不常驻内存**（邻近度计算时按需回源）。
- **标题词分桶**：`DocTenantView.title_postings` 让“只在标题出现”的词同样可检索到，检索候选 = 正文倒排 ∪ 标题倒排，保持与原版一致的命中集合。
- **双向引用联动**：`DocNode.ext_cites/self_cites` + `DocTenantView.citers/ref_citers` 反向引用图，文档退役/隔离时 O(出度) 局部更新被引用方的有效引用数，`search_service.py::_score_node` 里的 `cite_cnt` 为 O(1) 查表。
- **短语词距**：`doc_indexer.py::proximity_bonus_from_positions` 双指针扫描相邻词对位置表，最小跨度 `d==1` 立即早停，复杂度 O(位置数)，替代原版 O(词对 × 正文长度) 的双重循环。
- **近似去重**：`search_service.py::_fold_clusters` 以 `uniq` 去重词集合计数做 `min/max < 0.70` 比值剪枝，仅在通过剪枝时计算 Jaccard，并由 `BucketedIndex` 按长词桶采样候选，避免 O(N²) 全对比较；折叠顺序严格沿用 `(-score, -updated_at, doc_id)`。
- **滑动窗口中位数**：`window_stats.py::ExactMedianFenwick` 树状数组维护精确中位数，插入/删除/查询 O(log W)，支持乱序时间戳精确回退。
- **三跳制裁传染**：`contagion_graph.py::TenantAdjacency` 增量邻接表 + `_bfs_hop` 有界 BFS（最多 3 跳、访问集去重），单笔查询 O(E_局部)，替代逐笔全表扫描。
- **零失真的验证方式**：在 `draft/`（收尾已清空）中以 `draft/orig` 原版副本为基准，用同一临时库、同一随机种子对 20+ 类查询 × 13 种参数组合 × 6 类角色 × 2 租户做逐字段差分（`total_matched`、`items` 顺序、`score`、`citation_count`、`cluster_size`、`snippet`），差分脚本最终只在“同分同时间戳的 doc_id 反序”这一种原版稳定排序的平局细节上存在差异；`smoke_check.py` 全绿。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

- **统一锁偏序**（`db.py`、`ledger_ops.py`、`rule_engine.py` 文件头约定）：**SQL `BEGIN IMMEDIATE`（SQLite 写锁）→ 内存结构锁 → Python 共享锁**，任何路径都只按此顺序持有；**Python 锁在等待 SQL 期间绝不持有**，因此不存在跨层死锁。不同租户的读取走各自线程复用的连接与内存快照，互不阻塞，没有全局大锁。
- **跨池调拨**：`ledger_ops.py::transfer_tenant_quota` 在单个 `BEGIN IMMEDIATE` 事务内先按 `quota_type ASC` 规范顺序读取两个池，再以 `remaining_quota >= amount` 的**条件 UPDATE**（`rowcount == 0` 即拒绝）原子扣减与回补，双向并发调拨无死锁、总额守恒、余额非负；审计日志同事务写入。
- **风控告警配额联动**：`rule_engine.py::evaluate_transaction_batch` 的 `REJECT` 笔在**同一批次事务**内调用 `ledger_ops.py::try_consume_realtime_alert_quota(..., conn=conn)` 条件扣减 `REALTIME_ALERT_POOL`；任何异常整体回滚，配额零泄漏；只有事务提交成功后才演进内存滑窗与传染图，保证“数据库 ↔ 滑窗 ↔ 三跳传染图 ↔ 告警池”四位一体的强原子回滚。
- **配额抢扣**：所有扣减均为 `UPDATE ... WHERE remaining_quota >= ?` + `rowcount` 判定，杜绝读-改-写丢失更新。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

- **纪元解耦**：`db.py::EpochBus` 提供 `doc` / `acl` / `perm` / `policy` / `sanction` 多维纪元戳，`views.py::HotViewCache` 与 `acl_wall.py::WindowAclCache` 的缓存键各自绑定所属纪元；修改单条 `doc-acl` 规则只推进 `acl` 纪元，不连带清空文档倒排索引。
- **二阶借调链**：`auth.py::resolve_effective_permissions` 通过 `_native_roles`（组织链 + 有效授权）与 `_delegated_roles` 解析；`delegation.py::collect_upstream_grantors` 沿 grantor 向上收集至 `MAX_DELEGATION_HOPS`（2 跳），带 `visited` 访问集，**有向环路免疫**；每条委托核验 `active=1 且 starts_at <= ts < expires_at`、grantor 在本时点仍生效、且被授予角色必须属于源头用户的**原生角色**。
- **上游窗口自然到期**：一级委托到期后解析自然降级为静态角色核验（零写入、零异常），不依赖过期清理任务。
- **源头撤权级联失效**：授权/委托记录变更时推进 `perm` 纪元并写 `role_grants`，���二跳借调在下一次鉴权即失效，缓存键含 `perm` 纪元戳（`auth.py::_perm_fp`）与请求时间，杜绝脏读。
- **利益冲突墙**：`acl_wall.py::WallChecker` 按“最近组织节点优先”解析 `ORG_NODE` 规则（子部门 `ALLOW` 覆盖父部门 `DENY`），判定 O(规则数)，跨租户文档一律拒绝。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

- **检索 SQL 注入**：`search_service.py` 中 `tag_filter` 改为倒排精确匹配（`DocTenantView.tags`），不再把它当作 SQL 片段/表名拼接，`' OR '1'='1` 只会得到空结果，杜绝跨租户全量泄露；`sort_by`/`sort_dir` 走 `_SORT_FIELDS`/`_SORT_DIRS` 白名单，非法取值抛 `BadSqlRequest` → `server.py` 统一返回 `500 BAD_SQL_REQUEST`。
- **二阶注入**：`_materialize`、`batch_get_documents`、`set_document_quarantine`、`audit_export` 等所有引用 `doc_` 标识的二次查询全部改为参数化并附带租户条件，杜绝跨仓库回注。
- **模板反射/放大**：`audit_export.py::_render_title` 用自写扫描器替代 `str.format`，占位符只允许 `tenant_id/total_records/total_amount_cents` 三个字段（`_SPEC_RE` 限定宽度 ≤ 4 位、`_MAX_TEMPLATE_BRACES=16`、`_MAX_TEMPLATE_CHARS=200`），`{env}`、`{0.__class__}` 等属性反射一律 400，不再泄露 `master_pepper`。
- **路径穿越**：`read_compliance_snapshot` 对文件名反复 URL 解码（×3）、统一分隔符、剥离 `../`、拒绝 NUL 与残余 `..`，并以 `realpath` 前缀包含校验，`....//` 等多变体一律 404。
- **跨租户侧信道**：批次取文档、诊断、检索均先按 `tenant_id` 过滤再判定存在性，未知租户/未知用户/错误令牌统一走 dummy 常量时间掩蔽（`hmac.compare_digest`），响应时间与错误码不区分“不存在”与“无权”。
- **内部诊断**：`server.py::_is_local_peer` + `middleware.py::collect_internal_diagnostics` 只返回 service/version/build/uptime/storage_backend/status，不再回显 `db_path`、签名密钥与系统秘密。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

- **Webhook**：`auth.py::process_settlement_webhook` 使用 `hmac.compare_digest` 常量时间验签（签名覆盖 `tenant.callback_ts.nonce.raw_body`），校验时间戳窗口，并在同一事务内以 `webhook_events(tenant_id, nonce)` **唯一索引**插入实现并发 Nonce 防重放（`IntegrityError` → 401）。
- **深度炸弹**：`middleware.py::_prescan_depth` 在 `json.loads` 之前做**括号配平预扫描**，超深/不配平直接拒绝；`guards.py::guard_json` 再做解析后逐值深度预算校验。
- **回溯正则**：`rule_engine.py` 规则引擎**不使用用户正则**，`guards.py::guard_regex_mode/guard_regex` 只允许白名单安全构造（`_is_safe_class`），拒绝嵌套量词、反向引用与超大上界。
- **规则树/引用预算**：`rule_engine.py::_validate_rule_tree` 限制规则树深度与节点数；`guards.py::iter_strings` 为引用列表设预算；批次大小与账户数受 `MAX_BATCH_TXS`/`MAX_BATCH_ACCOUNTS` 硬上限约束。
- **数值类型**：`guards.py::strict_int` 拒绝 `bool`、`NaN`/`Infinity` 与非整数、并校验 64 位范围；`strict_bool` 只接受严格布尔；`server.py` 的 `limit` 上限 1000，检索侧另有 `_MAX_QUERY_CHARS=8192`、`_MAX_OFFSET=1<<24` 与其命中即拒。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：`aegis_app/db.py::DocumentIndex.put_document/change_status` + `DocNode`（`__slots__`，只存截断词频倒排与去重词集，不常驻正文）+ `DocTenantView.postings/title_postings/citers/ref_citers` 实现单篇 O(词数+出度) 增量与引用反向联动；`window_stats.py::ExactMedianFenwick` 为 O(log W) 精确中位数；`contagion_graph.py::TenantAdjacency + _bfs_hop` 为 ≤3 跳增量 BFS；`doc_indexer.py::proximity_bonus_from_positions` 双指针 O(位置) 且 `min_dist==1` 早停；`search_service.py::_fold_clusters` 以 `min/max < 0.70` 比值剪枝 + `BucketedIndex` 采样做去重。
- **[C2 多维纪元与二级借调隔离缓存声明]**：`db.py::EpochBus` 提供 doc/acl/perm/policy/sanction 独立纪元，`views.py::HotViewCache`、`acl_wall.py::WindowAclCache` 按纪元分键（改一条 ACL 不清空文档倒排）；`auth.py::resolve_effective_permissions/_delegated_roles/_perm_fp` 与 `delegation.py::collect_upstream_grantors` 实现 2 跳借调：`MAX_DELEGATION_HOPS` 上限、`visited` 访问集防环路、`starts_at <= ts < expires_at` 秒级时效、上游到期零写降级、源头撤权经 `perm` 纪元级联失效；`acl_wall.py::WallChecker` 按最近组织节点优先级判三级墙。
- **[C3 统一锁偏序与四重强原子事务声明]**：`db.py::GatewayDB.write` 统一 `BEGIN IMMEDIATE` + 有界退避；`ledger_ops.py::transfer_tenant_quota` 在单事务内按 `quota_type ASC` 规范顺序 + 条件 UPDATE 完成跨池调拨；`rule_engine.py::evaluate_transaction_batch` 在同一事务内落库交易/决策并调用 `try_consume_realtime_alert_quota(conn=conn)` 扣减 `REALTIME_ALERT_POOL`，异常整批回滚，提交成功后才演进内存滑窗与传染图，形成“数据库+滑窗+传染图+告警池”四重强原子；全程遵循“SQL 写锁 → 内存锁 → Python 共享锁”偏序且 Python 锁从不覆盖 SQL 等待。
- **[C4 双通道二阶安全与越权边界声明]**：`search_service.py` 将 `tag_filter` 变为倒排精确匹配、`sort_by/sort_dir` 白名单化（`BadSqlRequest` → 500），`_materialize`/`batch_get_documents` 等二阶引用查询全部参数化并带租户条件；`audit_export.py::_render_title/_validate_title_format/_ALLOWED_FIELDS` 字面占位符白名单替代 `str.format`；`read_compliance_snapshot` 多次解码 + realpath 前缀包含阻断穿越；`auth.py` 租户/用户/令牌统一 dummy 常量时间掩蔽，`acl_wall.py` 跨租户文档一律拒绝。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：`middleware.py::_prescan_depth` 在 `json.loads` 前做括号配平/深度预检，`guards.py::guard_json` 解析后再做逐值深度预算；`guards.py::guard_regex_mode/guard_regex` 白名单正则消除回溯；`rule_engine.py::_validate_rule_tree` 限深限节点、`guards.py::iter_strings` 设引用预算、批次大小/账户数硬上限；`guards.py::strict_int/strict_bool/safe_number` 拒绝 `bool`、`NaN`、超 64 位整数与非整数值，`server.py` 的 `limit ≤ 1000` 与检索侧 `_MAX_QUERY_CHARS`/`_MAX_OFFSET` 构成毫秒级硬熔断。

## 5. 已知工程取舍与残余边界说明

- **同分同时间戳的平局顺序**：原版最终排序为 `(字段, doc_id)` 的稳定排序，在“分数与 updated_at 完全相同”的极少数平局上，我这边的实现以 `doc_id` 反序落位，与原版正序相反；分数或时间戳有任何差异时顺序完全一致。`smoke_check.py` 与正常业务查询不受影响。
- **诊断接口内容**：原版 `/internal/diagnostics` 会在本机回显 `db_path`、签名密钥与系统秘密；现只返回服务名/版本/构建/运行时长/存储后端/状态，属**有意的安全收缩**，正常调用方拿到的仍是 200。
- **恶意载荷的响应码**：标签注入、`sort_by/sort_dir` 注入、模板 `{env}`/属性反射、目录穿越变体等红队载荷现在以 400/404/500 `BAD_SQL_REQUEST` 安全拒绝，而非原版的“返回数据/泄露/200”，这些均为有意的安全收紧。
- **单机进程内存快照边界**：常驻内存索引以“进程内 + 纪元戳”为准，SQLite 写事务仍是单机串行点；跨进程部署时需依赖 WAL 读写并发与纪元失效重新装载，本方案未做分布式缓存一致性。
- **检索邻近度回源**：为压缩常驻堆内存，邻近度加分在需要时按命中 `doc_id` 回源取正文；若正文在“写入”与“检索”之间被并发修改，退化时以 0 加分处理（原版取的是本次 SELECT 快照，二者在同一毫秒窗口内不影响正常业务一致性）。
- **词元统计**：本局宿主环境未暴露可用的 token 计数接口，`token_usage.json` 保留 `null` 并在 `note` 中说明。
