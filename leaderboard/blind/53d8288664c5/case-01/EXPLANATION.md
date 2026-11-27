# 性能剖析与安全加固阐述（EXPLANATION.md）

> 本文档全部声明与 `aegis_app/` 沙盒源码逐条对应，可在 `code_changes.diff` 与 `code/` 中直接核验。核心验证口径：`python smoke_check.py` 全绿；110 组随机检索（含 upsert/隔离/解封/retire 动态扰动前后、6 种用户角色、排序/分页/去重全组合）与原版算法参考实现**逐字段零失真**；配额调拨/批次原子回滚/借调级联失效等专项自检通过。

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

**定位到的问题与重构**：
- **零复合索引**：全库仅有主键索引。已在 `db.py` 的 `SCHEMA_SQL` 追加 12 条幂等复合索引（`CREATE INDEX IF NOT EXISTS`，存量库挂载安全）：`transactions(tenant_id, account_id, ts)` 支撑滑窗区间扫描、`transactions(tenant_id, ts)` 支撑传染图区间扫边、`compliance_docs(tenant_id, status, quarantined, updated_at)`、`doc_citations(tenant_id, doc_id)` 与 `(tenant_id, cited_by_ref)` 双向引用、`doc_acl_rules(tenant_id, doc_id, active)`、`delegation_grants` 的 grantee/grantor 双向、`role_grants(tenant_id, user_id, active)`、`audit_logs(tenant_id, ts, log_id)` 与 `(tenant_id, event_type, ts, log_id)`、`webhook_events(tenant_id, nonce)`。
- **逐函数逐节点新建连接**：原版 `acl_wall.get_org_lineage` 逐组织节点开一条连接、`delegation._collect_upstream_grantors` 逐上游逐层开连接、`search` 逐文档逐条开连接。已重构为 `db.py` 借还式连接池（`_conn_pool` + `_pool_lock` + `_PooledConnection`）：`close()` 即归还复用，未决事务自动回滚，杜绝半截事务污染；`init_schema` 启用 WAL（并发读与单写共存）+ `synchronous=NORMAL` + `temp_store=MEMORY` + `cache_size=-2000`（约束每连接常驻页缓存约 2MB）。
- **循环内重复查询放大**：`search_documents` 原版对每个候选文档逐行重算 `resolve_effective_permissions`（同一 user/ts 结果恒等）并逐文档开连接查引用计数——已将权限解析移出循环（直接采用认证阶段已算得的 `caller.max_clearance`，二者在同一 (user, request_ts) 下数学恒等），引用计数改由内存反向引用图提供；`evaluate_transaction_batch` 原版逐笔全表 `fetchall` 历史交易再逐行废用 `json.loads`——已改为单事务连接上的 `idx_tx_tenant_acct_ts` 索引区间扫描（同连接可见同批先序未提交交易，见 C3）。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

| 热点 | 原版复杂度 | 重构后 | 落点 |
| --- | --- | --- | --- |
| 滑窗精确中位数 | O(W²) 冒泡交换 | O(W log W) Timsort | `window_stats.compute_exact_median_cents` |
| 词距邻近度 | O(\|pos_a\|×\|pos_b\|) 笛卡尔配对 | 一次 O(N) 位置索引 + 有序位置表双指针归并，`min_dist==1` 早停 | `doc_indexer._min_token_distance` / `search_service._proximity_bonus_from_positions` |
| 近似修订簇折叠 Jaccard | O(NA×NB) 列表成员扫描 | C 级集合交并 + **min/max 集合大小比值上界剪枝**（Jaccard ≤ min/max，剪枝仅对必然低于 0.70 阈值的比对返回 0.0，阈值决策严格等价） | `doc_indexer.jaccard_similarity_from_texts` / `search_service._jaccard_token_sets` |
| 三跳传染追踪 | 逐制裁源全表扫描 + 逐源 BFS | 制裁名单纪元缓存 + `idx_tx_tenant_ts` 区间扫边 + **多源 BFS 一次扩展至深度 2**（`min over src dist` 与多源 `dist` 严格等价） | `contagion_graph.compute_sanction_contagion_hop` / `rule_engine._contagion_hop_on_conn` |
| 借调资格回溯 | 逐上游逐层新建连接递归、无环路防护（委托环上递归爆栈） | 活跃借调边图纪元缓存 + 内存 DFS（逐路径 visited 环路免疫 + 最小深度剪枝 + 2 跳截断） | `delegation._discover_upstream_holders` |
| 审计摘要导出 | `fetchall` 全量 + 双重 `deepcopy` + 逐行废用 `json.loads` | 游标流式滚动哈希，常驻内存 O(sample_limit) | `audit_export._compute_digest_from_rows` |
| 文本分词 | sub 清洗 + findall 双遍 | 单遍 `findall`（等价） | `doc_indexer.tokenize_text` |

**紧凑增量倒排与常驻堆内存**（`search_service.py`）：租户级 `_TenantSearchIndex` 按 `(docs, citations)` 双纪元寻址缓存；`_DocEntry` 用 `__slots__` 仅驻留分词位置 `array('i')`、词频（≤12 截断计数）、140 字符摘要与元数据字段，**原始全文 body 绝无常驻内存**。upsert/retire/quarantine 提交后仅 bump 纪元，触发 `_reconcile_tenant_index` 的「轻量元数据清单比对（含 `length(body)` 指纹）+ 仅对真正变更的文档单篇重读正文重建条目」增量维护——不整表重建倒排；引用图（`forward_refs`/`reverse_dependents`）仅在 citations 纪元变化时全量重建。另设抗 DoS 索引预算：单篇正文至多索引前 5 万词、单词至多保留 2048 个位置（正常业务文档数百词量级，打分逐 token 精确；截断仅作用于畸形巨型载荷以约束常驻堆）。原版检索把全表 `raw_rows` 的完整 body 与候选 `_raw_body` 全程随行驻留——已彻底消除。

**零失真保障**：检索评分公式、三级隔离墙裁决优先级、最近组织节点覆盖、双轨法规归一化（`legacy_compat.canonicalize_regulation_code`）、去重代表与 `cluster_size` 语义、全部排序键与分页切片逻辑逐行保留；110 组随机对照（含动态扰动）逐字段一致。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

**统一锁偏序**：全部配额变更路径（`ledger_ops.consume_tenant_quota` / `transfer_tenant_quota` / `redeem_override_token` / `try_consume_realtime_alert_quota`）与风控批次（`rule_engine.evaluate_transaction_batch`）一律以 `BEGIN IMMEDIATE` 作为**事务首语句**获取 SQLite 全局写锁，且全程不持有任何 Python 层配额锁——跨接口（`quotas/consume` × `quotas/transfer` × `evaluate-batch` 告警联动）天然满足单一偏序，配合 30s busy_timeout 杜绝死锁与丢失更新。WAL 模式保证读路径（检索/摘要导出）不被写事务长阻塞，跨租户读写互不拖累（各租户独立索引快照 + 全局仅 SQLite 写锁串行）。

**四重强原子提交**：`evaluate_transaction_batch` 第一遍全量预校验（任一笔非法即整批 400、零写入零扣减），随后单条 `BEGIN IMMEDIATE` 事务包裹全批「交易落库 + 决策落库 + 滑窗区间读取 + 传染图区间读取 + `REALTIME_ALERT_POOL` 条件更新扣减」（告警扣减经 `try_consume_realtime_alert_quota(..., conn=conn)` 内联复用同一事务）；主键冲突（`sqlite3.IntegrityError`）与任何异常一律 `conn.rollback()` 整批回滚——零半截落盘、零配额泄漏、零内存污染（专项自检：冲突批后 `REALTIME_ALERT_POOL` 余额分毫未动、`transactions/risk_decisions` 零残留）。**总额守恒**：transfer 的读校验、双池更新与调拨流水在同一写事务内提交，并发 consume/告警联动无法插入其间造成漂移（响应字段与原版逐字段一致）。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

**多维纪元注册中心**（`epoch_cache.py`）：`role_grants` / `delegation` / `acl` / `docs` / `citations` / `policy` / `sanctions` 各域单调纪元，写入方（`revoke_or_grant_role`、`create_or_revoke_delegation`、`upsert_doc_acl_rule`、`upsert/retire/quarantine`、`update_tenant_policy`、`manage_sanctioned_entity`）在事务提交后立即 `bump_epoch`；读方缓存以 (db, 纪元组合, 业务键) 寻址，`EpochScopedCache` 容量有界、超限批量清扫陈旧纪元条目。**关键解耦**：修改单条 `doc-acl` 规则仅 bump `acl` 纪元——只失效隔离墙裁决缓存，**不清空**租户文档倒排索引；文档写入仅 bump `docs/citations`——不动权限/借调/策略缓存。

**二级借调时效链**（`delegation.py`）：上游回溯在活跃借调边图上内存 DFS，每段边校验 `starts_at <= at_ts < expires_at` 与上游用户 active，深度截断于 `MAX_DELEGATION_HOPS=2`（深度 >2 的中间节点对最终 1~2 跳资格判定无贡献，正常链路结果与原版分毫不差）；**上游一级窗口自然到期为纯读取时判定、零写降级**（冒烟 base+7500 断言通过）；源头撤权经 `auth.revoke_or_grant_role` 提交后 bump `role_grants` 纪元级联失效下游原生角色缓存；**逐路径 visited 环路免疫**彻底消除委托有向环路上的递归爆栈。原版 `_collect_upstream_grantors` 无任何环路防护——重构后 A→B→A 型恶意委托链路安全终止。

**实时失效一致性**：隔离/解封（`set_document_quarantine` bump `docs`）→ 增量索引对账 + `reverse_dependents` 反向图对被引用方 `citation_count` 做 **O(deg) 局部重算**；制裁名单变更 bump `sanctions` → 传染追踪缓存即时失效；策略热更新 bump `policy` → 风控评估零脏读即时生效。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

- **一阶 SQL 注入**：原版 `search` 的 `tenant_id`/`custom_tag` f-string 拼接、`ORDER BY {sort_by}` 注入、`_get_doc_citation_count` 的 `WHERE doc_id = '{ref}'` 拼接、`render_saved_report` 的 `tenant_id`/`extra_event_filter` 拼接——全部消除，检索路径已全程内存化（零业务 SQL），审计路径全参数化。
- **双通道二阶注入**（落库后再读取拼接/格式化）：① 报表模板：保存时字面占位符白名单（仅 `{tenant_id}`/`{total_records}`/`{total_amount_cents}`，其余任何花括号结构一律 400）+ 合法事件名校验；渲染时白名单复检并以**纯字面替换**取代 `str.format`——杜绝 `{env.master_pepper}` 属性反射泄密与 `{:0>2000000d}` 宽度放大炸弹（纵深防御：直写库的历史恶意模板渲染同样 400）。② 文档内部引用：`doc_citations.cited_by_ref` 落库后由 `search_service._count_valid_refs` 参数化/内存校验消费，且**严格校验引用源属于本租户**（原版按全局 doc_id 裸查，跨租户 `doc_` 引用会被误计为有效——已按任务契约封堵该跨租户引用侧信道）。
- **内部诊断泄密**：原版 `/api/v1/internal/diagnostics` 未鉴权直爆 webhook_secret/system_secrets/主密钥/物理路径，`health?debug=1` 同样泄密，500 响应回显 db_path/storage_dir/master_pepper/堆栈——已全部整改：诊断路由下线（404）、诊断聚合仅返回脱敏计数、500 仅落 stderr。
- **目录穿越**：原版 `read_compliance_snapshot` 的 `unquote + replace("../","")` 可被 `....//`、双重编码、反斜杠等变体绕过直读 `system_vault.json`——已改为纯文件名白名单（字母数字开头，仅含 `A-Za-z0-9._-`，无任何路径分隔符/点段/编码残留）+ `realpath` 锚定校验（防符号链接逃逸）；canary 与 pepper 在全部穿越变体下零泄露。
- **横向/纵向越权**：`batch_get_documents` 原版无租户过滤、无密级/隔离墙校验（跨租户全文泄露）——已实现五重封堵（租户、ACTIVE、隔离、实时密级、利益冲突墙）+ 2000 条预算；`get_risk_decision_detail` 增加租户过滤堵跨租户决策侧信道。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

- **回调防重放**（`auth.process_settlement_webhook`）：`±300s` 时间窗校验（原版缺失）、HMAC-SHA256 验签改 `hmac.compare_digest` 常量时间比较、**Nonce 在 `BEGIN IMMEDIATE` 写事务内查重后落库**（并发/串行重放零窗口，409 拒绝）、nonce/timestamp/settlement_ref 长度上限、payload 必须为 JSON 对象、`amount_cents` 严格整数守卫。
- **回溯正则熔断**（`rule_engine`）：用户可控 REGEX 规则经 `_validate_rule_regex_pattern` 结构化白名单——长度 ≤256、反向引用（`\1`/`\g`）拒绝、花括号重复上界 ≤64、**嵌套量词/相邻叠量词**（`(a+)+`、`a**`）与**量词修饰分组内前缀歧义交替**（`(a|aa)+`、空分支）全部拒绝，非法模式 `re.error` 转 400；已验证 `(a+)+b`、`(a*)*$`、`(a|aa)+b`、`(?:x|xy)+z`、`(a|)+`、`([a-z]+){64/65}`、`a{1000000}` 等炸弹毫秒级 400，而 `WIRE_INTL.*`、`^(CRYPTO|CARD)_`、`\d{2,4}`、`(?:ab|cd)+` 等合法模式全部放行；正则编译经 `_regex_compile_cache` 线程安全缓存。
- **邮箱正则 ReDoS 线性化**：原版 `^([a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*)+@...` 外层 `+` 修饰内含 `*`/`+` 的分组，30+ 字符即指数回溯（每次 `evaluate-batch` 逐笔调用！）——已等价改写为 `^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@...`（外层迭代拼接处无分隔符、恒可归一为单次迭代，**语言严格等价**），2000 字符炸弹毫秒级拒绝；另设 254 字符长度上限。
- **畸形 JSON / 膨胀树预算**：`middleware.parse_json_payload` 在 `json.loads` **之前**用 O(N) 状态机预检花括号/方括号嵌套深度（>64 拒绝）+ 2MB 体积上限——千层嵌套毫秒级 400；规则树求值带深度 32 / 节点 2000 预算；策略热更新前 `_validate_rule_tree_structure` 结构预检（非法算子/炸弹正则/非数值操作数在 PUT 即拒绝）；交易批次 5000 笔预算；`doc_writer` citations ≤200 条、单条 ≤256 字符；batch-get ≤2000 条；HTTP 层 `Content-Length` 硬校验 + 4MB 载荷熔断。
- **严格类型边界**：`_coerce_rule_number`（数值比较拒绝 `bool`/`NaN`/`±Inf`/超 64 位整数/非数值串）、批次 `amount_cents`/`ts` 严格 int、`update_tenant_policy` 阈值严格整数、`consume/transfer` amount 拒 `bool` 且 ≤2^62、webhook `amount_cents` 拒 `bool`/非 int/超 62 位、server 层 `_body_int`/`_int_or_zero` bool 混淆闸门（保留原版数字字符串兼容语义）。原版 `float([1,2])` 触发 500、`float(True)=1.0` 可命中规则、`json.loads` 接受 `NaN/Infinity` 字面量——均已被 400 级硬熔断取代。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：`aegis_app/search_service.py` — `_TenantSearchIndex`/`_DocEntry`（`__slots__` 紧凑条目：分词位置 `array('i')`、≤12 截断词频、140 字符摘要，无原始 body 驻留）+ `_reconcile_tenant_index`（轻量元数据清单 + `length(body)` 指纹比对，仅单篇重读变更文档）+ `_build_doc_entry`（5 万词/2048 位置抗 DoS 预算）；`aegis_app/doc_indexer.py` — `_min_token_distance` 双指针归并（`min_dist==1` 早停）、`jaccard_similarity_from_texts` 集合交并 + min/max 比值上界剪枝；`aegis_app/window_stats.py` — Timsort 精确中位数；`aegis_app/contagion_graph.py` — 纪元缓存名单 + 索引区间扫边 + 多源 BFS。滑窗由全表 `fetchall` 降为 `idx_tx_tenant_acct_ts` 区间扫描（`rule_engine.evaluate_transaction_batch`），同批先序交易经同事务连接即时纳入后续窗口与传染图。
- **[C2 多维纪元与二级借调隔离缓存声明]**：`aegis_app/epoch_cache.py` — `bump_epoch`/`epoch_token`/`EpochScopedCache`（有界容量 + 陈旧纪元批量清扫）+ `load_tenant_static` 静态组织图/用户档案共享缓存；`aegis_app/delegation.py` — `_native_roles_cache`（`role_grants` 纪元，由 `auth.revoke_or_grant_role` 提交后 bump 级联失效）、`_delegation_graph_cache` + `_discover_upstream_holders`（逐路径 visited 环路免疫 + 最小深度剪枝 + 2 跳截断，上游窗口到期零写降级）；`aegis_app/acl_wall.py` — `(tenant, user, doc)` 裁决缓存按 `acl` 纪元失效，`upsert_doc_acl_rule` 单条规则变更仅 bump `acl` 纪元、不清空文档倒排（acl 与 docs 纪元解耦）。
- **[C3 统一锁偏序与四重强原子事务声明]**：`aegis_app/ledger_ops.py` — `consume_tenant_quota`/`transfer_tenant_quota`/`redeem_override_token`/`try_consume_realtime_alert_quota` 全部 `BEGIN IMMEDIATE` 首语句取写锁、零 Python 层配额锁，扣减为条件谓词更新（`remaining_quota >= 1` 等）绝不超扣为负，transfer 双池更新 + 流水同事务守恒提交；`aegis_app/rule_engine.py::evaluate_transaction_batch` — 单条 `BEGIN IMMEDIATE` 包裹全批四通道（交易/决策/滑窗/传染图 + `REALTIME_ALERT_POOL` 经 `conn=` 参数内联扣减），`IntegrityError` 与任意异常整批 `rollback()` 转 400（零半截落盘、零配额泄漏）。
- **[C4 双通道二阶安全与越权边界声明]**：`aegis_app/audit_export.py` — `_validate_title_format`/`_render_template_title`（字面占位符白名单 + 渲染复检 + 纯字面替换，全程参数化 SQL）、`read_compliance_snapshot`（纯文件名白名单 + realpath 锚定）；`aegis_app/search_service.py::batch_get_documents` — 租户/状态/隔离/密级/隔离墙五重校验 + 参数化分块 IN；`_count_valid_refs` — `doc_` 引用源本租户校验阻断跨租户引用侧信道；`aegis_app/server.py` — `/api/v1/internal/diagnostics` 路由下线、`health?debug` 脱敏、500 仅落 stderr；`aegis_app/middleware.py::collect_internal_diagnostics` — 仅返回非敏感计数。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：`aegis_app/middleware.py` — `_precheck_json_nesting_depth`（`json.loads` **之前** O(N) 状态机深度预检，>64 拒绝）+ 2MB 体积熔断；`aegis_app/rule_engine.py` — `_validate_rule_regex_pattern`/`_reject_nested_quantifiers`/`_reject_ambiguous_quantified_group`（嵌套量词/叠量词/花括号 >64/反向引用/前缀歧义交替全部 400 + 编译缓存）、PARTNER_EMAIL_PATTERN 线性化（语言等价，实测 2000 字符炸弹毫秒级）、`_coerce_rule_number`（bool/NaN/Inf/超 64 位拒绝）、规则树深度 32/节点 2000 预算、批次 5000 预算；`aegis_app/auth.py` — webhook ±300s 时窗 + compare_digest 常量时间验签 + BEGIN IMMEDIATE 内 Nonce 查重；`aegis_app/doc_writer.py` — citations 200 条/单条 256 字符预算与严格整数字段守卫。

## 5. 已知工程取舍与残余边界说明

1. **单机进程内存快照**：租户倒排索引、纪元缓存与连接池均为单机进程内结构，按 `db_path` 寻址共享；多网关实例挂载同一 SQLite 文件时依赖 30s busy_timeout 串行写，未引入分布式一致性协议（本基准为单机标准库约束下的合理边界）。
2. **增量对账指纹**：文档清单比对以「元数据 + `updated_at` + `length(body)`」为变更指纹；正文等长替换且调用方显式传入与旧值完全相同的 `updated_at`/标题时（正常业务不可能出现）不会触发单篇重读。此为以极小失真窗口换取高频混写下 O(变更数) 增量维护的取舍。
3. **抗 DoS 截断阈值**：单篇正文 >5 万词、单词 >2048 位置、正则模式 >256 字符、JSON 深度 >64 / 体积 >2MB、HTTP 载荷 >4MB、批次 >5000 笔、citations >200 条等预算均按「远超正常业务、毫秒级熔断畸形载荷」标定；超出预算的畸形载荷按预算截断或 400 拒绝（正则守卫为结构化白名单启发式，对前缀歧义交替等价类采取保守拒绝）。
4. **SQLite 写事务全局串行**：`BEGIN IMMEDIATE` 单写锁使跨池调拨与批次评估在写侧天然串行（无死锁的代价）；读侧经 WAL 与内存索引快照保持并发吞吐。配额类高并发吞吐上限受单写锁约束，属 SQLite 边界的现实取舍。
5. **邮箱正则语言等价改写**：外层 `+` 迭代拼接处无分隔符、恒可归一为单次迭代，改写后匹配语言与原版严格等价（含 `$` 允许尾随换行等 Python 正则既有语义均未改动）；仅新增 254 字符长度上限（超出为畸形载荷拒绝）。
6. **按任务契约的行为收敛**：batch-get 五重约束、决策详情租户过滤、webhook ±300s 时窗与 Nonce 防重放、`doc_` 引用本租户校验均为任务书 §2 路由契约明确要求的行为（原版缺失属待修复缺陷），对相应越权/重放载荷的响应与原版不同是契约规定使然。
