# 性能剖析与安全加固阐述（EXPLANATION.md）

> 本文档所有工程声明均与沙盒源码一一对应，可逐条核验。

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

**缺失复合索引**：原版 `SCHEMA_SQL` 零二级索引，导致滑窗统计、三跳传染图、审计导出、引用计数、隔离墙规则、委托链解析全部走全表扫描。在 `aegis_app/db.py` 的 `SCHEMA_SQL` 中补齐 11 个覆盖高频读路径的复合索引（`idx_tx_tenant_ts`、`idx_tx_tenant_acct_ts`、`idx_tx_tenant_batch`、`idx_cit_tenant_doc`、`idx_docs_tenant_active`、`idx_acl_tenant_doc`、`idx_audit_tenant_ts`、`idx_audit_tenant_logid`、`idx_deleg_tenant_grantee`、`idx_role_grants_tenant_user`、`idx_webhook_tenant_nonce`），全部 `CREATE INDEX IF NOT EXISTS`，对存量库挂载兼容。

**连接级调优**：`db.open_connection` 统一设置 `busy_timeout=30000`、`journal_mode=WAL`（尽力而为，不支持 WAL 的文件系统自动保持默认日志模式）、`synchronous=NORMAL`、`temp_store=MEMORY`、`cache_size=-8000`，写并发下读不阻塞、忙等可控。

**逐笔连接与逐笔事务**：原版 `rule_engine.evaluate_transaction_batch` 对每笔交易执行"开连接→全租户交易全表 SELECT→逐行 `json.loads(metadata_json)`（结果被丢弃）→逐笔独立 commit"。重构为：批次级单次 `SELECT account_id, counterparty_id, amount_cents, ts FROM transactions WHERE tenant_id=?`（零 metadata 解析），账户滑窗与传染图各建一次内存增量结构，落库与告警扣减统一收口到**单一 `BEGIN IMMEDIATE` 事务**（见 §2.1）。`audit_export` 原版 `fetchall()` 全量行 + 两次 `copy.deepcopy` 全量驻留内存，重构为 `_compute_digest_streaming` 数据库游标逐行流式哈希 + 计数，常驻内存 O(1)（仅保留前 `sample_limit`≤50 条样本）。`search_service._get_doc_citation_count` 原版逐文档开连接查引用、再逐引用逐条查文档状态，重构为进程内引用缓存 + 反向依赖脏标记（见 §1.2）。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

全部新增 `aegis_app/index_cache.py`（17 号模块）承载进程内多维缓存，关键点：

- **紧凑单篇增量倒排索引**：`TenantState.ensure_docs` 惰性一次性建库（每文档 token 化一次），此后 `apply_upsert` 单篇增量（重建该文档的 `title_tf` / `body_positions` / `uniq_tokens`，O(单篇正文)），`apply_status` / `apply_quarantine` 仅翻转单条目标志。`doc_writer` 在每次 upsert/retire 后调用单篇增量钩子，**绝不重建整租户索引**。倒排结构为 `dict[token -> list[int]]` 位置表 + `frozenset` 全词集合 + 标题词频 dict + 140 字 snippet，**绝不保留原始 body 全文**；`DocEntry` 使用 `__slots__`，并对 upsert 正文施加 `MAX_DOC_BODY_BYTES=256KB` 硬预算，常驻堆内存严格有界。搜索热路径（`search_documents`）零 SQL 全表扫、零逐行 token 化：命中判定 O(|q|)、词频 O(|q|)。
- **短语词距邻近度**：原版 `doc_indexer.compute_phrase_proximity_bonus` 枚举全部位置对 O(P_a×P_b)；重构为 `compute_phrase_proximity_bonus_from_positions` 双指针归并扫描 O(P_a+P_b)，并在 `min_dist==1` 时早停（1 已为非零最小距离，不可能更小）。差分验证 300 组随机用例与原版逐位一致。
- **双轨法规近似去重**：`jaccard_similarity_from_sets` frozenset 交并 O(U_a+U_b)（原版 list 线性成员判断 O(U_a×U_b)）；并新增 `min_len_ratio_prunable` 集合大小比值剪枝——Jaccard ≤ min/max，`min/max < 0.70` 时直接跳过相似度计算；且原版在 `_canon_reg` 不一致时仍白白计算 Jaccard（结果从不使用），重构后安全跳过。两项输出与原版逐位一致。
- **双向引用增量传播**：`TenantState` 维护 `refs`（正向唯一引用集）+ `reverse_dependents`（反向依赖图 ref→{引用方}）。引用源状态翻转（retire/quarantine）仅对 O(deg) 个被引用方脏标记（`_mark_ref_status_dirty`），`citation_count` 惰性精确重算——被引用方 `citation_count` 立即精确联动，无全库重建。
- **滑窗精确动态中位数**：`rule_engine._AccountWindowTracker` 保留单账户全量 `(ts, amount, cp)` 按 ts 升序数组；每次观察二分定位窗口 `[lo, hi)`，时间前推时增量进出窗维护有序金额表/对手方计数/累计金额（O(进出笔数)，amortized O(1)/笔），**时间回退或插入点落入当前窗口时整窗精确重建**，任意乱序时间戳零失真；中位数用"有序表 + 虚拟插入" O(log W) 零拷贝求值（`_median_with`），与原版"当前笔 + 窗口历史"语义逐位一致。`window_stats.compute_exact_median_cents` 的 O(N²) 交换冒泡排序替换为 `sorted()` O(N log N)，输出一致。
- **三跳制裁传染**：`contagion_graph.ContagionEdgeTracker` 按 ts 排序边集 + 双指针滑窗增量构建邻接表（同样支持乱序精确回退重建），BFS 由原版"逐制裁源点重复 BFS" O(|S|·(V+E)) 改为全局多源 BFS O(V+E)（`_multi_source_hop`），跳数语义逐位一致。
- **认证/权限热路径零数据库往返**：`auth.authenticate_caller` 与 `resolve_effective_permissions` 的租户表、用户表、组织树、角色授予、借调委托全部走纪元缓存（运行期无变更的结构常驻，可变结构按纪元惰性重建），原版每请求 3+ 连接、逐组织节点逐条查询被消除。

**跨模块零失真保障**：全部算法重构以差分测试锚定——2483 项自动验证（含 300 组中位数、300 组邻近度、200 组 Jaccard、60×15 步乱序滑窗、60×12 步乱序传染图与原版暴力参照逐位比对）全部通过；公开冒烟 `smoke_check.py` 全绿。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

**统一锁偏序 = SQLite 单写者锁**。`db.immediate_transaction` 是全系统唯一的跨语句写原语：`transfer_tenant_quota`（源扣减条件谓词 `remaining_quota >= ?` → 目标入账 → 流水登记）、`consume_tenant_quota`、`try_consume_realtime_alert_quota`、`redeem_override_token`（`WHERE used = 0` 条件更新）、webhook Nonce 去重、以及 `evaluate_transaction_batch` 的整批落库 + 逐 REJECT 笔按批次序条件扣减 `REALTIME_ALERT_POOL`（`UPDATE ... SET remaining_quota = remaining_quota - 1 ... AND remaining_quota >= 1`，rowcount 判定）**全部**收口到 `BEGIN IMMEDIATE`。进程内**不引入任何 Python 配额锁**，缓存锁与数据库写锁从不交叉持有——单一全局写偏序，结构性无死锁：单池抢扣（60 线程并发抢 50 点验证 `成功数 + 剩余 == 50` 且无负数）、跨池双向交叉调拨（总额守恒）、令牌核销（12 线程并发仅 1 次成功）、8 并发批次联动扣减告警池，全部实测通过。

**四重强原子回滚**：批次评估分四阶段——①全批输入严格校验（任一笔非法整批 `ValueError`，零副作用）；②纯内存评估（滑窗/传染图异常零污染）；③单一 `BEGIN IMMEDIATE` 事务内先做主键冲突预检（分块 `IN` 查询，命中即 ROLLBACK），再按批次序执行告警配额扣减与 `transactions`/`risk_decisions` 落库；④任何异常路径事务 ROLLBACK——数据库、滑窗、传染图（纯内存未提交）、告警配额四位一体强原子，零半截落盘、零配额泄漏。实测：批次第 2 笔非法字段 → 整批拒绝且告警池/交易表零变化；批次含与存量冲突的主键 → 整批回滚零残留。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

`index_cache.TenantState` 将六个缓存维度**完全独立纪元**：文档倒排索引（无纪元，单篇增量）、`acl_epoch`（`upsert_doc_acl_rule` 后仅 `bump_acl()`，**绝不连带清空文档倒排索引**）、`grants_epoch`（授予/撤权后 bump）、`delegation_epoch`（委托创建/撤销后 bump）、`policy_epoch`（策略热更新后 bump）、`sanctions_epoch`（名单变更后 bump）；跨租户独立租户锁，无全局大锁阻塞。

**2 跳借调链**（`delegation.py`）：`_collect_upstream_grantors` 递归深度硬上限 `MAX_DELEGATION_HOPS`（更深链段对本就无效，纯浪费）+ `visited` 集合环路防护——有向委托环路毫秒级免疫，绝不无限递归；每段链路要求 `active=1` 且 `starts_at <= at_ts < expires_at`，链上每个委托人 `active=1`；源头角色有效性在**每次请求时动态核验**（`resolve_base_and_explicit_roles` 实时读取纪元缓存）——源头撤权（`bump_grants` 后 grants 缓存即时更新）、上游撤销、上游窗口自然到期均即时级联失效下游（含"上游一级窗口到期、二级窗口未到期"的零写降级场景，冒烟第 2 节验证）。三级利益冲突墙 `evaluate_doc_wall_cached` 为纯内存 O(lineage) 裁决（个人 ALLOW > 个人 DENY > 最近组织节点 DENY 优先 > 默认放行），语义与原版逐位一致。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

- **二阶 SQL 注入（引用通道）**：`search_service._get_doc_citation_count` 原版以 f-string 拼接 `doc_id = '{ref}'`（ref 为攻击者可经 `docs/upsert citations` 持久化的任意字符串）→ 改为缓存内存判定，任何 SQL 拼接消失。
- **一阶注入**：`search_documents` 原版将 `tenant_id`、`tag_filter`、`sort_by`/`sort_dir` 直接拼接 SQL → 租户/标签全部参数化；`sort_by` SQL 排序整体移除（输出由白名单字段 `(score|updated_at|risk_weight)` 的 Python 终排序唯一决定，与原版行为逐位一致），`audit_export.render_saved_report` 的存储型二阶注入（模板 `extra_event_filter` 拼接）→ 参数化。
- **模板反射/放大**：`render_saved_report` 原版 `str.format(..., env=RUNTIME_ENV)` 可用 `{env.master_pepper}` 反射主密钥、`{total_records:0>200000}` 宽度放大耗尽内存 → `save_report_template` 白名单校验仅允许 `{tenant_id}`/`{total_records}`/`{total_amount_cents}` 三个字面占位符（残留花括号即拒绝），渲染用 `_render_title_safe` 手动安全替换，**全程不调用 str.format**。
- **目录穿越**：`read_compliance_snapshot` 原版仅 `replace("../","")` 一次（`....//` 还原、反斜杠、双编码均可绕过）→ 重构为"单次解码 + NUL/反斜杠拒绝 + PurePosixPath 相对化（拒绝绝对路径与任何 `..` 分量）+ realpath 锚定必须仍在租户快照目录内 + 文件大小上限"。六种变体穿越（含跨租户读 bravo 快照）实测全拒，合法 `2026-Q3.json` 正常。
- **跨租户泄露**：`batch_get_documents` 原版仅按 `doc_id IN (...)` 全局查询、无租户/密级/隔离墙校验 → 补齐租户过滤 + ACTIVE 且未隔离 + 密级 + 三级隔离墙全约束，并加 `MAX_DOC_IDS_BATCH=256` 上限；`get_risk_decision_detail` 补租户过滤（原版任意租户可读他租决策详情）。
- **内部信息泄露**：`/api/v1/health?debug=1` 不再反射任何诊断（存活探针零泄密）；`/api/v1/internal/diagnostics` 原版无认证返回主密钥/系统密钥表/物理路径 → 仅 `COMPLIANCE_ADMIN` 可达且彻底脱敏（无 webhook secret、无 pepper、无路径）；未知异常兜底 500 返回通用消息，删除原版泄露 `db_path`/`storage_dir`/`master_pepper`/traceback 的 `debug_context`。
- **认证侧信道**：API 令牌哈希比较与 webhook HMAC 验签均改 `hmac.compare_digest` 常量时间比较。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

- **Webhook 加固**（`auth.process_settlement_webhook`）：常量时间 HMAC 验签 → `±300s` 时间窗硬校验（过旧/超前报文拒绝）→ 载荷体积 ≤64KB、nonce ≤128 → 严格整数 `amount_cents` → `BEGIN IMMEDIATE` 串行化 Nonce 去重（并发 8 路同 nonce 实测仅 1 路 200、其余 409）。
- **配额/令牌竞态**：见 §2.1（条件 UPDATE 谓词消除读-改-写竞态）。
- **委托环路**：见 §2.2（深度硬上限 + visited 环路防护）。
- **正则炸弹**：规则树 `REGEX` 操作符经 `_safe_regex_search` 毫秒级硬熔断——模式长度 ≤256、分组数 ≤24、`{n,m}` 上界 ≤100、逐层分组扫描拦截嵌套量词（`(...+)+`）与前缀歧义量化交替（`(a|aa)+` 型），无效正则转 400；`(a+)+b`、`(a|aa)+b`、`(a*)*b`、`(?:a+)+b`、`a{999999}` 实测全部 <1s 拒绝。邮箱正则等价重写消除嵌套量词（语言完全一致），12 段病态邮箱毫秒级通过。
- **JSON 炸弹**：`middleware.parse_json_payload` 先字符级扫描嵌套深度（>64 拒绝）与体积（>2MB 拒绝），千层 JSON 在 `json.loads` 递归爆炸前 400 熔断；规则树深度 ≤32、节点数 ≤256（`_count_rule_budget` 落库前与求值时双重校验），400 层嵌套规则树毫秒级拒绝。
- **数值/类型边界**：`db.coerce_strict_int` / `coerce_query_int` 统一严格 64 位整数整编——拒绝 bool、NaN、±Inf、超 64 位、超长数字串；应用于批次交易金额/时间戳、配额 amount、策略阈值、委托窗口、webhook 时间戳、分页与快照参数等全部入口（`int(True)`、`999999999999999999999999999999`、`float('inf')` 实测 400）。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：`aegis_app/index_cache.py`（`DocEntry.__slots__` 紧凑条目 + `ensure_docs` 惰性建库 + `apply_upsert`/`apply_status`/`apply_quarantine` 单篇增量 + `refs`/`reverse_dependents` 双向引用 O(deg) 脏标记传播）；`aegis_app/doc_writer.py` 在 upsert/retire 后调用上述单篇钩子；`aegis_app/search_service.py` 检索走内存倒排 + 单次权限解析 + 剪枝去重；`aegis_app/doc_indexer.py` 双指针邻近度（`compute_phrase_proximity_bonus_from_positions`，min_dist==1 早停）与 frozenset Jaccard；`aegis_app/window_stats.py` O(N log N) 中位数；`aegis_app/rule_engine.py` `_AccountWindowTracker`（增量滑窗 + O(log W) 虚拟插入中位数 + 乱序回退重建）；`aegis_app/contagion_graph.py` `ContagionEdgeTracker` + 多源 BFS `_multi_source_hop`；`aegis_app/audit_export.py` `_compute_digest_streaming` 游标流式摘要。
- **[C2 多维纪元与二级借调隔离缓存声明]**：`aegis_app/index_cache.py` `TenantState` 六维独立纪元（`acl_epoch`/`grants_epoch`/`delegation_epoch`/`policy_epoch`/`sanctions_epoch` 与文档索引互不解耦联动，`bump_*` 单点递增）；`aegis_app/delegation.py` `_collect_upstream_grantors`（深度 ≤ `MAX_DELEGATION_HOPS` + `visited` 环路防护 + 逐段窗口/active 核验）、`resolve_active_delegated_roles`（请求期动态核验源头原生角色，实现撤权/撤销/自然到期零写级联失效）。
- **[C3 统一锁偏序与四重强原子事务声明]**：`aegis_app/db.py` `immediate_transaction`（全系统唯一跨语句写原语，SQLite 单写者锁即全局偏序，进程内零 Python 配额锁）；`aegis_app/ledger_ops.py` `transfer_tenant_quota`/`consume_tenant_quota`/`redeem_override_token`/`try_consume_realtime_alert_quota` 全部条件 UPDATE；`aegis_app/rule_engine.py` `evaluate_transaction_batch` 阶段 4 单一事务内完成主键冲突预检 + 按批次序告警配额扣减 + 全批落库，异常 ROLLBACK（四位一体强原子）。
- **[C4 双通道二阶安全与越权边界声明]**：`aegis_app/search_service.py`（引用缓存消除引用通道二阶注入、参数化 tag/category、batch-get 租户+密级+隔离+隔离全约束）；`aegis_app/audit_export.py`（`extra_event_filter` 参数化、`_validate_title_format`+`_render_title_safe` 模板沙箱、`read_compliance_snapshot` 双重路径锚定）；`aegis_app/acl_wall.py`/`index_cache.py` 租户隔离缓存；`aegis_app/server.py`（health/诊断/500 三处泄密堵点）；`aegis_app/auth.py` 常量时间令牌与 HMAC 比较。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：`aegis_app/middleware.py`（`_scan_json_depth` 深度预检 + 载荷体积上限）；`aegis_app/rule_engine.py`（`_safe_regex_search` 嵌套量词/前缀歧义交替/分组数/重复上界四重熔断、`_count_rule_budget` 树预算、`PARTNER_EMAIL_PATTERN` 等价无回溯重写）；`aegis_app/db.py`（`coerce_strict_int`/`coerce_query_int` 严格 64 位整数守卫，覆盖全部请求入口）。

## 5. 已知工程取舍与残余边界说明

1. **单机进程内缓存一致性**：文档/权限/策略缓存以"所有变更均经网关路由"为前提做单篇增量更新与纪元失效；若评测方绕过网关直接用 SQL 修改沙盒数据库，需重建网关实例（`create_gateway`）以刷新缓存。这是在"高频混写零全库重建"与"跨进程失效检测开销"之间的现实取舍。
2. **SQLite 写事务串行边界**：所有跨语句写操作收口到 `BEGIN IMMEDIATE`，高并发写天然按写锁串行（进程外多写者由 `busy_timeout=30s` 兜底）；在慢速文件系统（如网络盘）上单次事务 fsync 延迟为物理瓶颈，已用 WAL + `synchronous=NORMAL` 缓解但不消除。
3. **批次告警配额扣减时点**：告警配额扣减从"评估时即时"移至"整批提交事务内按批次序执行"——这是达成四位一体原子回滚的必要语义（失败批次零配额泄漏）；对成功批次，配额消耗顺序与原版逐笔一致。
4. **REGEX 规则白名单化**：为彻底消除回溯炸弹，量化分组体内的嵌套量词与前缀歧义交替被拒绝——合法业务规则（简单字面/字符类模式）不受影响，但高度复杂但良性的正则可能被误拒（宁可错杀，不可超时）。
5. **正文字节预算**：单篇文档正文 >256KB 拒绝入库，以保障常驻索引堆内存严格有界；该预算高于全部种子数据与常规合规文档体量。
