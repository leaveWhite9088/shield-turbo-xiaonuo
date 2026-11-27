# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
原版在每次鉴权、每个文档的 ACL/引用判断、每笔交易的策略/历史/图查询及每次配额扣减中反复开关 SQLite 连接；交易批次还逐笔提交，且缺少覆盖租户、时间和第二查询列的复合索引。

- `aegis_app/db.py` 增加覆盖用户/组织、授权与委托、ACL、有效文档、引用双向查找、账户时间窗、决策、审计及 Webhook Nonce 的复合索引；Webhook 另有 `(tenant_id, nonce)` 唯一索引。
- `_ConnectionPool` / `PooledConnection` 提供每库最多 8 个空闲连接的复用，检出连接仍由单个请求独占，归还时回滚未结束事务；`init_schema` 启用 WAL 与 `synchronous=NORMAL`，不删除或重建存量业务数据。
- `search_service.py` 不再对每个结果执行权限、ACL、引用 SQL；`auth.py` / `delegation.py` 在同一连接内完成有效权限链核验。
- `rule_engine.py` 将整批改为一个策略快照、一段有界历史查询、一个 SQLite 事务；`ledger_ops.py` 的告警扣减在同一连接、同一事务内完成，不再逐笔独立提交。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
- `doc_indexer.py` 的 `DocNode` 使用 `__slots__`，只保留检索元数据、140 字摘要、标题词频、正文词项位置及不可变词集合，**不保存完整原始 `body`**。`TenantDocumentIndex.term_docs` 是租户级倒排 postings；查询从“扫描全部文档”降为“查询词 postings 并集 + 命中候选过滤”。完整正文仅在初始流式装载的当前行、单篇写入及有权 `batch-get` 时短暂出现。
- 单篇 `apply_upsert` 只移除/增加该文档 postings，复杂度为 `O(正文词数 + 变更引用数)`；`citations` 保存唯一引用源，`reverse_dependents` 保存内部源文档到目标文档的反向边。退役、隔离、解封和恢复 ACTIVE 时，`apply_state` / `apply_upsert` 仅对相关目标做 `O(deg)` 引用计数传播，不重建整租户索引，并按唯一源、忽略自引用及源文档同租户/ACTIVE/未隔离规则计算。
- `compute_positions_proximity_bonus` 以两个有序位置序列双指针求相邻查询词最小距离，距离为 1 立即早停，避免原版逐词对枚举全部位置笛卡尔积。
- 去重先按归一化法规编号分块，仅在分数排序后的同簇候选中比较；`jaccard_similarity_sets` 先做 `min_len/max_len < 0.70` 数学安全剪枝，再遍历较小集合求交集。保留原版代表文档、簇计数及最终稳定排序。
- `window_stats.py` 的 `SlidingAccountWindow` 用两个堆、延迟删除、过期堆及对手方计数维护窗口；稳定时间序下摊还 `O(log W)` 插入/删除并得到精确中位数，乱序时间戳会使主增量状态失效并执行 `O(W log W)` 的精确重建，后续再安全恢复增量，避免静默漏记乱序交易。
- `contagion_graph.py` 的 `TemporalContagionGraph` 对批次历史只建边一次，各笔从当前交易双端做深度不超过 2 的时间过滤 BFS，只访问局部两跳邻域，不再逐笔全表扫描并从每个制裁源重复搜索；当前边评估后加入，供后续交易使用。
- `audit_export.py` 直接消费 SQLite 游标，边读取边累计分布、金额和 SHA-256，仅保留最多 50 条样本，去除整表 `fetchall()`、JSON 展开和多层深拷贝，额外内存由 `O(审计行及完整 payload)` 降为 `O(样本数 + 分类数)`。

以上路径继续沿用原评分公式、24 小时闭区间、整数中位数、三跳定义、引用有效性、主权清算豁免及排序规则；公开冒烟与补充的 80 组随机单调/乱序窗口差分均通过。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
`runtime.py` 的 `TenantLocks` 仅在查找锁对象时短暂持有注册表锁，业务期间只持有 `(db_path, tenant_id)` 对应的 `RLock`，不同租户可并行执行 Python 业务。

配额消费、双向调拨、令牌核销、委托/授权、策略和风控批次统一遵循：**先取本租户 Python 锁，再 `BEGIN IMMEDIATE`**；不存在进入 SQLite 写事务后反向申请该 Python 锁的路径。`transfer_tenant_quota` 读取和更新均按 `quota_type ASC` 固定偏序，源池条件校验后执行增减并记录流水。消费和告警扣减使用 `remaining_quota >= amount` 条件更新，令牌使用 `used = 0` 条件核销。

`evaluate_transaction_batch` 的滑窗和传染图全是批次私有对象，数据库交易、决策及 `REALTIME_ALERT_POOL` 在同一个连接事务中写入。任何非法交易或主键冲突都会回滚数据库与配额，并直接丢弃尚未发布的窗口、图和结果对象，因此不存在半批落盘、配额泄漏或全局内存污染。补充并发测试确认稀缺配额及应急令牌均只有一个成功者，失败批次首笔交易/决策和告警扣减均无残留。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
- 文档索引与 ACL 是独立对象：`TenantDocumentIndex.epoch` 仅随文档/引用变化推进；`acl_wall.py` 的 `_WallCacheEntry.epoch` 仅随 ACL 快照装载或规则变化推进。修改一条 `doc-acl` 只废弃 ACL 快照，绝不清空文档 postings 或词项位置。
- ACL 快照包含组织父子关系，`WallSnapshot.blocked` 依次执行 USER ALLOW、USER DENY、最近组织节点 DENY 优先的 ALLOW/DENY 裁决，组织链使用 visited 防环。
- 权限、策略和制裁名单不做跨请求结果缓存：每次认证实时计算权限，每个风控事务读取同一策略/名单快照，从源头避免撤权、阈值或名单变更后的陈旧缓存。
- `delegation.py` 的 `_active_delegated_conn` 只沿 `starts_at <= at_ts < expires_at` 的边做最多两跳 BFS，检查每个上游用户 active，并要求链上某个一至二跳源头当前原生持有角色。上游自然过期、撤销或源头角色撤回会即时使下游失效，无需写降级任务。`best_depth` 阻止环路重复扩展；`_would_create_cycle` 在创建前另做有向图检查，直接拒绝成环委托。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
- 检索排序字段改为显式白名单，租户、标签、事件过滤及时间条件全部参数化；`render_saved_report` 不再拼接落库后的租户或事件过滤值。内部引用只通过索引中的同租户 `DocNode` 验证，不再把持久化 `cited_by_ref` 拼进 SQL，也不会用其他租户同名文档增加引用分。
- `audit_export.py` 使用 `string.Formatter.parse` 仅作语法解析，允许 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个纯字段且禁止属性和下标访问、conversion、format spec；保存和读取存量模板时都校验，最终手工拼接，不调用 `str.format`，事件名另有白名单。
- 快照名最多重复解码四次，随后只允许有界 JSON 文件名并拒绝 `..`；最终通过 `Path.resolve()` 要求目标直接位于本租户 `snapshots` 目录，限制文件大小，阻止多重编码、绝对路径、分隔符及符号链接越界。
- `batch-get` 同时约束 tenant、ACTIVE、未隔离、调用者实时密级和 Chinese Wall；决策详情使用 `(tenant_id, decision_id)`；跨租户文档 ID、内部引用和完整正文均不会成为侧信道。
- 健康检查忽略 debug 泄密参数，内部诊断路由关闭，诊断兼容函数也只返回脱敏状态；500 响应不再包含路径、主密钥或堆栈。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
`process_settlement_webhook` 先校验 `±300s` 时间窗，再使用 `hmac.compare_digest` 验证固定长度 HMAC-SHA256；Nonce 有长度限制，并在本租户锁和数据库唯一索引双重保障下原子插入，串行或并发重放均返回冲突。认证同样使用常量时间摘要比较，并对未知身份走 dummy 比较路径。

- `middleware.py` 限制请求体和 URL，扫描原始 JSON 字符串/转义状态并在 `json.loads` **之前**限制嵌套深度，解析后再限制节点数并拒绝 `NaN`/Infinity。
- `safe_regex.py` 将规则正则编译为最多 512 状态的 Thompson NFA，支持常用分组、 alternation、字符类、锚点及有界重复，匹配复杂度有界且无指数回溯；反向引用、lookaround、过深嵌套和大计数重复直接拒绝。
- 规则树最多 256 节点、16 层、每个逻辑节点 32 子节点，IN 列表和正则长度有界；文档引用最多 512 条，交易批次最多 512 笔，批量取文最多 256 个 ID，元数据与查询也有大小/词项预算。
- `runtime.strict_int` 拒绝 bool、非 int、超 SQLite signed-64 位整数；`finite_number` 拒绝非有限数。金额、时间、阈值、配额及规则 bonus 均在边界处校验，配额调拨还检查目标池加法溢出。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：`aegis_app/doc_indexer.py` 的 `DocNode.__slots__`、`TenantDocumentIndex.term_docs / reverse_dependents`、`apply_upsert / apply_state` 实现无完整正文的单篇倒排更新和 `O(deg)` 引用传播；`compute_positions_proximity_bonus` 与 `jaccard_similarity_sets` 实现双指针/距离 1 早停及集合比值剪枝；`window_stats.py::SlidingAccountWindow` 实现双堆中位数与乱序精确回退；`contagion_graph.py::TemporalContagionGraph.hop` 实现复用建边的局部三跳查询；`audit_export.py::_consume_rows` 实现游标流式摘要。
- **[C2 多维纪元与二级借调隔离缓存声明]**：`aegis_app/doc_indexer.py::TenantDocumentIndex.epoch` 与 `aegis_app/acl_wall.py::_WallCacheEntry.epoch / get_wall_snapshot / upsert_doc_acl_rule` 分别维护文档和 ACL 纪元，ACL 变更不销毁文档索引；`aegis_app/delegation.py::_active_delegated_conn` 对每段执行实时窗口、active、源头原生角色及最多两跳核验，`best_depth` 与 `_would_create_cycle` 分别防止解析和创建环路；权限/策略/制裁无跨请求陈旧结果缓存。
- **[C3 统一锁偏序与四重强原子事务声明]**：`aegis_app/runtime.py::TenantLocks` 提供分租户锁；`aegis_app/ledger_ops.py::transfer_tenant_quota` 按租户锁→`BEGIN IMMEDIATE`→quota 名字典序更新，`consume_alert_quota_conn` 在既有事务内条件扣减；`aegis_app/rule_engine.py::evaluate_transaction_batch` 以同一事务包裹交易、决策和告警配额，失败时回滚数据库并丢弃批次私有 `SlidingAccountWindow`、`TemporalContagionGraph` 与结果对象。
- **[C4 双通道二阶安全与越权边界声明]**：`aegis_app/audit_export.py::_parse_template / render_saved_report / read_compliance_snapshot` 落实三字段白名单、禁止格式规格和手工渲染，以及多重解码后文件名白名单与 `resolve()` 目录锚定；`aegis_app/doc_indexer.py::_valid_ref` 要求内部引用源位于本租户索引且 ACTIVE/未隔离；`aegis_app/search_service.py::batch_get_documents` 和 `rule_engine.py::get_risk_decision_detail` 落实租户、状态、密级、ACL 与决策归属隔离。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：`aegis_app/safe_regex.py::_NFA / safe_regex_search` 以有界 NFA 取代用户正则回溯；`aegis_app/middleware.py::_preflight_json / _validate_json_tree` 在解析前后限制深度、节点及非有限数；`aegis_app/rule_engine.py::validate_rule_tree / _normalize_transaction`、`doc_writer.py` 和 `server.py` 落实规则、交易、引用及路由预算；`aegis_app/runtime.py::strict_int / finite_number / bounded_text` 集中拒绝 bool、超 64 位整数、NaN/Inf 和超长文本。

## 5. 已知工程取舍与残余边界说明
- 索引与 ACL 快照是单进程内缓存，适用于题目规定的网关进程；启动时会从既有 SQLite 数据流式建立索引。同进程多个网关实例共享缓存，但绕过网关的外部进程直接改库不会主动推送失效通知。
- WAL 改善读写并发，但 SQLite 仍会在数据库层串行实际写事务；本实现缩短写事务并避免 Python 跨层死锁，不声称提供多写者能力。
- 去重经法规分块和集合比值剪枝后，极端情况下一个巨大同法规且尺寸相近的簇仍可能呈二次比较上界；这是为保留原代表选择与簇计数语义所作取舍。
- 正则采用安全常用子集，主动拒绝反向引用、lookaround 与内联高级构造；窗口乱序采用精确重建而非冒用单调增量结果。常驻索引仍需保存检索词项和位置，但完整原始正文不常驻，审计导出不随总行数积累内存。
