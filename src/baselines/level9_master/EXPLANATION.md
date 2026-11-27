# AegisGate 性能优化与安全加固技术阐述（9.5级疾风铁盾殿堂大师校准基线 · v3.0）

## 1. 性能瓶颈诊断与增量算法降维重构方案
- **连接池与复合覆盖索引（`db.py`）**：开启 SQLite `WAL` 并发读写模式，通过有界线程本地连接池 `get_thread_connection` 复用持久连接，并建立 14 条跨列复合覆盖索引与唯一防重放索引。
- **紧凑单篇增量倒排、双向引用局部传播与双指针词距（`doc_indexer.py`、`search_service.py`、`doc_writer.py`）**：`IndexedDoc` 使用 `__slots__` 仅驻留 140 字摘要与词位置元组（剔除原始大体积正文，将常驻堆内存净增量压制在极低预算内）；`TenantDocIndex` 同时维护 `raw_refs_by_doc` 与反向引用依赖映射 `reverse_dependents`，当单篇文档发生 `upsert`/`retire`/`quarantine` 时，`sync_single_doc_in_index` 执行写时复制单篇 $O(L + \text{deg})$ 差量替换并调用 `with_updated_citation_count` 原地局部刷新受影响被引用文档的 `citation_count` 与 `base_score`，零整表扫描；短语邻近度采用 $O(|P_1|+|P_2|)$ 双指针扫描并在 `min_dist == 1` 时立即短路退出；双轨法规折叠通过 `canonicalize_regulation_code` 分桶与集合大小比值下界剪枝消除无效交并集。
- **$O(\log W)$ 单调滑窗中位数与有界两层多源传染追踪（`window_stats.py`、`contagion_graph.py`、`rule_engine.py`）**：`SlidingAccountWindow` 结合 `deque` 与 `bisect` 有序列表实现单调流 $O(\log W)$ 精确动态中位数与对手方引用计数，并内置乱序时间戳自动回退切片保底；三跳制裁传染按批次一次性拉取活跃窗口边，从纪元缓存黑名单源点执行最多两层前沿扩展；审计与自定义报表统一复用 `cur.fetchmany(256)` 轻量列游标流式扫描。

## 2. 跨模块并发锁偏序、二级借调快照与多维缓存一致性设计
- **64 路细粒度键级分片锁与全局统一锁偏序（`db.py`、`ledger_ops.py`、`rule_engine.py`）**：跨租户读写无锁并行；针对跨池双向配额调拨 `transfer_tenant_quota` 与批次风控 `evaluate_transaction_batch`（含 `REJECT` 交易联动扣减 `REALTIME_ALERT_POOL`）的交叉竞争，通过可变参 `acquire_ordered_striped_locks` 在进入 `BEGIN IMMEDIATE` 前严格按分片号全局升序一次性获取所需全部 Python 锁，并在单一 SQLite 事务内完成数据库记录、滑窗、传染图与 `REALTIME_ALERT_POOL` 配额的四位一体强原子提交/回滚，从数学上根除 AB-BA 死锁与半批配额泄漏。
- **五维独立纪元（`perm` / `acl` / `doc` / `policy` / `sanction`）与二级无环借调内存快照（`delegation.py`、`acl_wall.py`）**：修改利益冲突隔离墙仅递增 `acl` 纪元，绝不连带清空租户倒排索引；`_compute_role_hops_from_snapshot` 在内存内执行两层定界无环求值，精确核验 1~2 跳 `[starts_at, expires_at)` 双窗口交集及源头/中间节点实时资格（上游一级窗口自然到期无需写操作即零延迟自动降级，且免疫任意有向委托环路），检索缓存同时绑定五维纪元双检守卫与实时 `max_clearance` / `denied_doc_ids` 签名。

## 3. 纵深安全加固清单（漏洞根因 -> 修复机制）
- **一阶与双通道二阶 SQL 注入及跨租户引用侧信道阻断**：`search_documents` 全参数化绑定与排序白名单；`save_report_template` / `render_saved_report` 对 `extra_event_filter` 执行白名单校验并使用 `event_type = ?` 参数化绑定；`doc_writer.py` 使用 `SAFE_CITATION_REF_RE` 拦截恶意引用字符，且 `_count_effective_citations` 严格限定内部 `doc_` 引用仅在本租户活跃非隔离集合内计分，彻底封堵二阶注入与跨租户文档存在性侧信道。
- **报表模板沙箱逃逸/宽度放大与内部诊断泄露封堵**：废弃 `str.format(..., env=RUNTIME_ENV)`，改为 `_validate_and_render_title` 严格限制仅替换 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个纯字面占位符（拦截属性/下标反射与超宽格式说明符内存放大）；关闭 `/api/v1/internal/diagnostics`，剥离 `/api/v1/health?debug=1` 与 `500` 异常堆栈敏感回显。
- **多维越权、目录穿越、并发重放与全变体复杂度熔断**：`batch_get_documents` 强制执行租户、状态、密级与 `denied_doc_ids` 四重过滤；`authenticate_caller` 实施未知租户/用户常量时间 dummy 掩蔽；`read_compliance_snapshot` 拦截双重 URL 编码、空字节并用 `resolve().is_relative_to()` 锚定物理目录；Webhook 强制常量时间验签、300 秒窗口与 `(tenant_id, nonce)` 唯一约束防重放；`middleware.py` 在 `json.loads` 前执行 $O(N)$ 词法深度预检（`<=32`）并拒绝 `NaN`/`Infinity`；`rule_engine.py` 采用零回溯邮箱校验，拦截嵌套量词、多通配链、反向引用与超限花括号量词（`>32`），限制规则树深度/扇出与引用列表上限，全链路通过 `require_strict_int` 拦截布尔伪装整数与超 64 位溢出。

## 4. 核心工程声明（供盲评逐条核验代码）
- **[C1 增量索引与算法降维声明]**：已在 `aegis_app/search_service.py` 实现含 `reverse_dependents` 反向引用传播的 `sync_single_doc_in_index` 单篇 $O(L + \text{deg})$ 差量更新，并在 `aegis_app/doc_indexer.py` 实现 `__slots__` 紧凑节点（剔除原始正文驻留）与 `compute_phrase_proximity_bonus_indexed` 双指针短路扫描。
- **[C2 多维纪元与二级借调隔离缓存声明]**：已在 `aegis_app/db.py`、`aegis_app/acl_wall.py` 与 `aegis_app/delegation.py` 分离五维纪元，通过 `_compute_role_hops_from_snapshot` 实现 1~2 跳无环秒级双窗口核验与上游过期/撤权即时级联失效。
- **[C3 统一锁偏序与四重强原子事务声明]**：已在 `aegis_app/db.py`、`aegis_app/ledger_ops.py` 与 `aegis_app/rule_engine.py` 实现可变参 `acquire_ordered_striped_locks` 升序分片锁 + `BEGIN IMMEDIATE` 单事务，确保跨池双向调拨与批次风控 `REJECT` 扣减 `REALTIME_ALERT_POOL` 零死锁且异常时四重状态强原子回滚。
- **[C4 双通道二阶安全与越权边界声明]**：已在 `aegis_app/audit_export.py` 实现 `_validate_and_render_title` 纯字面占位符替换与 `event_type = ?` 参数化流式扫描，并在 `aegis_app/doc_writer.py` 与 `aegis_app/search_service.py` 实现 `SAFE_CITATION_REF_RE` 与 `_count_effective_citations` 本租户边界隔离。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：已在 `aegis_app/middleware.py` 实现 `check_json_nesting_depth` 词法预检与 `NaN`/`Infinity` 拦截，在 `aegis_app/rule_engine.py` 实现 `_compile_safe_regex` 与 `validate_rule_tree_budget`，并在 `aegis_app/db.py` 实现 `require_strict_int` 拦截 `bool` 与超 64 位整数。

## 5. 已知工程取舍与残余边界说明
进程内五维纪元、双向引用内存快照与 `BEGIN IMMEDIATE` 统一锁偏序针对单机多线程网关压榨至微秒级读取延迟、极低常驻内存增量与严格可串行化写事务；若未来横向扩展为多节点无共享集群，可将五维纪元号与配额账本下沉至共享事务存储协调。
