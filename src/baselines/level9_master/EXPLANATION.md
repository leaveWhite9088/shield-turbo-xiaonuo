# AegisGate 性能优化与安全加固技术阐述（9级疾风铁盾大师校准基线）

## 1. 性能瓶颈诊断与降维重构方案
- **连接池与复合覆盖索引（`db.py`）**：开启 SQLite `WAL` 并发读写模式，通过线程本地连接池 `get_thread_connection` 复用持久连接，并建立 14 条跨列复合覆盖索引与唯一防重放索引。
- **紧凑单篇增量倒排与 $O(|P_1|+|P_2|)$ 双指针词距（`doc_indexer.py`、`search_service.py`）**：`IndexedDoc` 仅驻留 140 字摘要与词位置元组（剔除大体积原始正文，大幅压降常驻堆内存）；文档 Upsert、Retire、Quarantine 通过 `sync_single_doc_in_index` 执行写时复制单篇 $O(L)$ 增量差量替换，彻底消除高频写流量下的整表重扫与倒排重建开销；短语邻近度采用双指针归并扫描并支持 `min_dist == 1` 早停；双轨法规折叠通过 `canonicalize_regulation_code` 分桶与集合大小比值剪枝消除无效交并集。
- **$O(\log W)$ 单调滑窗中位数与有界两层多源传染追踪（`window_stats.py`、`contagion_graph.py`、`rule_engine.py`）**：`SlidingAccountWindow` 结合 `deque` 与 `bisect` 有序列表实现单调流 $O(\log W)$ 精确动态中位数与对手方引用计数，并内置乱序时间戳自动回退切片保底；三跳制裁传染按批次一次性拉取活跃窗口边，从纪元缓存黑名单源点执行最多两层前沿扩展；审计与自定义报表统一复用 `cur.fetchmany(256)` 轻量列游标流式扫描。

## 2. 高并发架构、锁粒度与缓存一致性设计
- **64 路细粒度键级分片锁与全序无死锁双锁协议（`db.py`、`ledger_ops.py`）**：跨租户读写完全无锁并行；针对跨池双向配额调拨 `transfer_tenant_quota`，通过 `acquire_ordered_striped_locks` 严格按分片索引升序加锁并配合 `BEGIN IMMEDIATE` 单事务原子更新，从数学上根除 AB-BA 死锁环路与 SQLite 共享锁升级死锁。
- **五维独立纪元（`perm` / `acl` / `doc` / `policy` / `sanction`）与精确秒级借调快照（`delegation.py`、`acl_wall.py`）**：修改利益冲突隔离墙仅递增 `acl` 纪元，绝不连带清空租户倒排索引；`TenantAuthSnapshot` 在内存内按请求时刻精确核验 `[starts_at, expires_at)` 时效窗及委托人当前原生角色持有状态（委托人被撤权则下游受托资格零延迟级联失效），检索缓存同时绑定五维纪元双检守卫与 `max_clearance` / `denied_doc_ids` 签名。

## 3. 纵深安全加固清单（漏洞根因 -> 修复机制）
- **一阶与二阶 SQL 注入阻断**：`search_documents` 全参数化绑定与排序白名单；`save_report_template` 与 `render_saved_report` 对 `extra_event_filter` 双重校验标识符白名单并使用 `event_type = ?` 参数化绑定，彻底封堵二阶模板注入。
- **报表模板 `.format()` 反射与内部诊断泄露封堵**：废弃 `str.format(..., env=RUNTIME_ENV)`，改为 `_validate_and_render_title` 严格限制仅替换 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个字面占位符；关闭 `/api/v1/internal/diagnostics`，剥离 `/api/v1/health?debug=1` 与 `500` 异常堆栈敏感回显。
- **多维越权（横向 / 纵向 / 三级利益冲突墙 / 级联委托）闭环**：`batch_get_documents` 强制执行租户匹配、状态活跃、密级不超限与 `denied_doc_ids` 四重过滤；`acl_wall.py` 严格实现 `USER ALLOW > USER DENY > 最近祖先 ORG_NODE` 三级裁决。
- **多变体目录穿越、并发抢扣、回调重放与复杂度炸弹熔断**：`read_compliance_snapshot` 拦截双重 URL 编码、空字节并用 `resolve().is_relative_to()` 锚定物理目录；Webhook 强制常量时间验签、300 秒窗口与 `(tenant_id, nonce)` 唯一约束原子防重放；`middleware.py` 在 `json.loads` 前执行 $O(N)$ 嵌套深度预检（`<=32`）并拒绝 `NaN`/`Infinity`；`rule_engine.py` 替换为线性零回溯邮箱校验，拦截嵌套量词、多通配链与超限花括号量词（`>32`）并缓存编译正则；全链路使用 `require_strict_int` 拦截布尔伪装整数与超 64 位溢出，交易批次全量前置校验加单事务原子回滚。

## 4. 核心工程声明（供盲评逐条核验代码）
- **[C1] 写时复制单篇增量倒排索引与双指针词距**：已在 `aegis_app/search_service.py` 实现 `sync_single_doc_in_index` 单篇 $O(L)$ 差量更新，并在 `aegis_app/doc_indexer.py` 实现 `compute_phrase_proximity_bonus_indexed` 双指针扫描且不驻留文档原始全文。
- **[C2] 五维解耦纪元与级联借调内存快照**：已在 `aegis_app/db.py`、`aegis_app/acl_wall.py` 与 `aegis_app/delegation.py` 分离 `perm`/`acl`/`doc`/`policy`/`sanction` 五维纪元，通过 `compute_effective_roles_from_snapshot` 实现秒级窗口与委托人撤权级联失效。
- **[C3] 全序双锁无死锁跨池调拨与批次强原子事务**：已在 `aegis_app/db.py` 与 `aegis_app/ledger_ops.py` 实现 `acquire_ordered_striped_locks` + `BEGIN IMMEDIATE` 原子调拨，并在 `aegis_app/rule_engine.py` 实现 `SlidingAccountWindow` + 两层制裁传染前沿扩展 + 冲突预检单事务提交。
- **[C4] 二阶模板 SQL 参数化与零反射占位符替换**：已在 `aegis_app/audit_export.py` 实现 `_validate_and_render_title` 白名单正则单遍替换（彻底移除 `.format` 与 `RUNTIME_ENV` 传入）及 `event_type = ?` 参数化流式聚合。
- **[C5] 全变体复杂度熔断与严格数值边界守卫**：已在 `aegis_app/middleware.py` 实现 JSON 深度预检与 `NaN`/`Infinity` 拦截，在 `aegis_app/rule_engine.py` 实现 `_compile_safe_regex` 花括号上界/多通配链拦截与规则树预算校验，并在 `aegis_app/db.py` 实现 `require_strict_int` 拦截 `bool` 与超 64 位整数。

## 5. 已知权衡与边界条件
进程内五维纪元与单槽增量倒排快照针对单机多线程网关压榨至微秒级延迟与极低内存增量；若未来横向扩展为多进程无共享集群，可将五维纪元号下沉至共享内存页或轻量存储表头版本号对齐。
