# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理
1. **短连接高频重建与无索引全表扫描**：原系统每次请求及循环内部（如 `acl_wall.get_org_lineage`、`delegation._collect_upstream_grantors`、`search_service.search_documents`、`rule_engine.evaluate_transaction_batch`）频繁调用 `open_connection` 打开/关闭 SQLite 短连接，且 `SCHEMA_SQL` 缺少二级复合索引。本次在 `aegis_app/db.py` 的 `SCHEMA_SQL` 中为组织树、用户、角色授予、借调委托、隔离墙规则、黑名单、合规文档检索、双向引用、交易时间窗、决策查询、Webhook 防重放（`idx_webhook_tenant_nonce` 唯一索引）与审计流水共补齐 19 个复合/唯一索引，并在 `init_schema` 中开启 `PRAGMA journal_mode = WAL` 与 `PRAGMA synchronous = NORMAL`，在 `open_connection` 中配置 `temp_store = MEMORY`、`cache_size = -16384` 与 `busy_timeout = 30000`。
2. **有界连接池与串行化写事务**：在 `aegis_app/runtime.py` 的 `GatewayRuntime` 中实现最大容量 `MAX_POOL_SIZE = 32` 的线程安全 SQLite 连接池（`acquire_conn`/`release_conn`/`connection`）及基于 `_db_write_lock` + `BEGIN IMMEDIATE` 的 `write_tx()` 上下文管理器，使 WAL 模式下多线程读并发不阻塞，写事务在 Python 层无竞争排队而避免 `SQLITE_BUSY` 重试抖动。
3. **跨模块查询放大消除**：将风控批次循环内逐笔扫描 `transactions` 全表、合规检索循环内逐篇回查权限与 `doc_citations` 表的 $N+1$ 查询，全部收敛为增量内存索引命中、单次权限解析与按主键批量回表。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制
1. **紧凑单篇增量倒排与双向引用联动（`aegis_app/runtime.py`、`aegis_app/doc_writer.py`、`aegis_app/search_service.py`）**：
   - 使用 `__slots__` 定义 `CompactDocNode`，**绝不在内存中保留原始大正文 `body`**，仅保留 140 字符 `snippet`、排序整数词 ID 数组 `uniq_token_ids`（`array('I')`）、去重引用集合 `ext_refs`/`int_refs` 与实时有效引用计数 `valid_citation_count`。
   - `TenantDocIndex.postings` 将词频直接压缩进单个整型字节 `(min(title_tf, 5) << 4) | min(body_tf, 12)`。文档 `upsert` 时通过 `apply_upsert` 仅删除该篇旧词条并增量写入新词条；对正文位置序列维护硬上限为 `512` 篇且总词槽不超过 `262144`（约 1 MB）的 `body_token_lru`，仅当检索命中多词且正文中存在相邻查询词对且未命中 LRU 时按主键分批回表，大幅压缩常驻堆内存。
   - 维护 `reverse_dependents: dict[str, set[str]]` 反向引用图：当源文档经 `upsert`/`retire`/`quarantine` 发生 `ACTIVE & unquarantined` 有效性翻转时，`apply_upsert` 与 `apply_status_change` 仅遍历直接引用方集合以 $O(\text{deg})$ 精确加减 `valid_citation_count`，消除整租户重建。
2. **短语词距与双轨法规近似聚类降维（`aegis_app/doc_indexer.py`、`aegis_app/search_service.py`）**：
   - `compute_phrase_proximity_bonus` 与 `compute_phrase_proximity_from_ids` 改用单趟位置收集 + `_min_two_pointer_dist` 双指针归并扫描（将 $O(|P_a|\cdot|P_b|)$ 降至 $O(|P_a|+|P_b|)$），并在命中 `min_dist == 1` 时立即早停。
   - 去重阶段按非空归一化法规号 `canon_reg` 分桶（不同桶或空编号免于两两比对），并在 `jaccard_from_sorted_ids` 中先执行集合大小比值上界剪枝 `min_l / max_l < DEDUP_JACCARD_THRESHOLD`（$O(1)$ 跳过），再用有序 `array('I')` 双指针计算交并比。
3. **四维滑动窗口精确中位数与 3-Hop 制裁传染降维（`aegis_app/window_stats.py`、`aegis_app/contagion_graph.py`）**：
   - `window_stats.py` 淘汰 $O(W^2)$ 冒泡排序，实现基于惰性删除对顶堆的 `DualHeapMedian`（插入/淘汰 $O(\log W)$、中位数查询 $O(1)$）与 `AccountWindowState`：单调时间戳走 `push_monotonic` $O(\log W)$ 快路径，遇到乱序时间戳（`ts < max_ts`）自动回退到复合索引 `idx_tx_tenant_acct_ts` 区间扫描结合批内暂存列表精确重算，并同步有序插入窗口以保持后续单调路径一致。
   - `contagion_graph.py` 将逐笔全表扫描 + `list.pop(0)` BFS 替换为基于 `TenantRiskState.adj`（按边时间戳二分查找 `bisect_left` 验证 `[ts - 86400, ts]` 窗口）的 `compute_sanction_contagion_hop_fast`，采用双向自适应 1-Hop 扩展（按受制裁集与端点 1-Hop 邻域的度数代价选择较小侧扩展），在 $O(\min(\deg(S), \deg(N_1)))$ 内判定 1/2/3 跳传染并立即早停。
4. **流式游标审计导出（`aegis_app/audit_export.py`）**：
   - 去除 `fetchall()`、无用的 `json.loads(payload_json)` 及双份 `copy.deepcopy`，改用 `_stream_digest_from_cursor` 仅查询摘要所需的 6 个字段并按 `2048` 行分批 `fetchmany` 流式推进 `rolling_sha256` 与统计计数，常驻堆空间降至 $O(1)$。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制
1. **全局严格锁偏序（DAG）**：在 `GatewayRuntime` 中建立跨租户隔离、租户内严格有序的锁层级：
   - 文档域：`doc_lock(tenant_id)` -> `write_tx()`（`_db_write_lock`）；
   - 权限/隔离墙域：`perm_lock(tenant_id)` / `acl_lock(tenant_id)` -> `write_tx()`；
   - 风控与配额域：`risk_lock(tenant_id)` -> `quota_lock(tenant_id, quota_type)`（双池调拨通过 `quota_pair_locks` 严格按 `quota_type` 字典序加锁）-> `write_tx()`；
   - 令牌域：`token_lock(tenant_id, token_id)` -> `write_tx()`。
   不同租户锁实例完全独立，并发读写互不阻塞；同租户内 `evaluate_transaction_batch`（`risk_lock -> quota_lock(REALTIME_ALERT_POOL) -> write_tx`）与 `transfer_tenant_quota`（`quota_pair_locks -> write_tx`）严格同向加锁，从根源杜绝死锁与跨层丢失更新。
2. **单池/令牌并发原子 SQL**：`consume_tenant_quota`、`try_consume_realtime_alert_quota` 与 `redeem_override_token` 均在对应资源锁及 `BEGIN IMMEDIATE` 事务中执行带条件的原子更新（`WHERE remaining_quota >= ?` / `WHERE used = 0`），彻底杜绝超扣或重复核销。
3. **四位一体强原子批处理与回滚（`aegis_app/rule_engine.py`）**：`evaluate_transaction_batch` 先完成全批参数校验，再在 `risk_lock` + `quota_lock(REALTIME_ALERT_POOL)` 保护下对窗口推演记录 `window_undos`、批内图边写入临时 `staged_edges`、计算应扣减的告警配额总量 `alert_consumed`，随后在单次 `write_tx()` 中执行配额扣减与 `transactions`/`risk_decisions` 批量落盘；仅当数据库 `COMMIT` 成功后才将 `staged_edges` 合入 `risk_state.adj`。若批次中任一笔抛出异常或触发主键冲突（`sqlite3.IntegrityError`），数据库自动 `ROLLBACK`，`except` 块调用 `AccountWindowState.rollback` 还原所有受影响账户滑窗，`staged_edges` 直接丢弃，`REALTIME_ALERT_POOL` 零扣减，实现四维状态零污染。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制
1. **五维独立纪元解耦**：`TenantDocIndex.doc_epoch`、`TenantAclState.acl_epoch`、`TenantPermState.perm_epoch`、`TenantRiskState.policy_epoch` 与 `sanction_epoch` 严格独立。配置单条 `doc-acl` 仅局部增量更新 `TenantAclState.rules_by_doc[doc_id]` 并递增 `acl_epoch`，绝不清空文档倒排索引或重置其他状态。
2. **二级借调级联与零写过期失效（`aegis_app/runtime.py`、`aegis_app/delegation.py`）**：`TenantPermState` 缓存组织树节点与原生/授予角色，并在 `resolve_active_delegated_roles(grantee_user_id, at_ts)` 中针对每个候选角色执行受 `MAX_DELEGATION_HOPS = 2` 与 `visited` 集合约束的有向无环 BFS：逐段验证边 `starts_at <= at_ts < expires_at`、上游委托人 `active == 1` 以及源头持有者原生角色仍在 `native_roles` 中。即便无任何数据库写入，当请求时间戳 `_now_ts` 越过上游 1 跳窗口上限时，下游 2 跳角色立即自动降级；一旦源头角色被 `grants/revoke` 撤回或上游被撤销，下次权限解析立即级联失效。
3. **三级利益冲突墙快速裁决（`aegis_app/acl_wall.py`）**：利用预计算的组织节点链 `org_lineages` 与 `TenantAclState.rules_by_doc` 在内存中按 `USER ALLOW > USER DENY > 最近 ORG_NODE（同节点 DENY 优先） > 默认放行` 三级优先级执行 $O(1)$ 或 $O(\text{tree\_depth})$ 裁决。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断
1. **一阶与双通道二阶 SQL 注入修复**：
   - `search_service.py` 严格白名单校验 `sort_by in {"score", "updated_at", "risk_weight"}` 与 `sort_dir in {"asc", "desc"}`，并将 `tenant_id`、`category`、`tag_filter` 全部改为参数化查询，同时将有效引用计数统计收归租户内 `TenantDocIndex`（写库时 `doc_citations` 亦全参数化写入），根治 `search` 一阶注入与 `doc_citations` 二阶注入。
   - `audit_export.py` 的 `save_report_template` 与 `render_saved_report` 对 `extra_event_filter` 执行 `^[A-Z0-9_]{1,64}$` 严格校验并在渲染查询中全参数化绑定 `tenant_id` 与 `event_type`，彻底消除报表模板通道二阶 SQL 注入。
2. **模板沙箱防反射与宽度放大阻断**：移除 `render_saved_report` 对危险 `str.format` 及 `env=RUNTIME_ENV` 的调用；在 `validation.py` 实现 `validate_title_format` 与 `render_safe_title`，仅放行 `{tenant_id}`、`{total_records}`、`{total_amount_cents}` 三个字面占位符并采用单趟正则字面替换，完全免疫属性反射泄密与 `:0>200000` 宽度放大攻击。
3. **多变体目录穿越阻断**：`audit_export.read_compliance_snapshot` 拒接空字节、反斜杠、`%` 二次编码、冒号、绝对路径、`..`/`."` 段与符号链接，先逐级验证无 `is_symlink()`，再经 `resolve().is_relative_to(base_dir)` 锚定在租户 `snapshots/` 目录内。
4. **跨租户越权、引用侧信道与信息泄密消除**：
   - `TenantDocIndex` 按租户物理隔离引用解析，`doc_` 内部引用仅匹配本租户内 `ACTIVE` 且未隔离文档，阻断跨租户引用计数预言机。
   - `search_service.batch_get_documents` 强制校验 `tenant_id`、`status='ACTIVE'`、`quarantined=0`、`clearance_level <= live_clearance` 与 `is_doc_blocked_by_acl`。
   - `rule_engine.get_risk_decision_detail` 强制增加 `tenant_id = ?` 过滤，封堵跨租户决策 IDOR。
   - `doc_writer.upsert_compliance_document` 对已存在文档追加 `is_doc_blocked_by_wall` 校验。
   - `server.py` 与 `middleware.py` 移除 `/api/v1/internal/diagnostics` 路由、关闭 `/api/v1/health?debug=1` 诊断信息输出、将 `collect_internal_diagnostics` 脱敏，并将 500 响应收敛为通用提示（严禁输出 `traceback`、物理路径或 `MASTER_SIGNING_PEPPER`）。
   - `auth.authenticate_caller` 对未知租户、未知/停用用户及凭证比对均执行 `hmac.compare_digest` 与哑哈希比对掩蔽，消除认证枚举时序侧信道。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界
1. **Webhook 常量时间验签与并发防重放（`aegis_app/auth.py`）**：使用 `hmac.compare_digest` 验证签名（未知租户亦做哑 HMAC 计算），校验 `abs(now_ts - callback_ts) <= WEBHOOK_TOLERANCE_SECONDS (300)` 时间窗，并依靠 `write_tx()` + `idx_webhook_tenant_nonce` 唯一索引实现串行与高并发重复 Nonce 的 409 原子拦截。
2. **抗多变体复杂度炸弹（`aegis_app/validation.py`、`aegis_app/rule_engine.py`、`aegis_app/delegation.py`）**：
   - 重写线性时间 `validate_contact_email`，消除 `PARTNER_EMAIL_PATTERN` 灾难性回溯 ReDoS；
   - 实现 `validate_safe_regex` 静态审计用户规则正则，拒绝长度 `> 200`、反向引用、环视断言、嵌套量词、带量词分组内的内层量词或分支 `|` 以及上界 `> 64` 的花括号量词，并限制正则输入长度 `<= 4096`；
   - `precheck_json_raw` 在 `json.loads` 之前完成 `O(N)` 字节上限（4 MB）与括号嵌套深度（`<= 32`）预检，并通过 `parse_constant` 禁止非有限常量 `NaN`/`Infinity`；
   - `validate_rule_tree` 限制规则树深度 `<= 12` 与总节点数 `<= 128`；`doc_writer` 限制单次引用数 `<= 256`；`delegation.create_or_revoke_delegation` 通过 `has_delegation_path` 拒绝成环委托，`resolve_active_delegated_roles` 通过 `visited` + `MAX_DELEGATION_HOPS` 免疫存量环路。
3. **严格类型与数值边界守卫（`aegis_app/validation.py`）**：`strict_int` 与 `strict_finite_float` 明确拒绝 `bool`（消除 Python `isinstance(True, int)` 混淆）、浮点数、非有限数及超出有符号 64 位整数范围的值；`eval_rule_node` 对 `EQ`/`NEQ` 区分布尔与整型，对 `GT`/`GTE`/`LT`/`LTE` 强制有限浮点校验。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：在 `aegis_app/runtime.py` 中通过基于 `__slots__` 的 `CompactDocNode`（不保留原始 `body`）与 `TenantDocIndex`（位打包 `postings`、`reverse_dependents` 反向引用图及硬上限 512 篇 / 262144 词槽的 `body_token_lru`）实现单篇增量更新与 $O(\text{deg})$ 引用传导；在 `aegis_app/doc_indexer.py` 通过 `compute_phrase_proximity_from_ids` / `_min_two_pointer_dist`（`min_dist == 1` 早停）与 `jaccard_from_sorted_ids`（大小比值剪枝 + 双指针）降维检索与聚类；在 `aegis_app/window_stats.py`、`aegis_app/contagion_graph.py` 与 `aegis_app/audit_export.py` 中分别通过 `DualHeapMedian` / `AccountWindowState`（$O(\log W)$ 单调快路径 + 乱序回退）、`compute_sanction_contagion_hop_fast`（双向自适应 1-Hop 扩展）及 `_stream_digest_from_cursor`（`fetchmany(2048)` 流式游标）完成复杂度与堆内存压缩。
- **[C2 多维纪元与二级借调隔离缓存声明]**：在 `aegis_app/runtime.py` 中将 `TenantDocIndex`（`doc_epoch`）、`TenantAclState`（`acl_epoch`）、`TenantPermState`（`perm_epoch`）与 `TenantRiskState`（`policy_epoch`、`sanction_epoch`）彻底解耦；`aegis_app/acl_wall.py` 的 `upsert_doc_acl_rule` 仅增量更新 `TenantAclState` 而不触碰文档索引；`aegis_app/delegation.py` 与 `TenantPermState.resolve_active_delegated_roles` 在 `MAX_DELEGATION_HOPS = 2` 及 `visited` 防环约束下实时核验整条 1~2 跳链路时间窗 `[starts_at, expires_at)` 与源头原生角色，并在 `create_or_revoke_delegation` 中调用 `has_delegation_path` 阻止成环。
- **[C3 统一锁偏序与四重强原子事务声明]**：在 `aegis_app/runtime.py` 的 `GatewayRuntime` 中建立 `risk_lock(tenant) -> quota_lock/quota_pair_locks(按 quota_type 字典序) -> write_tx(BEGIN IMMEDIATE)` 的全局无环锁偏序；`aegis_app/ledger_ops.py` 的 `transfer_tenant_quota`、`consume_tenant_quota` 与 `redeem_override_token` 均采用有序锁 + 条件原子更新；`aegis_app/rule_engine.py` 的 `evaluate_transaction_batch` 在统一锁序下暂存 `window_undos`、`staged_edges` 与 `alert_consumed`，仅在单次 `write_tx()` 成功落盘交易、决策与 `REALTIME_ALERT_POOL` 扣减后提交内存图谱，异常时调用 `AccountWindowState.rollback` 与事务回滚实现四位一体强原子还原。
- **[C4 双通道二阶安全与越权边界声明]**：在 `aegis_app/search_service.py`、`aegis_app/audit_export.py` 与 `aegis_app/validation.py` 中对检索排序/过滤与报表模板事件过滤实施白名单与全参数化查询，在 `render_saved_report` 使用 `validate_title_format`/`render_safe_title` 彻底替换 `str.format` 与 `RUNTIME_ENV` 注入，在 `read_compliance_snapshot` 实行解码防绕过、禁符号链接与 `resolve().is_relative_to(base_dir)` 锚定；`TenantDocIndex` 严格限定 `doc_` 引用在本租户内解析，并在 `batch_get_documents`、`get_risk_decision_detail`、`upsert_compliance_document`、`authenticate_caller` 与 `server.py` 全面补齐跨租户、密级、隔离墙、哑比对掩蔽及脱敏报错边界。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：在 `aegis_app/validation.py` 中实现线性时间 `validate_contact_email`、`precheck_json_raw`（`json.loads` 前完成深度 `<= 32` 与字节数预检及非有限常量拦截）、`validate_safe_regex`（阻断嵌套量词、带量词分组内分支/量词、反向引用、环视与 `> 64` 花括号）及拒绝 `bool` 与越界 64 位整数的 `strict_int`/`strict_finite_float`；并在 `rule_engine.py`（`validate_rule_tree`）、`doc_writer.py`（引用数上限）、`auth.py`（`process_settlement_webhook` 时间窗与唯一索引防重放）及 `server.py`（入参类型与 `Content-Length` 守卫）中全面落地硬熔断。

## 5. 已知工程取舍与残余边界说明
1. **单机进程内增量快照假定**：`GatewayRuntime` 假设网关启动后对该 SQLite 数据库的在线业务写入均经由本进程网关实例完成；若在网关运行时从外部进程直接篡改数据库行而不重启/重建网关实例，内存增量状态不会自动感知。
2. **SQLite 单库写锁串行边界**：为彻底消除多线程高并发写下的 `SQLITE_BUSY` 抖动并保证批处理四重强原子性，`GatewayRuntime.write_tx` 通过单库 `_db_write_lock` 串行化 `BEGIN IMMEDIATE` 写入（而 WAL 读查询与各租户内存计算保持全并发），在单机高吞吐场景下写事务提交吞吐受限于单 SQLite 文件的磁盘 fsync 速率（已通过 `synchronous = NORMAL` 缓解）。
3. **大文档超多词命中时的小幅回表开销**：为严格守住常驻堆内存预算，未将全部原始 `body` 或全量位置倒排常驻内存，而是采用 512 篇 / 1 MB 上限的 `body_token_lru`；当极端多词查询命中海量正文且超出 LRU 容量时，会退化为按主键分批回表 `compliance_docs` 提取正文。
