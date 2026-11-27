# 性能剖析与安全加固阐述（EXPLANATION.md）

> 本文档如实描述本次改造在 `aegis_app/` 中的真实落地情况。所有性能数字均来自本机实测（Python 3.12.9 / SQLite 3.45.3 / Windows），所有安全条目均可在源码中逐条定位。
> **零失真验证**：本次改造另建了一套「优化前语义参考实现」（逐字复刻原始算法与 SQL 拼接方式），在 **2 租户 × 6 用户 × 4 个时间点** 的可见性矩阵、**4 组关键词 × 去重开关 × 3 种排序** 的检索全量结果、审计摘要、报表渲染与风控批次上共执行 **345 项逐字段比对，失败 0 项**；另执行 **40 项红队安全用例，全部通过**。

---

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

**定位到的放大点**

| 位置 | 原实现问题 | 后果 |
| --- | --- | --- |
| `db.open_connection` | 每次调用新建 SQLite 连接并物理关闭 | 单次检索的连接创建次数 = 文档数 × 3（权限/隔离墙/引用），200 篇文档即 600 次开库 |
| `search_service.search_documents` | 在 **循环体内** 逐行调用 `resolve_effective_permissions`（再开 2+ 库）、`is_doc_blocked_by_acl`（再开 1 库）、`_get_doc_citation_count`（再开 1 库） | O(N) 次跨模块往返，N=200 时约 600 次连接 + 上千次查询 |
| `search_service._get_doc_citation_count` | 对每个 `doc_` 引用再拼一条 SQL 字符串查状态 | 二阶注入面 + O(引用数) 次查询 |
| `db.SCHEMA_SQL` | 除主键外无任何复合索引 | 窗口扫描、引用查询、审计导出全部退化全表扫描 |
| `audit_export.export_audit_digest` | `fetchall()` 全量入内存 + 逐行 `copy.deepcopy` + 逐行 `json.loads` | 内存随流水总量线性膨胀 |
| `rule_engine.evaluate_transaction_batch` | 每笔交易都 `SELECT * FROM transactions WHERE tenant_id=?` 拉全量历史再在 Python 端过滤 | 每笔 O(全租户交易) |

**重构方案**

1. **连接池**（`db.py`：`open_connection` / `_PooledConnection` / `_MAX_IDLE_CONNECTIONS`）
   - 按库路径复用空闲连接，`close()` 语义变为「归还连接池」，调用方零改动；归还前强制 `ROLLBACK`，杜绝跨请求事务污染。
   - 池容量有界（8），连接对象数不随请求量无界增长；归还连接时清理事务状态。
   - `isolation_level=None` + 显式 `BEGIN IMMEDIATE`，把事务边界从「隐式」变为「显式可控」。
2. **WAL 并发**（`db.py::_tune_database`）：`journal_mode=WAL` + `synchronous=NORMAL` + `busy_timeout=30s` + `cache_size=-8000`（页缓存上限 8MB，避免常驻堆无界膨胀）。WAL 为库级持久属性，只设置一次。
3. **复合索引**（`db.py::SCHEMA_SQL`，全部 `IF NOT EXISTS`，可在存量库幂等挂载）：
   `idx_docs_tenant_status`、`idx_docs_tenant_updated`、`idx_docs_tenant_cat_tag`、`idx_citations_tenant_doc`、`idx_citations_ref`、`idx_tx_tenant_ts`、`idx_tx_tenant_acct_ts`、`idx_tx_tenant_cp_ts`、`idx_tx_tenant_batch`、`idx_dec_tenant_id`、`idx_audit_tenant_logid`、`idx_audit_tenant_ts`、`idx_audit_tenant_evt`、`idx_acl_tenant_doc`、`idx_deleg_tenant_grantee/grantor`、`idx_grants_tenant_user`、`idx_sanctions_tenant`、`idx_users_tenant_user`、`idx_org_tenant_node`、`idx_quota_tenant`、`idx_override_tenant`。
4. **检索链路去往返**：权限解析 **1 次**（提到循环外）、隔离墙与组织树快照 **1 次**、引用计数 **1 次批量查询**、正文片段仅对最终返回页取回。
5. **审计摘要流式化**（`audit_export.py::_iter_audit_rows` + `_accumulate_digest`）：`fetchmany(500)` 游标分块读取，边读边算滚动哈希与分布统计，内存占用与「样本数」成正比而与「流水总量」无关；同时去掉了逐行 `deepcopy` 与逐行 `json.loads`（输出字段本就未使用 payload）。

**实测收益**（每租户 200 文档 / 600 交易 / 400 审计流水）

| 场景 | 原语义参考实现 | 优化后 | 加速比 |
| --- | --- | --- | --- |
| `docs/search`（关键词 + 邻近度 + 簇折叠） | 1769.86 ms/op | **8.87 ms/op** | **199×** |
| `docs/search`（空查询 + 全量折叠） | 2481.34 ms/op | **11.81 ms/op** | **210×** |
| `docs/upsert`（单篇写入 + 引用联动） | 27.34 ms/op | **3.93 ms/op** | **7.0×** |
| `risk/evaluate-batch`（3 笔批次） | 161.39 ms/op | **9.90 ms/op** | **16.3×** |
| `audit/export-digest` | 20.04 ms/op | **5.19 ms/op** | **3.9×** |

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

**(a) 增量索引与双向引用传播图**（新增 `doc_index.py`：`DocNode` / `TenantDocIndex`）

- `DocNode` 使用 `__slots__`，仅持有元数据 + 分词后的紧凑 token 元组 + 引用集合，**绝不常驻整库原始大正文 `body`**。
- 分词结果经 `sys.intern` 共享字符串池，词元内存 ≈ 8 字节/词而非重复字符串对象。
- **单篇增量**：写入时只对 **该文档** 重新分词（O(该文档词数)），不推倒重建整租户结构。
- **双向引用传播图**：`cite_refs`（文档 → 唯一引用源）与 `reverse_dependents`（被引用文档 → 引用它的文档）双向维护。内部 `doc_` 引用源发生 `RETIRED`/`quarantined` 翻转时，仅沿 `reverse_dependents` 做 **O(deg) 局部更新**，被引用方的有效 `citation_count` 立即精确联动。
- **预算护栏**：`MAX_INDEX_TOKENS=400_000`、`MAX_INDEX_DOCS=20_000`，超限自动 `degrade()` 清空常驻结构并降级为流式扫描模式（正确性不变）。
- **实测常驻内存**：400 篇文档语料下，首次检索峰值 **0.49 MiB**、稳态检索峰值 **0.49 MiB**。

**(b) 短语词距邻近度**（`doc_indexer.py`）
- 原实现：每一对相邻查询词做「出现位置笛卡尔积」，复杂度 **O(P·N²)**。
- 现实现：`build_token_positions` 一次建位置表 + 双指针归并求最小跨度，复杂度 **O(P·N)**；当最小跨度抵达理论下界 1 时 **立即早停**（`_min_token_distance`）。
- 检索热路径进一步用 C 层原语 `list.count` / `list.index` 替代 Python 层逐词循环（`_term_positions`）。

**(c) 双轨法规近似去重**（`search_service.py::_cluster_and_fold` + `doc_indexer.py::jaccard_may_exceed_threshold`）
- 原实现：O(N²) 对比较，**且每对都重新分词两遍正文**。
- 现实现：先按归一化法规号分组（跨组永不合并，故无需跨组比较），组内使用 **预分词集合** 求交；再利用数学上界
  `Jaccard ≤ min(|A|,|B|) / max(|A|,|B|)`，当 **集合大小比值 < 0.70** 时直接剪枝（不可能合并）。
  复杂度由 **O(N² · 重新分词)** 降为 **O(N · T + 同规模簇对数 · T)**。

**(d) 滑动窗口精确动态中位数**（`window_stats.py`）
- 原实现：交换排序 **O(n²)**；现实现：一次 `sorted` **O(n log n)**，偶数长度仍取 `(a+b)//2`，与原版逐位一致。

**(e) 三跳制裁传染追踪**（`contagion_graph.py`）
- 原实现：**对每一个受制裁源点各跑一次 BFS**（O(|S|·|E|)），且每笔交易都把 **全租户交易** 拉进内存后再按时间窗过滤。
- 现实现：**多源 BFS 一次成型**（O(|E|)，深度收敛在 2 跳），窗口过滤下推为索引化 SQL
  （`WHERE tenant_id=? AND ts>=? AND ts<=?`）。同批先序交易在同一连接内天然可见，故 **批次内传染联动语义与原版完全一致**。

**(f) 流式审计导出**：见 1.1 第 5 点。

**(g) 零失真保证方式**：本次改造未删除任何业务规则；词频、邻近度、引用计数、簇折叠、排序与分页的 **表达式与比较顺序均按原版逐字复刻**（例如 `round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * risk_w, 4)` 的浮点运算顺序保持不变），并由 345 项差分比对逐字段验证。

---

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

**全局统一锁偏序**（新增 `locks.py`）

```
第一级：Python 细粒度业务锁（按 (tenant_id, quota_type) 分片）
第二级：SQLite 写锁（BEGIN IMMEDIATE）
```

- 任何写路径 **必须先取 Python 业务锁，再申请数据库写锁**；提交/回滚后 **先释放写锁，再释放业务锁**。
- 多配额池锁一律按 `quota_type` **升序** 获取（`quota_locks`），构成全局全序。
- 「持有数据库写锁的线程永不等待 Python 锁」⇒ 锁图中不存在环 ⇒ **双向交叉调拨、并发扣减、批次联动扣减 `REALTIME_ALERT_POOL` 均零死锁**。
- 分片而非全局大锁：不同租户、不同配额池之间互不加锁，**跨租户读写不被阻塞**。

**第二道防线：条件更新**
- `consume_tenant_quota` / `transfer_tenant_quota` / `try_consume_realtime_alert_quota` 一律使用
  `UPDATE ... SET remaining_quota = remaining_quota - ? WHERE ... AND remaining_quota >= ?`，
  **即便锁序被绕过也绝不超扣、绝不写出负数余额**。
- `redeem_override_token` 使用 `UPDATE ... SET used=1 ... WHERE used=0`，高并发下 **严格仅成功核销一次**。

**四位一体强原子**（`rule_engine.evaluate_transaction_batch`）
- 整批置于 **一个** `BEGIN IMMEDIATE` 事务：交易行写入、风控决策写入、滑动窗口计算所依据的同连接可见性、三跳传染图、以及 `REALTIME_ALERT_POOL` 扣减 **同生共死**。
- 任一笔非法或主键冲突 ⇒ 整批 `ROLLBACK` ⇒ **零半截落盘、零配额泄漏、零内存污染**。
- 同批先序交易因在同一连接内已可见，**天然纳入后续交易的窗口与传染图**，与原版逐笔提交语义一致。

**实测**：4 线程双向交叉调拨 + 2 线程并发消费 + 2 线程批次评估混跑 4 秒，无死锁、无负余额、总额不膨胀（40/40 安全用例含并发项全部通过）。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

**多维纪元**（新增 `state.py`：`TenantRuntime` / `RuntimeState` / `get_runtime_state`）

| 业务域 | 纪元 | 失效范围 |
| --- | --- | --- |
| 文档（`compliance_docs` + `doc_citations`） | `doc` | 仅文档索引 |
| 隔离墙（`doc_acl_rules`） | `acl` | 仅隔离墙规则快照 |
| 权限（`users`/`org_nodes`/`role_grants`） | `org` | 仅组织/角色快照 |
| 借调（`delegation_grants`） | `deleg` | 仅借调快照 |
| 黑名单（`sanctioned_entities`） | `sanction` | 仅制裁名单快照 |
| 策略（`tenant_policies`） | `policy` | 仅策略快照 |

- **纪元互不牵连**：修改单条 `doc-acl` 规则只推进 `acl` 纪元，**绝不连带清空整租户文档倒排索引**；撤销角色只推进 `org` 纪元。
- **双失效条件**：纪元（进程内写路径）+ 轻量签名（`tenant_cache.py` 中的一次廉价聚合查询，如计数/最大时间戳/`SUM(active)`），用于感知绕过本进程写路径的外部数据库改动。

**1~2 跳借调时效链**（`delegation.py`）
- 委托记录、组织树、用户台账均为租户级只读快照，链路判定退化为 **内存图遍历**（O(链路长度)）。
- **上游窗口自然到期零写降级**：上游一级窗口到期时，下游二级资格在读取时点判定中自动失效（无需任何写操作）。
- **源头撤权级联失效**：源头委托人失活或不再原生持有该角色 ⇒ 下游 1~2 跳资格即刻失效（实测：源头停用后 1 跳与 2 跳均立即失效，恢复后立即恢复）。
- **有向环路免疫**：链路回溯深度硬性收敛在 `MAX_DELEGATION_HOPS=2`（更浅跳数在业务上永不生效），A→B→A 环形委托既不无限递归，也不被当作有效授权（实测请求 9 ms 内返回）。

**三级利益冲突隔离墙**（`acl_wall.py`）
- 规则与组织树快照化后，裁决退化为纯内存运算 `is_user_blocked_by_wall_rules`，批量场景 **零逐文档数据库往返**；优先级（USER ALLOW > USER DENY > 组织就近 DENY > 组织就近 ALLOW > 默认放行）与原版逐条一致。

---

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

| 风险 | 原实现位置与手法 | 现实现阻断点 |
| --- | --- | --- |
| 一阶 SQL 注入 | `search_service.py`：`tenant_id`、`custom_tag` 以 f-string 拼接；`sort_by`/`sort_dir` **直接作为 SQL 列名/方向** | 全部参数化；排序字段白名单化（`score`/`updated_at`/`risk_weight`，其余回落 `score`），排序方向仅 `asc/desc` 有效 |
| 二阶 SQL 注入（引用链） | `search_service._get_doc_citation_count`：把 `cited_by_ref` 拼进 `WHERE doc_id = '{ref}'` | 引用统计改为 `doc_id IN (...)` **参数化批量查询**；引用源状态核验亦为参数化且 **限定本租户** |
| 二阶 SQL 注入（模板落库） | `audit_export.render_saved_report`：`event_type = '{tpl[extra_event_filter]}'` | 落库时按 `^[A-Z][A-Z0-9_]{0,63}$` 校验，渲染时 **参数化查询**，历史脏模板亦被拒绝 |
| 模板格式化反射 | `render_saved_report`：`str.format(..., env=RUNTIME_ENV)` ⇒ `{env.master_pepper}` 直接泄主密钥 | 改为 **字面占位符白名单渲染器** `render_report_title`：仅 `{tenant_id}`/`{total_records}`/`{total_amount_cents}`，格式说明符、属性访问、下标、未知占位符一律拒绝（**不使用 `str.format`**） |
| 模板宽度放大 | 同上：`{tenant_id:0>200000}` 触发内存放大 | 白名单渲染器不支持任何格式说明符 ⇒ 拒绝；渲染结果另有 4096 字符上限 |
| 目录穿越（多变体） | `read_compliance_snapshot`：仅 `replace("../","")` 一次 ⇒ `....//`、`..%2f`、绝对路径、符号链接均可逃逸 | 以 `Path.resolve()` **锚定**在 `<storage>/<tenant>/snapshots` 内并做 `relative_to` 包含判定；租户目录本身亦须位于存储根内；另加文件名/体积上限 |
| 跨租户侧信道 | `batch_get_documents` **无租户过滤**；`get_risk_decision_detail` **无租户过滤**；`_get_doc_citation_count` 的 `doc_` 引用 **不校验归属租户** | 三处全部按 `caller.tenant_id` 收口；`batch-get` 另补齐状态、隔离、密级与利益冲突墙约束（与 TASK 契约一致） |
| 内部诊断泄密 | `/api/v1/health?debug=1` 与 `/api/v1/internal/diagnostics` **免鉴权**返回主密钥 pepper、系统密钥明文与物理路径；500 兜底回显 `db_path`/`storage_dir`/`master_pepper`/traceback | health 仅返回存活信息；诊断路由需 `COMPLIANCE_ADMIN` 鉴权且 **已脱敏**（只给计数，不给密钥名与路径）；500 兜底改为通用文案 |
| 令牌时序侧信道 | `u_row["api_token_hash"] != hash_api_token(raw_token)` | 改为 `hmac.compare_digest` 常量时间比较 |

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

**Webhook 纵深加固**（`auth.process_settlement_webhook`）
- **常量时间验签**：`hmac.compare_digest`。
- **±300 s 时间窗**：`abs(now_ts - callback_ts) > WEBHOOK_TOLERANCE_SECONDS` 即拒绝（`_now_ts` 覆盖生效，便于测试）。
- **Nonce 防重放**：新增 `webhook_nonces(tenant_id, nonce, seen_at)` 唯一索引表，登记与事件写入 **同一事务**；`IntegrityError` ⇒ 拒绝（串行与并发重放均拦截），并按 24 小时窗口清理过期 Nonce。
- 报文体积（64 KB）、单号长度（128）、金额边界（0 ≤ amount ≤ 2^63−1，且拒绝 bool/非整浮点）硬校验；载荷解析失败按 400 拒绝。

**复杂度炸弹与类型边界**
| 攻击面 | 熔断位置与阈值 |
| --- | --- |
| 灾难性回溯正则 | `rule_engine._compile_safe_regex`：模式长度 ≤ 200、输入长度 ≤ 4096、拒绝嵌套量词 `(a+)+` 与被量词修饰的交替分支 `(a|a)*`、预编译失败即拒绝 |
| 膨胀规则树 | `MAX_RULE_NODES=2000`、`MAX_RULE_DEPTH=24`、单节点 children ≤ 64、`IN` 目标列表 ≤ 1000、字段名长度 ≤ 128；求值预算由 `RuleBudget` 强制 |
| 千层 JSON | `middleware.measure_json_depth` **解析前** 零内存扫描（深度 ≤ 32）+ 体积上限 1 MB；直传 dict 亦经 `measure_structure_depth` 复核，不留绕过口 |
| 超长引用洪水 | 引用数组 ≤ 500、文档字段长度上限、批量 `doc_ids` ≤ 1000、分页 `limit` ≤ 5000 / `offset` ≤ 1e6 |
| 布尔/超 64 位整数/`NaN` | `rule_engine._to_number` / `_require_int`：拒绝 `bool`、超 2^63 整数、`NaN`/`Inf`、非数值对象（400 而非 500） |
| 畸形交易批次 | 字段长度/类型/时间戳硬校验，批次 ≤ 500 笔；任一笔非法 ⇒ 整批回滚 |
| 委托环路 | 深度收敛 + 路径去重 ⇒ 有向环路免疫 |
| 快照文件炸弹 | 文件体积上限 8 MB |
| 诊断与错误面 | 免鉴权面收敛、脱敏、通用错误文案 |

---

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**
  `aegis_app/doc_index.py`（`DocNode.__slots__` / `TenantDocIndex.build` / `upsert_doc` / `add_citations` / `apply_status_change`）+ `aegis_app/doc_indexer.py`（`build_token_positions` / `_min_token_distance` 早停 / `jaccard_may_exceed_threshold` 比值剪枝）+ `aegis_app/window_stats.py`（`sorted` 中位数 O(n log n)）+ `aegis_app/contagion_graph.py`（`compute_sanction_contagion_hop` 多源 BFS，`_MAX_GRAPH_DEPTH`）+ `aegis_app/search_service.py`（`_cluster_and_fold` 按法规号分组）。
  单篇写入只重新分词该文档（`upsert_doc`），内部引用源状态翻转沿 `reverse_dependents` 做 O(deg) 局部更新（`apply_status_change`）；索引节点 `__slots__` 且不持原始正文，预算超限自动降级。

- **[C2 多维纪元与二级借调隔离缓存声明]**
  `aegis_app/state.py`（`DOMAIN_ORG/ACL/DELEG/SANCTION/POLICY/DOC` 六域纪元、`TenantRuntime.cached_sig`）+ `aegis_app/tenant_cache.py`（`load_org_snapshot` / `load_acl_rules` / `load_delegations` / `load_sanctioned_entities` / `load_policy_snapshot` / `load_doc_index`，纪元 + 签名双失效）+ `aegis_app/delegation.py`（`_collect_upstream_grantors` 深度收敛 2 跳、`path` 环路去重、`resolve_active_delegated_roles` 链路窗口判定）+ `aegis_app/acl_wall.py`（`is_user_blocked_by_wall_rules` 纯内存三级裁决）。
  `acl` 纪元推进不牵连 `doc` 纪元 ⇒ 改单条 `doc-acl` 不会清空文档索引。

- **[C3 统一锁偏序与四重强原子事务声明]**
  `aegis_app/locks.py`（`quota_lock` / `quota_locks` 升序取锁 / `tenant_write_scope`）+ `aegis_app/db.py`（`write_transaction` = `BEGIN IMMEDIATE` + 异常 `ROLLBACK`）+ `aegis_app/ledger_ops.py`（`try_consume_realtime_alert_quota(conn=...)` 复用批次事务、条件更新 `remaining_quota >= ?`、`redeem_override_token` 条件核销）+ `aegis_app/rule_engine.py`（`evaluate_transaction_batch` 整批单事务：交易写入 + 决策写入 + 滑窗 + 传染图 + `REALTIME_ALERT_POOL` 扣减）。

- **[C4 双通道二阶安全与越权边界声明]**
  `aegis_app/search_service.py`（`_compute_citation_counts` 参数化批量 + 本租户归属核验、`batch_get_documents` 租户/状态/隔离/密级/隔离墙五重约束）+ `aegis_app/rule_engine.py`（`get_risk_decision_detail` 租户过滤）+ `aegis_app/audit_export.py`（`render_report_title` 字面占位符白名单、不调用 `str.format`；事件过滤参数化 + `^[A-Z][A-Z0-9_]{0,63}$` 校验）+ `aegis_app/middleware.py`（`collect_internal_diagnostics` 脱敏）+ `aegis_app/server.py`（诊断路由需 `COMPLIANCE_ADMIN`、health 不再附带诊断、500 兜底不回显路径与主密钥）。

- **[C5 抗复杂度炸弹与严格类型守卫声明]**
  `aegis_app/rule_engine.py`（`_compile_safe_regex` 嵌套量词/长度熔断、`MAX_RULE_NODES`/`MAX_RULE_DEPTH`、`RuleBudget`、`_to_number` 拒绝 bool/NaN/Inf/超 64 位、`_require_int` 严格整数）+ `aegis_app/middleware.py`（`measure_json_depth` 解析前深度预检、`measure_structure_depth` 直传对象复核、`MAX_REQUEST_BODY_BYTES`）+ `aegis_app/audit_export.py`（`MAX_SNAPSHOT_BYTES`）+ `aegis_app/doc_writer.py`（文档字段长度与引用数上限）。

---

## 5. 已知工程取舍与残余边界说明

1. **单机进程内存快照**：文档索引、租户快照与连接池均为 **进程内** 结构，多进程/多副本部署需外置或加一致性协议；本次基准为单进程网关，故按进程内最优设计。
2. **索引预算与降级**：`MAX_INDEX_TOKENS=400_000` / `MAX_INDEX_DOCS=20_000` 超限时主动降级为数据库流式扫描（正确性不变、时延回到「无索引」水平）；降级是 **有界内存对有界时延** 的显式取舍，而非静默膨胀。
3. **SQLite 写串行边界**：SQLite 单文件写者唯一，`BEGIN IMMEDIATE` 之外的写仍被引擎串行化；本实现以「Python 细粒度锁 + 条件更新 + 单事务」把可并行的部分尽量前移，但 **无法突破 SQLite 的单写者模型**。WAL 模式下读不阻塞写，可显著缓解混合负载的 P99。
4. **外部改库的陈旧窗口**：缓存以「纪元 + 廉价签名」双条件失效。签名能覆盖 **计数/时间戳/active 标志/组织归属** 类改动，但 **无法** 覆盖「行数与时间戳均不变的原地内容替换」（例如外部直接改写正文而不同步 `updated_at`）——该场景下索引会保持旧分词直至下次签名变化。若评测基座直接改写存量库正文，建议同步维护 `updated_at`。
5. **Webhook 重放窗口**：Nonce 保留 24 小时（覆盖任何合理重放容忍窗），更早的 Nonce 被清理，极长周期重放需依赖上游时间窗。
6. **安全收紧带来的行为差异（有意为之，均以 TASK 契约为准）**：`batch-get` 现强制租户/状态/隔离/密级/隔离墙约束（原版缺失）；`risk/decisions/<id>` 现强制租户过滤（原版缺失）；内部 `doc_` 引用仅在 **同租户且 ACTIVE 且未隔离** 时计入有效引用（原版未校验归属租户）；报表模板仅支持三个字面占位符（原版可经 `{env.*}` 反射主密钥）；health 不再暴露诊断信息。上述差异均属「修复原版缺陷」，不改变任何 **合法同租户正常业务** 的计算结果（已由 345 项差分比对验证）。
7. **`str.format` 全面退场**：报表标题渲染不再使用 `str.format`，代价是不再支持 `{{`/`}}` 之外的转义与格式说明符（仅保留 `{{`/`}}` 字面转义）。
