# 性能剖析与安全加固阐述（EXPLANATION.md）

## 1. 核心性能瓶颈诊断与增量算法/存储降维方案

### 1.1 存储层、连接管理与查询放大（I/O 层）治理

原实现几乎每次基础查询都新建/销毁 SQLite 连接；检索时还按“文档数 × 权限/ACL/引用”循环开连接，风控则对每笔交易重读策略、制裁名单和整租户交易。主要改造如下：

- `aegis_app/db.py` 新增每数据库最多 8 连接的线程粘滞池 `PooledConnection/_ConnectionPool`，嵌套读取复用同线程连接；统一 `Row`、busy timeout、WAL、`synchronous=NORMAL` 和有界 SQLite cache。保留 `open_connection/init_schema/seed_dataset` 外部签名。
- `INDEX_SQL` 增加用户/授权/委托、在线文档与标签、双向引用、交易 `(tenant_id, ts)` 与 `(tenant_id, account_id, ts)`、制裁、审计时间/严重度/事件等复合索引；Webhook `(tenant_id, nonce)` 使用唯一索引（存量重复数据有兼容回退）。
- `delegation.py`、`acl_wall.py` 将逐用户、逐组织节点、逐文档查询合并为小型租户权限快照；`search_service.py` 不再进行逐文档 SQL 权限与引用查询。
- `rule_engine.py` 每批仅读取一次策略、制裁集合及批次所需时间范围内的交易，并以同一连接完成整批写入；`audit_export.py` 使用 `arraysize=256` 游标，不再 `fetchall()` 或深拷贝整表。

### 1.2 核心算法时间复杂度、增量索引与常驻堆内存控制

- **文档索引与引用**：`doc_indexer.TenantDocIndex` 按租户懒加载、游标建索引，之后 `upsert/set_state` 仅替换单篇 posting。`DocEntry` 使用 `__slots__`，不保存原始 `body`，只保留 140 字符摘要、租户内 uint32 词元 ID、`array('I')` 正文序列、词频与去重集合；词元字典有引用计数，修订淘汰词会释放映射。运行索引注册表最多保留 64 个租户。
- **引用双向联动**：`citations` 保存目标到唯一引用源，`reverse_dependents` 保存内部源文档到其引用目标。源文档状态/隔离翻转仅触及反向邻居；内部源必须在本租户索引中且 `ACTIVE`、未隔离，外部文号直接计数，自引用和重复引用不计。
- **词距**：`compute_phrase_proximity_bonus` 从原先每个词对构造位置表并做笛卡尔积（可至 $O(QB+Q^2B^2)$），降为一次正文扫描加相邻词对双指针 $O(B+Q)$，距离为 1 时立即结束该词对。
- **修订簇**：检索期直接复用索引词元集合计算 Jaccard，先按规范化法规编号分组，再以 `min_size/max_size < 0.70` 做数学上无损的大小比剪枝；仍按原算法“综合分代表与后续候选逐一比较”计数，未改成会改变簇语义的传递并查集。
- **滑窗中位数**：`window_stats.LazyMedian` 以大小根堆、有效尺寸和懒删除实现 $O(\log W)$ 增删，`AccountWindow` 同步维护金额和及对手方 `Counter`。`_BatchTemporalState` 对正常前向时间流增量推进；遇乱序时间戳则精确重建当前视图，避免单调队列近似造成统计失真。
- **三跳传染**：`TemporalContagionGraph` 用边计数支持重复边及精确过期；每次评估从全部制裁源执行一次限深 2 的多源 BFS，复杂度 $O(V+E)$，替代“每个制裁源一次 BFS”的 $O(S(V+E))$，并临时加入/撤销当前交易边。
- **审计**：`_compute_digest_from_records` 单次流式累计计数、总金额和滚动 SHA-256，仅保留至多 50 条样本及少量分布键，时间 $O(R)$、常驻空间 $O(1)$（相对结果行数）。

上述改造保留原评分公式、引用去重规则、簇代表选择、最终排序、窗口闭区间、偶数中位数整除、主权结算豁免和批次先序可见性；另以随机乱序输入将增量滑窗/图结果逐项对齐朴素全量算法。

## 2. 跨模块并发控制锁偏序与多维隔离缓存设计（性能—安全平衡）

### 2.1 高并发混合读写、跨池调拨与风控告警配额联动的无死锁控制

`runtime.RuntimeRegistry.tenant_write` 提供 256 分片的租户写锁，锁序固定为 **租户分片 Python 锁 → SQLite `BEGIN IMMEDIATE` → 按 `quota_type` 排序读取配额行**。不同租户不使用全局业务大锁；SQLite 写事务内不追加获取其他 Python 配额锁。

- `consume_tenant_quota` 使用带 `remaining_quota >= amount` 条件的原子更新，审计与扣减同事务。
- `transfer_tenant_quota` 对两个池统一排序读取、条件扣源、增加目标并写调拨流水，双向交叉调拨没有相反锁序。
- `evaluate_transaction_batch` 与上述接口共用分片锁和同一连接事务；REJECT 告警通过 `_try_consume_alert_conn` 在本事务内条件扣 1，不再另开连接提前提交。
- 批次滑窗、传染图、结果和计数全部是调用局部对象。任一笔校验失败或主键冲突时，数据库（含告警配额）回滚，局部滑窗/图/结果直接丢弃，因此数据库、滑窗、传染图、配额四位一体均无半批污染。
- 单次令牌使用 `used=0` 条件更新；Webhook 使用唯一约束和写事务查重，覆盖并发核销/重放。

### 2.2 多维纪元解耦、二级借调时效链与实时失效一致性机制

`runtime.py` 将 `auth` 与 `acl` 纪元分离；角色/委托变更仅清理原生角色和委托快照，ACL 变更仅清理 ACL 快照。文档索引维护自身 `revision` 和单篇内容，不会因一条 ACL 规则变化而清空倒排。所有小型 LRU 均有容量上限。

`delegation.py` 每请求以请求秒重新检查 `[starts_at, expires_at)`，所以上游自然到期不依赖后台写操作。`_has_native_source` 最多回溯 2 层，并要求每段有效、中间用户活跃、源头当前仍原生持有角色；`visited(user, depth)` 防止环。二级转借调只接受 `exact_hops=1` 的上游资格，不能借第三跳继续扩散；新建委托另以有向可达性检查拒绝成环。

`acl_wall.decide_wall` 保留 USER ALLOW > USER DENY > 最近组织节点（同节点 DENY 优先）> 默认放行。策略和制裁不做跨事务脏缓存，而是在批次写事务中读取同一个一致快照。

## 3. 纵深安全漏洞修复与抗拒绝服务（Anti-DoS）体系

### 3.1 一阶/双通道二阶注入、模板沙箱防反射、路径穿越与跨租户侧信道阻断

- 所有租户、标签、事件过滤、引用、ID 和时间条件均参数化；`render_saved_report` 对落库后的事件过滤同样使用绑定参数，ACL 动态表名只来自固定 USER/ORG_NODE 白名单。
- `audit_export._render_literal_template` 仅用 `string.Formatter.parse` 解析，不调用 `str.format`；字段仅允许 `{tenant_id}`、`{total_records}`、`{total_amount_cents}`，拒绝属性、索引、转换和格式规格，保存与渲染两个阶段都验证，因此历史恶意模板也不能反射泄密或制造超宽输出。
- 快照名最多三轮解码，之后若仍可解码即拒绝；仅允许短季度 JSON 文件名，并对 `resolve()` 后路径做 `commonpath` 租户目录锚定，限制文件大小，阻止多重编码、绝对路径和符号链接逃逸。
- `batch_get_documents` 同时校验租户、ACTIVE、未隔离、密级和完整 Chinese Wall；风控决策详情使用 `(tenant_id, decision_id)` 查询。内部引用只在本租户索引内解析，不能用其他租户文档状态形成引用计数预言机。
- 健康检查忽略 debug 参数，内部诊断路由不再开放；500 响应不包含异常文本、堆栈、物理路径或密钥。认证使用常量时间 token 比较，未知用户也执行 dummy 比较。

### 3.2 回调防重放与抗多变体复杂度炸弹 / 特殊数值类型边界

Webhook 使用 HMAC-SHA256 `hmac.compare_digest`，先检查 `±300s`，再验证负载字段；Nonce 以租户唯一约束加 `BEGIN IMMEDIATE` 防串行/并发重放，重复返回 409。

- `security.preflight_json_text` 在 `json.loads` **之前**做字符串/转义感知的深度扫描，限制 1 MiB、32 层；直接字典也经迭代节点/深度检查，NaN/Infinity 由解析钩子和有限数检查拒绝。
- 规则树最多 12 层、256 节点、每个逻辑节点 32 子节点；`safe_regex_search` 限制模式和输入长度，以标准库正则 AST 拒绝嵌套重复、重复分支、反向引用和超大重复上界，编译缓存有界且线程安全。
- 联系邮箱改为分段线性校验，移除嵌套量词灾难回溯；委托链限深且有 visited/成环检测；查询、批量 ID、批次交易、引用、模板、正文和快照均有预算。
- `strict_int` 明确拒绝 bool、float、NaN、非十进制字符串及有符号 64 位溢出；`strict_bool` 不再把非空字符串误判为 True。数值规则比较只接受有限数。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）

- **[C1 增量索引与算法降维声明]**：`aegis_app/doc_indexer.py` 的 `DocEntry(__slots__, array('I'))`、`TenantDocIndex.upsert/set_state/_refresh_dependents` 实现单篇 posting 与 `reverse_dependents` 局部引用传播；`compute_phrase_proximity_bonus` 为双指针且 d=1 早停；`aegis_app/window_stats.py::LazyMedian/AccountWindow` 实现 $O(\log W)$ 精确中位数及滑窗；`aegis_app/contagion_graph.py::TemporalContagionGraph.hop_for` 实现多源限深 BFS；`rule_engine._BatchTemporalState` 对乱序精确重建。
- **[C2 多维纪元与二级借调隔离缓存声明]**：`aegis_app/runtime.py::RuntimeRegistry` 分离 `auth/acl` 纪元和有界 LRU；`aegis_app/delegation.py::_has_native_source/resolve_active_delegated_roles/_would_create_cycle` 实现 1~2 跳源头原生角色、全链活跃用户与秒级窗口核验、自然到期/撤权级联失效和环路免疫；`aegis_app/acl_wall.py::decide_wall` 保留三级优先级。
- **[C3 统一锁偏序与四重强原子事务声明]**：`aegis_app/runtime.py::tenant_write` 固定分片锁到 `BEGIN IMMEDIATE` 的顺序；`aegis_app/ledger_ops.py::consume_tenant_quota/transfer_tenant_quota/_try_consume_alert_conn` 使用条件原子更新及配额名排序；`aegis_app/rule_engine.py::evaluate_transaction_batch` 在同一连接事务内写交易、决策、告警配额，异常回滚数据库并丢弃局部滑窗/图/结果。
- **[C4 双通道二阶安全与越权边界声明]**：`aegis_app/audit_export.py::_audit_query/_render_literal_template/read_compliance_snapshot` 实现落库过滤参数化、三字段字面占位符和路径锚定；`aegis_app/search_service.py::batch_get_documents` 落实租户/状态/隔离/密级/ACL 全约束；`aegis_app/rule_engine.py::get_risk_decision_detail` 做租户过滤；`aegis_app/doc_indexer.py::_count_citations` 只认可本租户有效内部引用源。
- **[C5 抗复杂度炸弹与严格类型守卫声明]**：`aegis_app/security.py::preflight_json_text/validate_json_value` 在解析前限制深度并检查直接对象，`strict_int/strict_bool/finite_number` 拒绝 bool、非有限数与溢出；`validate_contact_email` 为线性分段算法；`_validate_regex_ast/safe_regex_search` 阻断回溯变体；`aegis_app/rule_engine.py::validate_rule_tree/_normalize_transaction` 落实规则、批次和元数据预算；`aegis_app/doc_writer.py` 限制单篇引用和正文预算。

## 5. 已知工程取舍与残余边界说明

- 连接池上限为 8，超出并发度的请求有界等待；SQLite 仍具有单写者物理约束，因此使用 WAL 让读写在多数场景并行，并以短事务减少写锁占用，而未声称可消除数据库层写串行。
- 文档运行索引是单网关进程内结构，首次访问某租户需流式懒加载存量数据；挂载已有 SQLite 不会清空数据。若另一个进程绕过本网关直接修改文档表，本网关不会收到进程内增量通知，需要重启该网关以重建视图；通过本网关全部写路由的变更均立即一致。
- 索引注册表采用 64 租户 LRU，词元 ID 为 uint32；超高速连续创建大量全新文档仍会按真实文档数增长必要索引，不以丢弃可检索数据换取假低内存。
- 批次限制 128 笔、单批 upsert 引用限制 128 条，规则/JSON/正文/模板均有明确预算；这些是有意的抗 DoS 拒绝边界，而非对合法超限请求的排队执行。
