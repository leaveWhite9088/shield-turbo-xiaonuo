# AegisGate 多租户实时风控与企业合规检索网关（v2.0）— 性能压榨与安全加固任务书

## 1. 业务背景与你的使命

`aegis_app/` 是一套历经多期业务迭代的多租户金融风控与合规检索网关系统（**AegisGate v2.0**，共 16 个源码模块），仅依赖 Python 标准库与本地 SQLite 数据库运行，承载五大在线核心域：
1. **企业合规文档实时流式入库/修订（Upsert）、多维检索、词距邻近度加分与跨期近似修订簇折叠**；
2. **多级组织汇报继承、带有效期的跨部门临时角色借调委托（Delegation）与三级优先级利益冲突隔离墙（Chinese Wall）**；
3. **实时交易批次四维滑动时间窗（含精确动态中位数）、三跳受制裁实体资金传染链路追踪（3-Hop Contagion）与自定义布尔规则树试算**；
4. **稀缺配额扣减、跨配额池原子额度调拨（Transfer）、单次应急放行令牌核销与清算机构签名回调（Webhook）**；
5. **合规审计流水滚动摘要导出、自定义审计报表模板保存与渲染、以及季度归档快照读取**。

当前系统在常规业务输入下计算逻辑 100% 正确（运行同目录 `python smoke_check.py` 全部绿灯通过），但在高强度读写交错生产环境与红队实战对抗下面临严峻的性能劣化、并发死锁与跨链路安全风险。

**你的唯一使命**：
通读并剖析 `aegis_app/` 全部 16 个模块（**切勿遗漏任何子模块中的既有业务规则、权限优先级或历史清算/合规兼容逻辑**），在确保所有合法业务请求的计算结果、排序顺序、统计数值与原版 **100% 分毫不差**的前提下，完成架构级性能优化与纵深安全加固，并如实填写 [`EXPLANATION.md`](EXPLANATION.md)。

---

## 2. 不可动摇的工程契约（必守）

### 2.1 挂载入口与运行环境契约
- **零外部第三方依赖**：仅允许使用 Python 3 标准库，不得引入任何第三方包。
- **网关调用入口不变**：
  - `aegis_app.server.create_gateway(db_path, storage_dir)` 必须返回具备线程安全方法 `request(method, path, *, headers=None, body=None) -> tuple[int, dict, dict]` 的网关实例；
  - `aegis_app.server.build_http_server(gateway, host, port)` 必须保持可正常承载 HTTP 请求；
  - `aegis_app.db.init_schema(db_path)` 与 `aegis_app.db.seed_dataset(...)` 的外部签名及核心业务表结构须保持兼容（评测时会在已初始化存量数据的 SQLite 文件上直接挂载你的 `create_gateway`，严禁启动时清空存量数据）。

### 2.2 核心网关路由契约（共 18 个路由）

除 `/api/v1/health` 与 `/api/v1/webhooks/settlement-callback` 外，所有业务接口均通过 `X-Aegis-Tenant`、`X-Aegis-User`、`X-Aegis-Token` 请求头认证：

| 路由 | 方法 | 核心业务语义与零失真守恒要求 |
| --- | --- | --- |
| `/api/v1/health` | `GET` | 返回网关存活状态（严禁向未授权方暴露内部诊断配置、物理路径或主密钥）。 |
| `/api/v1/docs/search` | `GET` | 融合调用者实时有效密级（含有效期内且未级联失效的借调角色）与利益冲突隔离墙优先级，执行词频 + 相邻查询词最小跨度邻近度加分检索，并按归一化法规编号执行 Jaccard `>= 0.70` 近似修订簇折叠与稳定排序。 |
| `/api/v1/docs/upsert` | `POST` | 实时新增或原地修订本租户合规文档及引用记录；修改后须对后续检索立即生效。 |
| `/api/v1/docs/retire` | `POST` | 仅 `COMPLIANCE_ADMIN` 可调用，将文档置为 `RETIRED` 退役下架；须立即生效。 |
| `/api/v1/docs/batch-get` | `POST` | 按 `doc_ids` 批量获取调用者有权访问的完整文档（须严格遵守租户、状态、隔离、密级与利益冲突墙全部约束）。 |
| `/api/v1/docs/quarantine` | `POST` | 仅 `COMPLIANCE_ADMIN` 可调用，紧急隔离或解除隔离文档；须立即生效。 |
| `/api/v1/admin/grants/revoke` | `POST` | 仅 `COMPLIANCE_ADMIN` 可调用，授予或撤回成员角色（若某委托人丧失角色，其下游受托资格须同步级联失效）。 |
| `/api/v1/admin/delegations` | `POST` | 由委托人本人或管理员创建/撤销带 `[starts_at, expires_at)` 窗口的跨部门角色借调委托。 |
| `/api/v1/admin/doc-acl` | `POST` | 仅 `COMPLIANCE_ADMIN` 可调用，配置文档对特定 `USER` 或 `ORG_NODE` 的 `ALLOW`/`DENY` 隔离墙规则。 |
| `/api/v1/admin/sanctions` | `POST` | 仅 `COMPLIANCE_ADMIN` 可调用，实时新增、激活或停用受制裁黑名单实体；须对后续风控评估立即生效。 |
| `/api/v1/policies` | `PUT` | 仅 `COMPLIANCE_ADMIN` 可调用，热更新租户风控阈值与自定义规则树并递增 `policy_version`。 |
| `/api/v1/risk/evaluate-batch` | `POST` | 按批次顺序逐笔计算四维滑动窗口统计（含精确动态中位数）、三跳受制裁实体资金传染等级与风控评分（须完整保留全部既有行业兼容规则），同批次先序交易须纳入同批后续窗口与关联图；整批必须强原子落盘（任一笔非法或主键冲突则整批回滚，零半截落盘、零内存污染）。 |
| `/api/v1/risk/simulate-rule` | `POST` | 试算自定义布尔规则树对单笔样本的命中结果与附加分。 |
| `/api/v1/risk/decisions/<id>` | `GET` | 查询本租户下的单笔风控决策完整详情。 |
| `/api/v1/quotas/consume` | `POST` | 扣减本租户指定配额池余量（高并发下严禁超扣或负数）。 |
| `/api/v1/quotas/transfer` | `POST` | 仅 `COMPLIANCE_ADMIN` 可调用，在本租户两个配额池间原子调拨额度（须保证总额严格守恒且高并发双向交叉调拨零死锁）。 |
| `/api/v1/risk/override-token/redeem` | `POST` | 核销本租户单次应急放行令牌（高并发下严格仅成功核销一次）。 |
| `/api/v1/webhooks/settlement-callback` | `POST` | 校验 HMAC-SHA256 签名，拦截伪造、超出 `±300s` 时间窗及并发/串行重复 Nonce 重放报文。 |
| `/api/v1/audit/export-digest` | `GET` | 统计时间窗口内审计流水分布、总金额及按 `log_id ASC` 滚动计算的 `rolling_sha256` 摘要。 |
| `/api/v1/audit/report-template` | `PUT` | 保存自定义审计汇总报表配置模板。 |
| `/api/v1/audit/render-report` | `GET` | 按已保存模板渲染生成带格式化标题的审计汇总报告。 |
| `/api/v1/audit/snapshots` | `GET` | 安全读取本租户 `snapshots/` 目录下的季度归档快照文件。 |

---

## 3. 核心架构挑战提示

1. **高频动态写流与常驻内存红线**：生产流量包含高频 `docs/upsert` 文档修订与实时交易写入。若每次文档或权限变动就推倒重建整套内存索引，高并发尾延迟（P95/P99）将严重恶化；若无节制将全库原始大文本常驻内存，将触碰常驻内存预算上限扣分。
2. **高阶算法复杂度**：需同时降伏词距邻近度检索、双轨法规近似聚类、三跳动态资金传染图搜索、滑动窗口精确中位数与大表流式摘要的算法复杂度。
3. **跨模块深水区安全与并发死锁**：除了常规注入、路径穿越、越权、并发穿盾与多变体复杂度炸弹外，请特别审视**跨接口落库后再读取执行的二次触发数据流、双向资源锁定的加锁顺序、多级委托与隔离墙的级联失效及并发回填竞态、以及语言底层特殊数值/类型边界**。

---

## 4. 本地自检与交付要求

1. 运行公开基础回归冒烟自检（仅验证小样本正常业务未改坏，不含高压与红队载荷）：
   ```sh
   python smoke_check.py
   ```
2. 如实填写 [`EXPLANATION.md`](EXPLANATION.md)，确保第 4 节的 **5 条核心工程声明（C1–C5）** 均可在你的源码中逐条核验属实。
