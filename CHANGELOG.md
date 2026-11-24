# CHANGELOG

## xiaonuo-v2.0 (2026-11-23)

- **十六模块深水代码迷宫升级**：将沙盒网关 `aegis_app/` 从 7 个模块扩充重构为 16 个职责交织的企业级模块（新增 `legacy_compat.py`、`delegation.py`、`acl_wall.py`、`doc_indexer.py`、`doc_writer.py`、`contagion_graph.py`、`window_stats.py`、`ledger_ops.py`、`middleware.py` 等），植入历史双轨法规号映射与主权央行清算豁免隐式兼容契约。
- **粉碎无脑全库内存缓存**：新增高频实时文档流式入库/修订（`POST /api/v1/docs/upsert`）与退役（`POST /api/v1/docs/retire`）混合压测，并在 `A3` 引入常驻堆内存净增量预算（`≤ 8.0 MB`）与 `A2` 硬性 `P99` 尾延迟门控，迫使高分方案实现紧凑单篇 $O(L)$ 增量倒排索引。
- **高阶算法复杂度升级**：新增三跳受制裁实体活跃窗口资金传染追踪（`contagion_graph.py`）、24 小时滑动窗口精确动态中位数突变检测（`window_stats.py`）与相邻查询词最小词距邻近度加分（`doc_indexer.py`）。
- **跨模块二阶漏洞与双向死锁深水陷阱**：新增持久化报表模板二阶 SQL 注入与 Python `.format()` 属性反射主密钥窃取攻击面（`audit_export.py`）、带时效窗口与上游委托人撤权级联失效的跨部门角色借调（`delegation.py`）、三级优先级利益冲突隔离墙（`USER ALLOW > USER DENY > 最近祖先 ORG_NODE`）以及 24 路双向跨池配额调拨 AB-BA 死锁探测（`ledger_ops.py`）。
- **计分天花板收紧与四档盲评硬锁**：`A1` 升级为两段式边际递减对数曲线（`60×` 拐点、`180×` 满分），`B1` 守恒惩罚指数提升至 `acc ** 5`，`B2` 收紧为 `6` 分钟满分、`8` 分钟半衰期；D 层盲评升级为 `14.0 / 20.5 / 24.5 / 30.0` 四档硬封顶规则，并同步升级 `level5_mediocre` 与 `level9_master` 双校准基线。

## xiaonuo-v1.0 (2026-11-22)

- 初始发布《疾风铁盾 · 性能压榨与安全加固基准》（`shield-turbo-xiaonuo`）。
- 构建零剧透商业级多租户实时风控决策与合规文档检索网关沙盒模板（`src/sandbox_template/`），自然融合浅、中、深三段位性能瓶颈与三段位安全攻击面。
- 对齐 `silicon-rider-xiaonuo` 两角色信任域隔离架构：实现 `start_run.py`、`judge_pack.py`（含自动提取脱敏 `code_changes.diff` 与捆绑《官方 5 级平庸参照补丁样本》）、`judge_submit.py`（支持随时重评最新生效）、`objective_cache.py`（双指纹防篡改缓存）、`isolation_audit.py`、`timing_audit.py` 与 `finalize.py`。
- 内置三套端到端验证基线（未优化原版基线、官方 5 级平庸优化基线、9 级疾风铁盾大师基线）及自动化测试套件 `tests/`。
