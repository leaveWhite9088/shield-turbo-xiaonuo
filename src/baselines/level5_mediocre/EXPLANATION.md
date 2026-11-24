# AegisGate 性能优化与安全加固技术阐述（官方 5 级平庸参照样本）

## 1. 性能瓶颈诊断与降维重构方案
- **数据库层**：在 `db.py` 中补充了 4 个基础单列 `tenant_id` / `doc_id` 索引，并在 `search_service.py` 中将逐篇引用计数改为单次 `GROUP BY doc_id` 聚合查询，减少了基础 N+1 查询，但未启用 WAL 模式与线程本地连接复用。
- **算法与内存层**：在 `window_stats.py` 中将交换排序替换为内置 `sorted()`，在 `audit_export.py` 中移除了多余的 `copy.deepcopy`；但检索去重仍保留了 $O(N^2)$ 集合两两比较，短语邻近度仍逐词扫描下标列表，三跳制裁传染仍每笔交易全表拉取窗口边并执行 `list.pop(0)` 搜索。

## 2. 高并发架构、锁粒度与缓存一致性设计
- **锁模型**：在 `server.py` 的请求入口外层加了一把全局互斥锁 `_GLOBAL_GATEWAY_LOCK` 串行化全部请求，虽然规避了部分内存竞争，但导致跨租户高并发读写互相严重阻塞。
- **缓存设计**：在 `search_service.py` 中引入了字典 `_NAIVE_SEARCH_CACHE`，在文档写入、退役和隔离时直接整库清空缓存（导致读写混压时缓存命中率骤降），且在角色撤权、借调委托过期或利益冲突隔离墙变更时遗漏了缓存失效联动。

## 3. 纵深安全加固清单（漏洞根因 -> 修复机制）
- **一阶查询注入与诊断泄露**：将 `search_documents` 中的 `tenant_id` 与 `tag_filter` 改为参数化查询，关闭了 `/api/v1/internal/diagnostics` 与异常堆栈中的敏感常量回显；但遗漏了 `audit_export.py` 中报表模板 `extra_event_filter` 的二阶 SQL 注入与 `title_format.format(..., env=RUNTIME_ENV)` 的反射密钥泄露。
- **访问控制与重放防护**：在 `batch_get_documents` 与 `get_risk_decision_detail` 中补充了 `tenant_id` 过滤，在回调验签中增加了 `hmac.compare_digest` 与时间戳窗口校验；但遗漏了 `batch_get_documents` 的纵向密级和利益冲突墙拦截，未校验回调 `nonce` 唯一防重放，也未拦截复杂回溯正则、深层规则树与超大整数类型混淆。

## 4. 核心工程声明（供盲评逐条核验代码）
- **[C1] 基础索引与聚合查询**：已在 `aegis_app/db.py` 添加 `BASIC_INDEXES_SQL` 并在 `aegis_app/search_service.py` 将引用统计合并为 `GROUP BY doc_id`。
- **[C2] 全局互斥锁并发控制**：已在 `aegis_app/server.py` 使用全局 `_GLOBAL_GATEWAY_LOCK` 包裹 `AegisGateway.request` 请求分发。
- **[C3] 基础查询缓存**：已在 `aegis_app/search_service.py` 使用 `_NAIVE_SEARCH_CACHE` 缓存检索响应并在文档写入/下架时清空。
- **[C4] 一阶检索参数化与诊断关闭**：已在 `aegis_app/search_service.py` 参数化检索过滤条件并在 `aegis_app/server.py` 禁用内部诊断路由。
- **[C5] 回调常量时间验签与窗口检查**：已在 `aegis_app/auth.py` 的 `process_settlement_webhook` 中补充 `WEBHOOK_TOLERANCE_SECONDS` 与 `hmac.compare_digest` 校验。

## 5. 已知权衡与边界条件
本方案仅完成了表层单列索引、全局大锁与一阶输入修补，属于典型的 5 级基础补丁，尚未实现增量倒排索引、多维纪元无锁读缓存、无死锁配额调拨锁序、批次原子回滚以及二阶注入与复杂度熔断防护。
