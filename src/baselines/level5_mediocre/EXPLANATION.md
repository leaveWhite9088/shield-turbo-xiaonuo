# 性能剖析与安全加固阐述（5 级平庸优化基线样本）

## 1. 核心性能瓶颈诊断与算法/存储降维方案
1. 在 `aegis_app/db.py` 中为 `tenant_id` 与 `doc_id` 添加了基础单列索引。
2. 在 `aegis_app/search_service.py` 中将引用计数改为 `GROUP BY` 聚合，并增加了字典缓存 `_NAIVE_SEARCH_CACHE`。
3. 在 `aegis_app/rule_engine.py` 中复用了单个批次连接提交事务。

## 2. 并发控制粒度与安全隔离缓存设计
1. 在 `aegis_app/server.py` 的入口处使用全局互斥锁 `_GLOBAL_GATEWAY_LOCK` 包裹全部请求以防止并发超扣。
2. 在 `aegis_app/search_service.py` 对检索结果做了内存字典缓存，隔离文档时清空缓存。

## 3. 纵深安全漏洞修复与抗拒绝服务体系
1. 限制了 `sort_by` 字段名并使用参数化查询绑定 `tag_filter`；关闭了诊断接口与 500 堆栈回显。
2. 为快照路径增加了 `.replace("../", "").replace("..\\", "")` 过滤，并为 Webhook 增加了 300 秒时间戳校验。

## 4. 可直接在源码中核验的 5 条核心工程声明（必核项 C1–C5）
- **[C1 算法降维声明]**：`aegis_app/search_service.py` 使用 `GROUP BY doc_id` 替代逐篇查询引用数（去重仍沿用双重循环）。
- **[C2 缓存隔离与失效声明]**：`aegis_app/search_service.py` 使用 `_NAIVE_SEARCH_CACHE` 缓存查询结果，仅在文档隔离时清空。
- **[C3 并发原子性与锁粒度声明]**：`aegis_app/server.py` 采用全局 `threading.Lock()` 串行化网关全部读写请求。
- **[C4 注入/越权/路径边界防御声明]**：`aegis_app/search_service.py` 校验 `sort_by` 枚举并在 `batch_get_documents` 校验 `tenant_id`；`audit_export.py` 使用字符串替换过滤 `../`。
- **[C5 抗复杂度炸弹熔断声明]**：暂未改动 `rule_engine.py` 的邮箱正则与递归规则树求值逻辑。

## 5. 已知工程取舍与残余边界说明
全局锁在高并发混合读写下存在排队等待；审计导出仍使用全量列表加载。
