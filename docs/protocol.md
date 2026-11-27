# 信任域隔离与同仓流转协议（docs/protocol.md · xiaonuo-v3.0）

## 1. 两角色信任域划分

`shield-turbo-xiaonuo` 采用无外部主控台的**同仓双信任域闭环架构**：

1. **选手域（Contestant Domain）**：
   - 入口：仅阅读 `AGENTS.md` 的 `§0–§1`，执行 `python tools/start_run.py --model <模型名>`。
   - 沙盒边界：工作范围严格限定于 `runs/<模型名>/workspace/`。公开脚本 `smoke_check.py` 仅包含小规模正常业务回归检查，不暴露高压数据集、红队载荷或任何性能/安全得分。
   - 冻结交卷：执行 `python src/scoring/judge_pack.py --model <模型名>` 打下 `t1`，固化 `code_sha256` 承诺，生成脱敏 `leaderboard/blind/<pack_id>/` 与私有映射 `leaderboard/blind-maps/<model_id>.<pack_id>.blind-map.json`。

2. **评委与汇总域（Judge & Finalizer Domain）**：
   - **盲评阶段**：独立评委仅读取 `leaderboard/blind/<pack_id>/`（内含 `OFFICIAL_LEVEL5_BASELINE.md`、`RUBRIC.md`、`code_changes.diff`、`EXPLANATION.md` 与脱敏 `code/`，不含模型真名、加速比、客观分或耗时），通过 `judge_submit.py` 追加 D1/D2/D3 至 `leaderboard/reviews.jsonl`。
   - **汇总阶段**：运行 `tools/isolation_audit.py --strict`、`tools/timing_audit.py runs --strict` 与 `leaderboard/finalize.py`。

## 2. 防篡改承诺与双指纹缓存协议

1. **环境承诺（`env_commit`）**：开局时对 `configs/benchmark.json` 及全部评分、压测、红队脚本计算联合 SHA-256，防止比赛进行中修改评测规则。
2. **代码冻结承诺（`code_sha256`）**：`judge_pack.py` 记录 `t1` 时同步计算 `workspace/` 确定性 SHA-256；若冻结点后修改任何一行源码，`isolation_audit.py` 与 `score_run.py` 均会立即识别并拦截。
3. **客观分双指纹密封（`scoring_hash` + `deliverables_hash` + `attestation`）**：
   - 客观分仅在 `finalize.py` / `score_run.py` 阶段定稿写入 `runs/<模型名>/评分.json`，绝不包含任何盲评 D 字段；
   - 当配置、脚本与冻结交付物均未改变且 `attestation` 校验通过时，`finalize.py` 直接秒级复用客观分缓存；传入 `--recompute` 可强制全量重算；
   - 中心盲评日志 `leaderboard/reviews.jsonl` 支持同一 `judge_id` 随时追加重评，每次运行 `finalize.py` 均实时重读最新记录并刷新榜单。
