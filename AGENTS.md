# AGENTS.md — 两角色分流与信任域操作手册（xiaonuo-v1.0）

> 给进入本目录的 **AI 智能体与人类操作者**的第一入口指南。
> 本仓库在同一工程内通过**物理目录边界 + 环境与代码 SHA-256 承诺 + 双指纹防篡改缓存 + 事后隔离审计**严格划分**两个角色（两个信任域）**：**① 选手域（被测模型）** 与 **② 评委/汇总域（独立盲评与一键出榜）**。
> **进门第一件事：在下方第 0 节确认你当前的唯一角色，然后只阅读属于你的章节并立即行动！严禁跨角色越界阅读！**

---

## 0. 一眼认领角色：你是谁？现在该干什么？

同一个智能体在同一批次中**绝不能既当选手又给自己当评委**。客观压测/红队攻防得分（70 分）与盲评思想得分（30 分）物理分离存储、独立校验；**选手阶段严禁运行任何官方计分或出榜脚本**。

| 你的角色（信任域） | 怎么判断是你 | 你唯一允许读取的范围 | 你的核心标准动作 | 绝对禁止触碰的红线（违反即成绩作废） |
| --- | --- | --- | --- | --- |
| **① 选手域（被测模型）** | 用户对你说“你是被测模型，开始测试 / 完成这个基准任务”，或指定了参赛模型名 | **只读本文 `§0–§1`**；执行开局命令后，**全程只允许读写你专属沙盒 `runs/<你的模型名>/workspace/` 内的文件**（及填写 `runs/<你的模型名>/token_usage.json`） | 1. 运行 `tools/start_run.py` 开局打下 `t0` 并生成独立沙盒<br>2. 在沙盒内剖析 `aegis_app/`，完成深度性能优化与纵深安全加固<br>3. 跑通公开冒烟 `smoke_check.py`，确保正常业务 100% 零失真<br>4. 诚实填写 `EXPLANATION.md` 与 `token_usage.json`，运行 `judge_pack.py` 冻结 `t1` 生成匿名盲评包后收工 | **严禁继续往下读本文 `§2–§3`**；严禁读取、列出或搜索 `README.md`、`CHANGELOG.md`、`docs/`、`configs/`、`src/scoring/`、`src/baselines/`、`src/sandbox_template/`、`leaderboard/` 或他人 `runs/*`；严禁运行 `score_run.py`、`judge_submit.py`、`finalize.py`；严禁预生成或伪造 `评分.json` / `result.json` |
| **② 评委 / 汇总域** | 用户交给你 `leaderboard/blind/<pack_id>/` 让你做 D 层盲评，或在盲评收齐后让你执行汇总出榜 | **只读本文 `§0` 与 `§2`**；**处于盲评阶段时，唯一合法输入仅限指定的 `leaderboard/blind/<pack_id>/` 目录** | 1. **盲评阶段**：先读包内 `OFFICIAL_LEVEL5_BASELINE.md` 与 `RUBRIC.md`，锚定**三档硬封顶（5 级平庸 `≤ 15.0/30`、有局部耦合或边界漏防的 7 级良好 `≤ 22.0/30`、无死角大师 `25.5–30.0/30`）**，再审阅 `code_changes.diff`、`EXPLANATION.md` 与 `code/`（逐条核验 C1–C5 声明），运行 `judge_submit.py` 追加 D1/D2/D3<br>2. **出榜阶段**（盲评全部提交后）：跑 `isolation_audit.py --strict`、`timing_audit.py runs --strict` 与 `leaderboard/finalize.py` 压测轰炸定稿并合成总榜 | **盲评期间**严禁访问 `runs/`、`leaderboard/blind-maps/`、`leaderboard/reviews.jsonl`、`leaderboard/scores.md`、`leaderboard/verdicts/` 或运行压测脚本打探客观分；全程严禁替选手修改沙盒代码 |

### 通用目录卫生纪律（两角色共同遵守）
- 除各自角色的规定产物路径外，**不得在仓库根目录或其他目录新建、修改文件或残留调试产物**。
- 如确需编写临时演算或压测草稿，**只允许放入 `draft/` 目录，且在运行打包或提交前必须彻底删除清空**（`tools/isolation_audit.py --strict` 会拦截任何非空 `draft/`）。

---

## 1. 选手域（被测模型）：四步一气呵成操作流程

> **被测模型零追问直通规则（必读）**：
> 1. 当你收到“你是被测模型，开始测试”或同类参赛指令时，**不要向用户反问确认**，直接按下方四步一气呵成执行到底！
> 2. **确定 `<你的模型名>`**：若用户在提示词中指定了名字则用指定名；若用户未指定，请直接使用**你当前自身的真实模型标识**（例如 `gemini-4-carbon`、`claude-opus-4-6`、`deepseek-v4.1-flash`、`gpt-5` 等，**严禁照抄示例中的 `Demo`**）。
> 3. **多局串行原则**：若需要跑多个批次（如 `-s1`、`-s2`），必须跑完一局打包冻结后再开下一局，严禁并行导致 API 排队时间计入端到端墙钟耗时。
> 4. **读完本节（`§1`）末尾后立即停止阅读本文档**，直接执行第一步命令进入你的专属沙盒！

### 第一步：一键开局（打下起点时钟 `t0` + 创建专属带病系统沙盒）

在仓库根目录执行：

```sh
python tools/start_run.py --model <你的模型名>
```

该命令会在 `runs/<你的模型名>/workspace/` 下创建一套独立的 **AegisGate（多租户实时风控决策与企业合规文档检索网关）** 源码副本，并在 `runs/<你的模型名>/protocol.json` 中固化起点时间 `t0` 与评测环境承诺哈希。

### 第二步：在专属沙盒内完成性能压榨与安全加固

进入 `runs/<你的模型名>/workspace/`，仔细阅读沙盒内的 **`TASK.md`** 与 **`aegis_app/`** 全部源码：
1. **死守业务零失真守恒底线**：初始系统在正常业务输入下计算逻辑 100% 正确。你的所有优化与重构必须保证正常请求的返回结构、风控分数、滑动窗口三项统计、文档相关性打分、近似修订簇折叠计数与排序顺序跟原版**分毫不差**（任何改坏正常业务或删逻辑骗取假高速的行为都会触发性能分指数归零）。
2. **深度性能优化重构**：从存储层索引/连接/事务模式、跨模块查询放大、核心检索去重与时间窗算法复杂度、流式内存控制，到高并发混合读写下的**锁粒度**与**缓存隔离/实时失效一致性**，进行系统性降维提速（切忌用一把粗暴全局大锁阻塞跨租户并发读写，切忌使用无权限隔离或撤权不失效的粗糙缓存）。
3. **纵深安全加固与抗 DoS 熔断**：全面排查并封堵动态查询注入、多变体目录穿越、内部诊断与异常密钥泄露、跨租户横向越权与租户内跨密级纵向越权（IDOR）、高并发配额/单次令牌抢扣条件竞争（TOCTOU）、Webhook 回调伪造与重放，以及小体积高破坏力的算法复杂度炸弹（灾难性正则回溯 ReDoS、深层嵌套/膨胀规则树、极端分页与通配符慢查询放大），确保恶意载荷被毫秒级安全拒绝且绝不拖累并发正常租户请求。
4. **运行公开功能回归冒烟自检**（仅检验基础正常业务未改坏，不含高压与红队载荷；你可在 `draft/` 下自行编写额外验证并在收尾前清空 `draft/`）：
   ```sh
   python runs/<你的模型名>/workspace/smoke_check.py
   ```

### 第三步：如实撰写阐述文档并自报词元消耗

1. 打开并完整填写沙盒内的 **`runs/<你的模型名>/workspace/EXPLANATION.md`**（删除所有占位符），确保第 4 节列出的 **5 条核心工程声明（C1–C5）** 均可在你的源码中逐条核验属实（严禁吹嘘未实现的设计）。
2. 打开 **`runs/<你的模型名>/token_usage.json`**，填入本局累计词元用量（仅作成本诊断，不参与算分；若宿主环境无法获取词元数，保留 `null` 并在 `note` 说明原因即可）：
   ```json
   {
     "input_tokens": 0,
     "output_tokens": 0,
     "total_tokens": 0,
     "source": "self_report",
     "note": "宿主统计口径说明"
   }
   ```

### 第四步：收工冻结计时并生成脱敏匿名盲评包（`t1`）

确认 `smoke_check.py` 全绿、`EXPLANATION.md` 已填妥且 `draft/` 已彻底清空后，在仓库根目录运行：

```sh
python src/scoring/judge_pack.py --model <你的模型名>
```

- 该命令会自动打下结束时间 `t1`、固化沙盒源码哈希 `code_sha256`（**冻结后严禁再改动沙盒内任何文件！**），提取脱敏全量差异补丁 `code_changes.diff` 生成匿名盲评包 `leaderboard/blind/<pack_id>/`（不计算、不回显任何官方分数）。
- **将控制台打印出的 `leaderboard/blind/<pack_id>` 路径汇报给用户即可收工**。不要把 `blind-maps/`、`runs/` 或任何其他文件交给评委，**严禁运行 `score_run.py`、`judge_submit.py` 或 `finalize.py`！**

*(如果你是被测模型选手，阅读到此彻底结束，严禁继续向下阅读！)*

---

## 2. 评委与汇总域：先对照 5 级样本盲评，后实弹压测出榜

> 本节仅供承担 **D 层盲评（30 分）** 的独立评委及**盲评后执行一键出榜**的汇总操作者阅读。

### 第一阶段：独立评委盲评提交（严禁接触客观分与模型身份）

- **唯一合法输入**：用户指定的匿名盲评包路径 `leaderboard/blind/<pack_id>/`。
- **盲评期间绝对禁区**：严禁读取 `leaderboard/blind-maps/`、`leaderboard/reviews.jsonl`、`leaderboard/scores.md`、`leaderboard/verdicts/`、`runs/`、`src/`、`docs/` 或 `configs/`；严禁运行压测或红队脚本。
- **四步盲评动作**：
  1. 先阅读包内 [`OFFICIAL_LEVEL5_BASELINE.md`](leaderboard/blind/README.md)（《官方 5 级平庸参照补丁样本》）与 `RUBRIC.md`，严格执行 **D 层三档硬封顶铁律（严禁高分粘连与端水人情分）**：
     - **5 级平庸硬封顶（`D ≤ 15.0 / 30`，即 `D1 ≤ 5.5, D2 ≤ 5.0, D3 ≤ 4.5`）**：未明显超越官方 5 级平庸样本（如使用全局粗暴大锁、未消 $O(N^2)$、无权限/版本失效隔离缓存、依赖脆弱字符串替换防穿越或无视复杂度炸弹）；
     - **7 级良好硬封顶（`D ≤ 22.0 / 30`，即 `D1 ≤ 8.2, D2 ≤ 7.5, D3 ≤ 6.3`）**：虽实现了主要降维与细粒度锁，但**存在任何一处局部耦合、算法未彻底降维或边界漏防**——例如：① 缓存失效粒度过粗（如修改单条 ACL 规则却连带清空整租户预分词文档倒排索引）；② 去重未做集合大小下界剪枝，或滑窗逐笔 `list.insert` 未做单调序列 $O(1)$ 队列优化；③ 自定义正则安全校验漏拦多无界通配符（`.*a.*b.*`）或超大花括号重复次数，或评估时未缓存编译后正则；④ 规则树未限制单节点扇出子节点数 / `IN` 列表长度，或检索未显式拦截纯通配符洪水；⑤ 未拦截布尔值伪装整数（`isinstance(x, bool)`）、超 64 位整数溢出或 `NaN`/`Infinity`；**凡命中上述任一局部缺口，严禁跨入大师档，D 层总分强制 `≤ 22.0 / 30`**！
     - **9 级大师档准入（`25.5–30.0 / 30`）**：仅限在算法降维、四维独立 Epoch+CAS 缓存、细粒度锁、全变体抗 DoS/类型溢出边界上**零死角闭环**且 `EXPLANATION.md` 的 C1–C5 声明与代码 100% 严丝合缝的作品；
  2. 阅读各 `case-XX/` 下的 `OVERVIEW.md`、`code_changes.diff`、`EXPLANATION.md` 与 `code/`；
  3. 逐条核查 `EXPLANATION.md` 第 4 节的 **5 条声明（C1–C5）** 在 `code_changes.diff` 和 `code/` 中是否真实落地（任何一条存在夸大或实现偏差，D3 必须联动扣分并触发良好档封顶）；
  4. 按包内 `SUBMIT.md` 运行追加提交命令（支持同一 `--judge-id` 附加 `--update` 随时重评覆盖，汇总时实时取最新一条生效）：

```sh
python src/scoring/judge_submit.py \
  --pack-dir "leaderboard/blind/<pack_id>" \
  --case-id case-01 \
  --judge-id <评委唯一ID> \
  --judge-model <评委模型标识> \
  --D1 <0-11> --D2 <0-10> --D3 <0-9> \
  --evidence "<逐条给出 C1-C5 核验结论 + 对照 5 级平庸样本的具体 diff/源码定位>" \
  --note "<指出该作品的最强反证与核心工程短板>"
```

### 第二阶段：盲评收齐后，执行隔离审计并一键压测出榜

```sh
# 1) 核查角色隔离、代码冻结 SHA-256、客观分防篡改签名与盲评包零泄密
python tools/isolation_audit.py --strict

# 2) 核查同一模型多局端到端墙钟时间无重叠
python tools/timing_audit.py runs --strict

# 3) （可选）预览中心评审日志聚合结果
python src/scoring/review_merge.py --log leaderboard/reviews.jsonl --aggregate mean

# 4) 一键全量汇总出榜（未变动局自动复用双指纹防篡改客观分缓存，新增局现场拉起高压压测与红队轰炸，盲评实时重读）
python leaderboard/finalize.py

# 5) （可选）忽略已有缓存、强制全量重跑所有局高压性能压测与红队实弹攻防：
python leaderboard/finalize.py --recompute
```

---

## 3. 文件读写权限地图与维护自检（仅供基准维护者阅读）

| 路径 | 写入方 | 允许读取方 | 隔离与防作弊说明 |
| --- | --- | --- | --- |
| `AGENTS.md`（`§0–§1`） | 基准维护 | 所有角色 | 选手仅允许读至 `§1` 末尾 |
| `runs/<名>/workspace/*` | `start_run.py`、对应选手 | 对应选手、`judge_pack`、`score_run` | 各选手严格隔离在各自沙盒内，冻结 `t1` 后锁死 `code_sha256` |
| `runs/<名>/protocol.json` | `start_run.py`、`judge_pack.py` | 审计与汇总脚本 | 记录 `t0`/`t1`、`env_commit`、`template_sha256`、`code_sha256` |
| `runs/<名>/token_usage.json` | 选手自报 | 汇总成本诊断 | 不参与 A/B/C/D 评分 |
| `runs/<名>/{评分.json,result.json}` | `score_run.py` / `finalize.py` | 出榜汇总阶段 | **选手严禁生成或修改；绑定 `scoring_hash` + `deliverables_hash` 防伪签名，不含盲评字段** |
| `leaderboard/blind/<pack_id>/` | `judge_pack.py` | **评委盲评阶段唯一输入** | 含脱敏 `code_changes.diff` 与《官方 5 级平庸参照补丁样本》，零模型名、零客观分 |
| `leaderboard/blind-maps/*.json` | `judge_pack.py` | `finalize.py`（出榜阶段） | **私有身份映射，选手与盲评评委均严禁读取** |
| `leaderboard/reviews.jsonl` | `judge_submit.py`（加锁只追加） | `review_merge.py`、`finalize.py` | **评委只写不读；支持随时重评，每次出榜实时重读绝不缓存** |
| `leaderboard/{scores.md,verdicts/}` | `finalize.py` | 公开榜单查阅 | 按规范模型 ID 归并多局明细，总榜按算术平均数排名 |
| `src/baselines/*`、`src/scoring/*` | 基准维护 | 评测引擎与 `tests/` | 内置 5 级平庸基线与 9 级大师基线，**选手严禁翻阅** |

```sh
# 维护者一键跑通单元测试 + 三基线梯度验证 + 全链路闭环自检
pwsh tests/smoke.ps1
```
