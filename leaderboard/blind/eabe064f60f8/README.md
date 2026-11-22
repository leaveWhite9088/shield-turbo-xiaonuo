# 匿名盲评包 · shield-turbo-xiaonuo（仅限独立评委阅读）

本目录是你作为 **D 层优化与安全思想评委** 的**唯一合法输入**。包内已彻底隐去模型身份、客观压测加速比、红队攻防得分与完赛耗时。

## 评委四步评审流程
1. **先立标尺**：仔细阅读 [`OFFICIAL_LEVEL5_BASELINE.md`](OFFICIAL_LEVEL5_BASELINE.md)（《官方 5 级平庸参照补丁样本》）与 [`RUBRIC.md`](RUBRIC.md)；
2. **审阅补丁与源码**：打开各 `case-XX/` 下的：
   - `OVERVIEW.md`（改动文件统计与阐述文档完整性提示）
   - `code_changes.diff`（选手相对初始沙盒的全量代码差异补丁）
   - `EXPLANATION.md`（选手提交的《性能剖析与安全加固阐述》）
   - `code/`（选手脱敏后的完整终局代码）
3. **强制交叉核验**：将 `EXPLANATION.md` 第 4 节的 **5 条核心声明（C1–C5）** 逐一与 `code_changes.diff` 及 `code/` 对照核实真伪，并判断其工程水平是否真正超越《官方 5 级平庸参照补丁样本》；
4. **提交打分**：按 [`SUBMIT.md`](SUBMIT.md) 中的命令调用 `judge_submit.py` 追加写入中心日志。

## 绝对隔离红线
- **严禁**读取上级 `leaderboard/blind-maps/`、`leaderboard/reviews.jsonl`、`leaderboard/scores.md`、`runs/`、`src/`、`docs/` 或 `configs/`；
- **严禁**自行运行任何压测或红队脚本打探客观分；
- **严禁**猜测模型身份或查看其他评委打分。
