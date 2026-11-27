# 提交 D 层盲评评分

独立审阅完 `OFFICIAL_LEVEL5_BASELINE.md`、`code_changes.diff`、`EXPLANATION.md` 与 `code/` 后，请在仓库根目录执行以下命令提交评分（只追加写入中心日志，不显示他人评分）：

```sh
python src/scoring/judge_submit.py \
  --pack-dir "leaderboard/blind/a4be43d6c3e5" \
  --case-id case-01 \
  --judge-id <你的评委唯一ID，如 judge-1> \
  --judge-model <你的模型名称> \
  --D1 <0-11> --D2 <0-10> --D3 <0-9> \
  --evidence "<逐条给出 EXPLANATION C1-C5 核验结论 + 对照 5 级样本的具体补丁/源码定位>" \
  --note "<指出该作品的最强反证与核心工程短板>"
```

如需重评更新你本人此前的打分，保持相同 `--judge-id` 附加 `--update` 再次运行即可；汇总出榜时将实时采信最新一条记录。
