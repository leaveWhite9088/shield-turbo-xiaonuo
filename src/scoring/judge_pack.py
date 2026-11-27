#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选手收尾、计时冻结与匿名盲评包生成工具（judge_pack.py）。

职责：
1. 拦截任何违禁预生成官方分数文件（严禁选手阶段存在 评分.json / result.json）及冻结点后代码篡改；
2. 打下结束时间戳 t1（end_iso），锁定端到端耗时与沙盒源码 SHA-256（code_sha256）；
3. 自动对比初始模板与选手沙盒源码，生成全量脱敏差异补丁 code_changes.diff 与改动统计；
4. 连同脱敏后的选手源码、阐述文档 EXPLANATION.md 以及《官方 5 级平庸参照补丁样本》
   （OFFICIAL_LEVEL5_BASELINE.md）打入 leaderboard/blind/<pack_id>/；
5. 【隔离红线】盲评包内绝不含模型名称、运行目录名，也绝不含 A/B/C 客观压测分、加速倍数或墙钟耗时！
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import json
import os
from pathlib import Path
import re
import secrets
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from model_identity import canonical_model_id, matches_batch_run  # noqa: E402
from objective_cache import compute_workspace_sha256  # noqa: E402

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".git", ".mypy_cache", ".venv", "venv"}
SKIP_SUFFIXES = {
    ".db",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".sqlite",
    ".sqlite3",
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dll",
    ".exe",
    ".log",
    ".tmp",
}
TEMPLATE_DOC_FILES = {"TASK.md"}
FORBIDDEN_SCORE_FILES = {"评分.json", "result.json", "token_usage.json", "protocol.json"}


def _epoch(iso: str) -> float:
    return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _sanitize_text(text: str, tokens_to_redact: list[str]) -> str:
    out = text
    out = re.sub(r"[A-Za-z]:[\\/][^\s\"'`<>|]+", "<REDACTED_PATH>", out)
    out = re.sub(r"/(?:Users|home)/[^\s\"'`<>|]+", "<REDACTED_PATH>", out)
    for tok in sorted({t.strip() for t in tokens_to_redact if t and len(t.strip()) >= 3}, key=len, reverse=True):
        out = re.sub(re.escape(tok), "<ANONYMOUS_CANDIDATE>", out, flags=re.IGNORECASE)
    return out


def _collect_text_files(base_dir: Path, *, include_explanation: bool = False) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not base_dir.is_dir():
        return out
    for p in sorted(base_dir.rglob("*"), key=lambda x: x.relative_to(base_dir).as_posix()):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(base_dir).parts
        if any(pt in SKIP_DIRS for pt in rel_parts):
            continue
        if p.name in FORBIDDEN_SCORE_FILES or p.name in TEMPLATE_DOC_FILES:
            continue
        if not include_explanation and p.name == "EXPLANATION.md":
            continue
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        rel = p.relative_to(base_dir).as_posix()
        raw = p.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        out[rel] = raw.splitlines(keepends=True)
    return out


def build_unified_diff(
    src_dir: Path,
    dst_dir: Path,
    *,
    tokens_to_redact: list[str] | None = None,
) -> tuple[str, dict[str, int]]:
    """计算从初始模板 src_dir 到目标目录 dst_dir 的完整 unified diff 与增删行统计。"""
    old_files = _collect_text_files(src_dir, include_explanation=False)
    new_files = _collect_text_files(dst_dir, include_explanation=False)
    all_paths = sorted(set(old_files) | set(new_files))

    diff_chunks: list[str] = []
    added_lines = 0
    deleted_lines = 0
    changed_files = 0

    for rel in all_paths:
        a_lines = old_files.get(rel, [])
        b_lines = new_files.get(rel, [])
        if a_lines == b_lines:
            continue
        changed_files += 1
        from_label = f"a/{rel}" if rel in old_files else "/dev/null"
        to_label = f"b/{rel}" if rel in new_files else "/dev/null"
        udiff = list(
            difflib.unified_diff(
                a_lines,
                b_lines,
                fromfile=from_label,
                tofile=to_label,
                n=3,
            )
        )
        for ln in udiff:
            if ln.startswith("+") and not ln.startswith("+++"):
                added_lines += 1
            elif ln.startswith("-") and not ln.startswith("---"):
                deleted_lines += 1
        diff_chunks.append("".join(udiff))

    full_diff = "\n".join(diff_chunks) if diff_chunks else "# (与初始沙盒源码相比无任何代码改动)\n"
    if tokens_to_redact:
        full_diff = _sanitize_text(full_diff, tokens_to_redact)
    stats = {
        "changed_files": changed_files,
        "added_lines": added_lines,
        "deleted_lines": deleted_lines,
    }
    return full_diff, stats


def build_official_level5_reference_doc(root: Path = ROOT) -> str:
    """生成盲评强制对照的《官方 5 级平庸参照补丁样本》文档（含真实 diff 补丁对照 · xiaonuo-v3.0）。"""
    tpl_dir = root / "src" / "sandbox_template"
    lvl5_dir = root / "src" / "baselines" / "level5_mediocre"
    lvl5_diff, lvl5_stats = build_unified_diff(tpl_dir, lvl5_dir)
    return f"""# 官方 5 级平庸参照补丁样本（评委打分强制对照锚点 · xiaonuo-v3.0）

> **强制封顶规则（打分前必读）**：
> 本样本展示了一个在 16 模块代码库上**典型的“5.0 级平庸水平”补丁**（改动 {lvl5_stats['changed_files']} 个文件，`+{lvl5_stats['added_lines']} / -{lvl5_stats['deleted_lines']}` 行）。
> **凡是被测作品在增量算法降维、跨模块统一锁偏序、五维纪元与二级借调快照、或双通道二阶安全与抗复杂度熔断上的工程思想未明显超越本 5 级平庸样本的，其 D 层总分不得超过 `13.5 / 30`！**

---

## 一、本 5 级平庸补丁的五大典型短板特征

1. **只加基础单列索引，未解决高阶算法复杂度、双向引用增量传播与内存驻留**：
   - 仅在 `db.py` 加了 4 个单列索引，将引用读取合并为全表拉取；
   - **完全未解决**近似聚类去重的 $O(N^2)$ 两两比较、短语词距的 $O(P_1 \\times P_2)$ 下标嵌套遍历、三跳制裁传染逐笔重新拉边建图与 `list.pop(0)` 搜索，且 `audit_export.py` 仍全量 `fetchall()` 大载荷列。
2. **用“一把全局粗暴大锁”逃避跨模块锁偏序与并发设计**：
   - 在 `server.py` 入口套了一把 `_GLOBAL_GATEWAY_LOCK` 串行化全站读写请求，未启用 SQLite WAL 与线程本地连接复用，更未针对 `transfer_tenant_quota` 与 `evaluate_transaction_batch`（`REJECT` 联动扣减 `REALTIME_ALERT_POOL`）设计全局升序分片锁与 `BEGIN IMMEDIATE` 单事务。
3. **无界粗糙缓存：一写即整库清空，二级借调上游到期/撤权/隔离墙变更却漏失效**：
   - `search_service.py` 的 `_NAIVE_SEARCH_CACHE` 在每次单篇 `upsert`/`retire`/`quarantine` 时粗暴清空全库缓存（高频混写下持续抖动），而在角色撤回、二级转借调上游一级窗口自然跨过 `expires_at`（零写操作）、源头委托人被撤权或利益冲突墙变更时毫无感知，导致严重脏读越权。
4. **只修表层查询拼接，漏掉双通道二阶注入、格式化反射/放大、跨租户引用侧信道与有向环路**：
   - 虽参数化了 `search_documents` 主查询并关闭了 `/diagnostics`，但漏掉了 `audit_export.py` 报表模板 `extra_event_filter` 的二阶 SQL 注入、`title_format.format(..., env=RUNTIME_ENV)` 的属性反射与 `:0>200000` 宽度内存放大，以及跨租户内部 `doc_` 引用存在性侧信道；
   - `delegation.py` 未做访问集合防环与跳数前置剪枝，遇到双向借调有向环路即触发无限递归栈崩溃；`batch_get_documents` 漏掉纵向密级与三级利益冲突墙；Webhook 漏掉 `nonce` 唯一防重放。
5. **未做四位一体强原子回滚与抗复杂度/数值边界熔断**：
   - `evaluate_transaction_batch` 逐笔独立扣减 `REALTIME_ALERT_POOL` 并提交（末尾交易失败会导致已扣告警配额永久泄漏，且脏边污染滑窗与三跳传染图）；未修邮箱与自定义规则 ReDoS（含花括号大上界与反向引用）、千层 JSON/膨胀规则树/超长引用洪水、`limit=-1` 放大及 `bool`/超 64 位整数/`NaN` 类型混淆。

---

## 二、官方 5 级平庸参照补丁全量 Diff 对照

```diff
{lvl5_diff.strip()}
```
"""


RUBRIC_MD = """# D 层盲评量表与反通胀五档精细硬封顶规则（xiaonuo-v3.0 · 满分 30 分 = D1 11 + D2 10 + D3 9）

> **核心校准铁律（严禁高分粘连，严禁把“基本修全但未达极致”的作品塞进 28–29 分）**：
> 1. 评委必须先通读同目录的 [`OFFICIAL_LEVEL5_BASELINE.md`](OFFICIAL_LEVEL5_BASELINE.md)，再逐行审阅各 `case-XX/` 的 `code_changes.diff`、`EXPLANATION.md` 与 `code/`。
> 2. **第 1 档 · 5.0 级平庸硬封顶（`D ≤ 13.5 / 30`，即 `D1 ≤ 4.8, D2 ≤ 4.6, D3 ≤ 4.1`）**：凡停留在“单列索引 + 全局一把大锁 + 无权限/时效失效的粗糙缓存 + 漏防二阶注入/反射/环路/复杂度炸弹”水平、未明显超越官方 5 级样本的，总分严格 `≤ 13.5`！
> 3. **第 2 档 · 6.5 级及格中坚硬封顶（`D ≤ 19.0 / 30`，即 `D1 ≤ 7.0, D2 ≤ 6.5, D3 ≤ 5.5`）**：虽移除全局大锁并补上主要表层漏洞，但**命中任一架构级硬伤**：① 文档 `upsert`/`retire`/`quarantine` 仍整表重查数据库或全量重建整租户倒排索引，或未联动更新内部 `doc_` 引用失效后的被引用方 `citation_count`，或将整库大体积原始正文 `body` 无界常驻内存；② `transfer_tenant_quota` 与 `evaluate_transaction_batch`（扣减 `REALTIME_ALERT_POOL`）未遵循全局统一锁偏序 + `BEGIN IMMEDIATE`（如在 `BEGIN IMMEDIATE` 事务内再去请求 Python 配额锁，存在跨层死锁或丢失更新隐患）；③ 未正确支持 2 跳受控借调链（含上游一级窗口自然到期零写降级、源头撤权级联失效及有向环路免疫）；④ 交易批次异常未实现“数据库 + 滑窗 + 三跳传染图 + `REALTIME_ALERT_POOL` 告警配额”四位一体强原子回滚，或遗漏任一通道二阶 SQL 注入（报表模板或文档引用）——总分严格 `≤ 19.0`！
> 4. **第 3 档 · 7.5 级良好硬封顶（`D ≤ 23.0 / 30`，即 `D1 ≤ 8.5, D2 ≤ 8.0, D3 ≤ 6.5`）**：具备基本增量索引、无死锁加锁与四重回滚，但**存在明显次优复杂度、纪元耦合或局部安全漏防**：① 修改单条 `doc-acl` 隔离墙规则却连带清空整租户文档倒排索引（未解耦 `acl` 与 `doc` 纪元）；② 三跳制裁传染仍逐笔全表扫描，或滑窗中位数逐笔重新全量排序（未做 `bisect`/双堆 $O(\\log W)$ 维护），或词距未做 $O(|P_1|+|P_2|)$ 双指针扫描，或审计/报表仍 `fetchall()` 全量进内存；③ 漏防跨租户 `doc_` 引用存在性侧信道、模板超宽格式说明符放大（如 `:0>200000`）、花括号大上界/反向引用正则、超长引用列表洪水或 `bool`/超 64 位整数/`NaN` 边界；④ `EXPLANATION.md` 的 C1–C5 存在任何不实或夸大（同时 D3 `≤ 6.0`）——总分严格 `≤ 23.0`！
> 5. **第 4 档 · 8.5 级优秀硬封顶（`D ≤ 26.0 / 30`，即 `D1 ≤ 9.6, D2 ≤ 9.0, D3 ≤ 7.4`）**：**【打破顶部粘连核心分水岭】** 核心功能与红队防御虽基本齐备，但在静态代码核查中发现**以下任一精细度短板**的作品，**总分严格锁死在 `23.5–26.0`，严禁给上 `27+`**：
>    - **短板 A（索引与去重精细度）**：去重虽按归一化法规分桶，但未做集合大小比值下界剪枝（`min_len / max_len < 0.70` 跳过交集），或双指针词距在 `min_dist == 1` 时未提前短路退出，或内部引用状态翻转时仍重查全租户引用表而非通过内存反向映射 `reverse_dependents` 做 $O(\\text{deg})$ 局部更新；
>    - **短板 B（常驻内存与容量边界）**：内存索引节点未使用 `__slots__`、仍保留完整原始 `body` 字符串或保留多代历史索引副本，或线程连接池/检索缓存/编译正则缓存无容量上限；
>    - **短板 C（滑窗鲁棒性）**：单调滑窗未兼容“批次内时间戳乱序倒退”的精确回退保底；
>    - **短板 D（侧信道与前置词法防御）**：认证未对未知租户/未知用户做 dummy `hmac.compare_digest` 常量时间掩蔽，或 JSON 深度检查在 `json.loads` 之后才执行（无法拦截千层原始 JSON 触发解析器栈溢出），或模板仅删除 `env` 参数但仍调用 `str.format`；
>    - **短板 E（工程克制与权衡深度）**：跨模块职责侵入混乱、残留冗余死代码或第 5 节未深入诚实剖析单机架构权衡。
> 6. **第 5 档 · 9.5 级殿堂大师档准入（`27.0–30.0 / 30`，即 `D1: 10.0–11.0, D2: 9.3–10.0, D3: 7.7–9.0`）**：**唯有零短板通过第 4 档全部静态核验清单**（紧凑 `__slots__` 剔除原文 + 反向引用图 $O(L+\\text{deg})$ 写时复制 + 大小剪枝与双指针短路 + 带乱序回退的 $O(\\log W)$ 滑窗 + 两层多源传染前沿 + 五维解耦纪元与 2 跳无环快照 + 全系统统一升序分片锁先于 `BEGIN IMMEDIATE` 四重原子事务 + 双通道二阶安全 + 纯白名单字面替换 + `json.loads` 前词法深度预检 + C1–C5 100% 严丝合缝）的极致作品，方可授予 `27.0–30.0`！

---

## D1 增量算法降维、内存紧凑度与锁/缓存架构（0–11 分：平庸 ≤ 4.8，6.5级 ≤ 7.0，7.5级 ≤ 8.5，8.5级 ≤ 9.6）
- **10.0–11.0（9.5 级殿堂大师）**：紧凑 `__slots__` 倒排节点剔除全文驻留 + 双向引用依赖图 $O(L+\\text{deg})$ 差量更新 + 双指针 `min_dist==1` 短路 + 法规分桶与大小下界剪枝；带乱序保底的 $O(\\log W)$ 滑窗中位数 + 批次单次拉边两层传染前沿；`fetchmany` 流式投影；WAL + 有界线程连接池 + 可变参全局升序分片锁先于 `BEGIN IMMEDIATE` + 五维独立纪元与 2 跳秒级双窗口快照。
- **8.6–9.6（8.5 级优秀）**：已实现单篇增量倒排、五维纪元与无死锁锁序，但缺反向引用局部刷新、缺集合大小比值剪枝、未剔除 `body`/`__slots__` 或缺滑窗乱序保底。
- **5.0–8.5（6.5–7.5 级）**：全量重建倒排或锁序隐患（`≤ 7.0`）；纪元耦合、逐笔排序求中位数或 `fetchall` 大列（`≤ 8.5`）。

## D2 纵深安全防御体系化（0–10 分：平庸 ≤ 4.6，6.5级 ≤ 6.5，7.5级 ≤ 8.0，8.5级 ≤ 9.0）
- **9.3–10.0（9.5 级殿堂大师）**：一阶与双通道二阶（报表模板 + 文档引用）全参数化与白名单隔离 + 跨租户引用零侧信道；彻底移除 `.format` 改为纯白名单字面占位符单遍替换（防反射与 `:0>200000` 宽度放大）；2 跳无环借调与三级隔离墙全入口严密闭环 + 未知主体 dummy 常量时间掩蔽；`resolve().is_relative_to()` + 双重编码拦截、Webhook 唯一 Nonce 防重放、四位一体强原子回滚；`json.loads` 前 $O(N)$ 词法深度预检 + 零回溯邮箱 + 正则嵌套/通配链/花括号/反向引用熔断 + 规则/引用预算 + 严格整数/`NaN` 守卫。
- **8.1–9.0（8.5 级优秀）**：主干漏洞均已封堵，但仍用精简 `str.format`、`json.loads` 后才查深度、缺未知主体常量时间掩蔽或个别引用预算较松。
- **4.8–8.0（6.5–7.5 级）**：漏任一二阶注入、漏委托环路/上游自然到期降级或漏配额原子回滚（`≤ 6.5`）；漏跨租户引用侧信道、宽度放大或数值/正则边界（`≤ 8.0`）。

## D3 补丁外科手术品味与诚实度（0–9 分：平庸 ≤ 4.1，6.5级 ≤ 5.5，7.5级 ≤ 6.5，8.5级 ≤ 7.4）
- **强制核查 `EXPLANATION.md` 第 4 节的 5 条核心工程声明（C1–C5）**：
  - **红线 1**：未填写 `EXPLANATION.md` 或敷衍塞责的，**D3 强制 ≤ 2.0 分**；
  - **红线 2**：C1–C5 中有 **≥ 2 条**未实现或夸大的，**D3 强制 ≤ 3.0 分**；发现 **1 条**不实或存在偏差，至少扣 2.0 分且触发 7.5 级及以下封顶（**D3 ≤ 6.0 分，D 总分 ≤ 23.0**）；
  - **红线 3**：16 模块边界混乱、吞异常掩盖错误或残留调试死代码的，**D3 ≤ 6.5 分**。
- **7.7–9.0（9.5 级殿堂大师）**：跨 16 模块演进内聚优雅、零冗余侵入，C1–C5 五条声明与代码 100% 严丝合缝，且深刻诚实剖析了单机内存快照与存储并发取舍。
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="冻结选手计时并生成含 code_changes.diff 与官方 5 级参照样本的匿名盲评包")
    ap.add_argument("--model", required=True, help="开局时使用的模型名称或运行标识")
    ap.add_argument("--model-id", default=None, help="可选：显式指定汇总分组用的规范模型 ID")
    ap.add_argument("--runs", nargs="*", default=None, help="可选：显式指定要打包的 run 目录路径")
    ap.add_argument("--runs-dir", default=str(ROOT / "runs"))
    ap.add_argument("--blind-dir", default=str(ROOT / "leaderboard" / "blind"))
    ap.add_argument("--blind-maps-dir", default=str(ROOT / "leaderboard" / "blind-maps"))
    ap.add_argument("--repack", action="store_true", help="允许对已冻结打包过的运行重新导出盲评包并更新映射")
    args = ap.parse_args()

    raw_model = args.model.strip()
    model_id = (args.model_id.strip().lower() if args.model_id else canonical_model_id(raw_model)).strip()
    if not model_id:
        print("打包失败：--model/--model-id 不能为空")
        return 1

    runs_root = Path(args.runs_dir).resolve()
    if args.runs:
        runs = [Path(p).resolve() for p in args.runs]
    else:
        if not runs_root.is_dir():
            print(f"找不到运行根目录：{runs_root}")
            return 1
        if canonical_model_id(raw_model) != raw_model.lower():
            runs = sorted(p for p in runs_root.iterdir() if p.is_dir() and matches_batch_run(raw_model, p.name))
        else:
            runs = sorted(p for p in runs_root.iterdir() if p.is_dir() and canonical_model_id(p.name) == model_id)

    runs = [r for r in runs if (r / "protocol.json").is_file() and (r / "workspace").is_dir()]
    if not runs:
        print(f"未找到模型 {model_id} 的有效运行目录（请先执行 python tools/start_run.py --model <模型名>）")
        return 1

    blind_root = Path(args.blind_dir).resolve()
    blind_maps_dir = Path(args.blind_maps_dir).resolve()
    blind_root.mkdir(parents=True, exist_ok=True)
    blind_maps_dir.mkdir(parents=True, exist_ok=True)

    existing_run_to_pack: dict[str, str] = {}
    existing_map_files: list[tuple[Path, dict]] = []
    for mf in sorted(blind_maps_dir.glob("*.blind-map.json")):
        try:
            bm = json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if canonical_model_id(bm.get("model_id") or bm.get("model", "")) != model_id:
            continue
        existing_map_files.append((mf, bm))
        if bm.get("superseded_by"):
            continue
        pid_ex = bm.get("pack_id") or ""
        for cmeta in (bm.get("cases") or {}).values():
            rn_ex = (cmeta or {}).get("run")
            if rn_ex and pid_ex:
                existing_run_to_pack[rn_ex] = pid_ex

    if not args.repack and not args.runs and existing_run_to_pack:
        unmapped = [r for r in runs if r.name not in existing_run_to_pack]
        if unmapped:
            runs = unmapped

    # 安全预检：严禁选手预生成官方分数文件，严禁冻结点后篡改沙盒代码
    for rdir in runs:
        proto = json.loads((rdir / "protocol.json").read_text(encoding="utf-8"))
        ws_dir = rdir / "workspace"
        forged_in_ws = [
            p.relative_to(ws_dir).as_posix()
            for p in ws_dir.rglob("*")
            if p.is_file() and p.name in ("评分.json", "result.json")
        ]
        if forged_in_ws:
            print(f"打包拦截：{rdir.name}/workspace 内发现违禁评分文件 {forged_in_ws}！")
            return 1

        timing = proto.get("timing") or {}
        if not timing.get("end_iso"):
            premature = [fn for fn in ("评分.json", "result.json") if (rdir / fn).exists()]
            if premature:
                print(
                    f"打包拦截：{rdir.name} 尚未冻结交卷却已存在官方评分文件 {premature}！\n"
                    "选手阶段严禁运行 score_run.py 或伪造官方得分。"
                )
                return 1
        else:
            rec_sha = proto.get("code_sha256")
            cur_sha = compute_workspace_sha256(ws_dir)
            if rec_sha and rec_sha != cur_sha:
                print(f"打包拒绝：{rdir.name} 在首次冻结 t1 后修改了沙盒源码，违反计时冻结纪律！")
                return 1

    if not args.repack and all(r.name in existing_run_to_pack for r in runs):
        packs_str = ", ".join(sorted({str(blind_root / existing_run_to_pack[r.name]) for r in runs}))
        print(f"提示：{model_id} 的目标运行已生成过匿名盲评包：{packs_str}（如需重打请加 --repack）")
        return 0

    pack_id = secrets.token_hex(6)
    pack_dir = blind_root / pack_id
    pack_dir.mkdir(parents=True, exist_ok=False)

    readme_md = """# 匿名盲评包 · shield-turbo-xiaonuo（仅限独立评委阅读）

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
"""
    (pack_dir / "README.md").write_text(readme_md, encoding="utf-8")
    (pack_dir / "RUBRIC.md").write_text(RUBRIC_MD, encoding="utf-8")
    (pack_dir / "OFFICIAL_LEVEL5_BASELINE.md").write_text(
        build_official_level5_reference_doc(ROOT),
        encoding="utf-8",
    )

    template_dir = ROOT / "src" / "sandbox_template"
    os_user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    cases = []
    mapping_cases = {}

    for idx, rdir in enumerate(runs, 1):
        case_id = f"case-{idx:02d}"
        proto_path = rdir / "protocol.json"
        proto = json.loads(proto_path.read_text(encoding="utf-8"))
        ws_dir = rdir / "workspace"

        now_iso = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        timing = proto.setdefault("timing", {})
        current_code_sha = compute_workspace_sha256(ws_dir)

        if not timing.get("end_iso"):
            t0_str = timing.get("t0_iso") or timing.get("process_iso") or now_iso
            e2e_sec = max(0.0, round(_epoch(now_iso) - _epoch(t0_str), 2))
            timing["end_iso"] = now_iso
            timing["endToEndSeconds"] = e2e_sec
            proto["code_sha256"] = current_code_sha
            proto["status"] = "packed"
            proto_path.write_text(json.dumps(proto, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        else:
            if not proto.get("code_sha256"):
                proto["code_sha256"] = current_code_sha
                proto_path.write_text(json.dumps(proto, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        tokens_to_redact = [
            raw_model,
            model_id,
            rdir.name,
            proto.get("run_name") or "",
            proto.get("model_id") or "",
            os_user if len(os_user) >= 3 else "",
        ]

        case_dir = pack_dir / case_id
        code_out_dir = case_dir / "code"
        code_out_dir.mkdir(parents=True, exist_ok=True)

        diff_text, diff_stats = build_unified_diff(template_dir, ws_dir, tokens_to_redact=tokens_to_redact)
        (case_dir / "code_changes.diff").write_text(diff_text, encoding="utf-8")

        explanation_text = "# 缺失 EXPLANATION.md\n\n该选手未提交《性能剖析与安全加固阐述》。\n"
        explanation_filled = False
        file_manifest: list[tuple[str, int]] = []

        for src_file in sorted(ws_dir.rglob("*"), key=lambda x: x.relative_to(ws_dir).as_posix()):
            if not src_file.is_file():
                continue
            rel_parts = src_file.relative_to(ws_dir).parts
            if any(p in SKIP_DIRS for p in rel_parts):
                continue
            if src_file.name in FORBIDDEN_SCORE_FILES or src_file.name in TEMPLATE_DOC_FILES:
                continue
            if src_file.suffix.lower() in SKIP_SUFFIXES:
                continue

            rel_posix = src_file.relative_to(ws_dir).as_posix()
            raw_txt = src_file.read_text(encoding="utf-8", errors="replace")
            clean_txt = _sanitize_text(raw_txt, tokens_to_redact)
            line_cnt = len(clean_txt.splitlines())

            if rel_posix == "EXPLANATION.md":
                explanation_text = clean_txt
                explanation_filled = ("（请填写" not in clean_txt) and (len(clean_txt.strip()) > 260)
                continue

            dst_file = code_out_dir / rel_posix
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            dst_file.write_text(clean_txt, encoding="utf-8")
            file_manifest.append((f"code/{rel_posix}", line_cnt))

        (case_dir / "EXPLANATION.md").write_text(explanation_text, encoding="utf-8")

        overview_lines = [
            f"# 匿名作品概览 · {case_id}",
            "",
            f"- **相对初始模板改动文件数**：{diff_stats['changed_files']} 个（`+{diff_stats['added_lines']} / -{diff_stats['deleted_lines']}` 行，详见同目录 [`code_changes.diff`](code_changes.diff)）",
            f"- **《性能剖析与安全加固阐述》状态**：{'已填写（请打开 EXPLANATION.md 逐条核验第 4 节 C1–C5 声明）' if explanation_filled else '⚠️ 疑似保留空白模板或未完整填写（请核实后按 RUBRIC.md 红线封顶处理）'}",
            "- **强制参照标尺**：请对照上级目录 [`../OFFICIAL_LEVEL5_BASELINE.md`](../OFFICIAL_LEVEL5_BASELINE.md) 评估是否明显超越 5 级平庸补丁",
            f"- **脱敏源码文件总数**：{len(file_manifest)} 个（共 {sum(x[1] for x in file_manifest)} 行）",
            "",
            "## 包内文件清单",
            "",
            "| 路径 | 行数 |",
            "| --- | ---: |",
            f"| `code_changes.diff` | {len(diff_text.splitlines())} |",
            f"| `EXPLANATION.md` | {len(explanation_text.splitlines())} |",
        ]
        for rel_p, lcnt in file_manifest:
            overview_lines.append(f"| `{rel_p}` | {lcnt} |")
        (case_dir / "OVERVIEW.md").write_text("\n".join(overview_lines) + "\n", encoding="utf-8")

        cases.append(
            {
                "case_id": case_id,
                "overview": f"{case_id}/OVERVIEW.md",
                "diff": f"{case_id}/code_changes.diff",
                "explanation": f"{case_id}/EXPLANATION.md",
                "code_dir": f"{case_id}/code",
            }
        )
        mapping_cases[case_id] = {
            "run": rdir.name,
            "code_sha256": proto.get("code_sha256"),
            "end_iso": timing.get("end_iso"),
            "diff_stats": diff_stats,
        }

    manifest = {
        "schema_version": 1,
        "pack_id": pack_id,
        "blind": True,
        "rubric": "RUBRIC.md",
        "official_level5_reference": "OFFICIAL_LEVEL5_BASELINE.md",
        "cases": cases,
    }
    (pack_dir / "pack.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    submit_md = f"""# 提交 D 层盲评评分

独立审阅完 `OFFICIAL_LEVEL5_BASELINE.md`、`code_changes.diff`、`EXPLANATION.md` 与 `code/` 后，请在仓库根目录执行以下命令提交评分（只追加写入中心日志，不显示他人评分）：

```sh
python src/scoring/judge_submit.py \\
  --pack-dir "leaderboard/blind/{pack_id}" \\
  --case-id case-01 \\
  --judge-id <你的评委唯一ID，如 judge-1> \\
  --judge-model <你的模型名称> \\
  --D1 <0-11> --D2 <0-10> --D3 <0-9> \\
  --evidence "<逐条给出 EXPLANATION C1-C5 核验结论 + 对照 5 级样本的具体补丁/源码定位>" \\
  --note "<指出该作品的最强反证与核心工程短板>"
```

如需重评更新你本人此前的打分，保持相同 `--judge-id` 附加 `--update` 再次运行即可；汇总出榜时将实时采信最新一条记录。
"""
    (pack_dir / "SUBMIT.md").write_text(submit_md, encoding="utf-8")

    if args.repack and existing_map_files:
        packed_names = {m["run"] for m in mapping_cases.values()}
        for old_mf, old_bm in existing_map_files:
            old_cases = old_bm.get("cases") or {}
            kept = {k: v for k, v in old_cases.items() if (v or {}).get("run") not in packed_names}
            if len(kept) != len(old_cases):
                old_bm["cases"] = kept
                if not kept:
                    old_bm["superseded_by"] = pack_id
                old_mf.write_text(json.dumps(old_bm, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    map_path = blind_maps_dir / f"{model_id}.{pack_id}.blind-map.json"
    map_obj = {
        "model": raw_model,
        "model_id": model_id,
        "pack_id": pack_id,
        "created_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "cases": mapping_cases,
    }
    map_path.write_text(json.dumps(map_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("================================================================")
    print("选手收尾完成！计时已冻结，脱敏差异补丁与匿名盲评包已生成。")
    print(f"  规范模型 ID  : {model_id}")
    print(f"  匿名盲评包   : leaderboard/blind/{pack_id}")
    print(f"  包内案例数   : {len(cases)} ({', '.join(c['case_id'] for c in cases)})")
    print(f"  私有映射文件 : {map_path}（严禁交给评委！）")
    print("----------------------------------------------------------------")
    print("【下一步交接】")
    print(f"  1. 请仅将 `leaderboard/blind/{pack_id}` 目录路径交给独立评委盲评；")
    print("  2. 评委提交完成后，由汇总侧运行 `python leaderboard/finalize.py` 执行高压压测与红队轰炸出榜。")
    print("================================================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
