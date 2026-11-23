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
    """生成盲评强制对照的《官方 5 级平庸参照补丁样本》文档（含真实 diff 补丁对照）。"""
    tpl_dir = root / "src" / "sandbox_template"
    lvl5_dir = root / "src" / "baselines" / "level5_mediocre"
    lvl5_diff, lvl5_stats = build_unified_diff(tpl_dir, lvl5_dir)
    return f"""# 官方 5 级平庸参照补丁样本（评委打分强制对照锚点）

> **强制封顶规则（打分前必读）**：
> 本样本展示了一个**典型的“5 级平庸水平”补丁**（改动 {lvl5_stats['changed_files']} 个文件，`+{lvl5_stats['added_lines']} / -{lvl5_stats['deleted_lines']}` 行）。
> **凡是被测作品在算法降维、并发锁粒度、缓存隔离失效或纵深安全防御上的工程思想未明显超越本 5 级平庸样本的，其对应维度最高锁死在 5 级（即 D 层总分不得超过 `15.0 / 30`）！**

---

## 一、本 5 级平庸补丁的五大典型短板特征

1. **只做表层索引，未看穿 $O(N^2)$ 核心复杂度与内存膨胀**：
   - 仅在 `db.py` 加了基础单列索引，在 `search_service.py` 把引用计数改为 `GROUP BY`；
   - **完全未解决**合规文档检索去重中的双重循环 $O(N^2)$ 词集比对，未构建倒排索引，也未将 `audit_export.py` 改造为游标流式输出（仍全量深拷贝列表进内存）。
2. **用“一把粗暴全局大锁”逃避并发设计**：
   - 在 `server.py` 顶部套了一把 `_GLOBAL_GATEWAY_LOCK = threading.Lock()` 串行包裹所有请求；虽然表面防住了配额超扣，但导致跨租户高并发读写全部排队阻塞，未开启 SQLite WAL，也未使用细粒度分片锁或 SQL 原子条件扣减。
3. **缓存缺乏角色密级隔离与跨模块事件失效**：
   - 在 `search_service.py` 添加了 `_NAIVE_SEARCH_CACHE`，但当管理员在 `auth.py` 调用 `revoke_or_grant_role` 撤回用户高密级授权时，缓存毫无感知，导致被撤权员工仍能从脏缓存中读出绝密文档。
4. **安全加固停留在“脆弱字符串黑名单替换”与半截补丁**：
   - `audit_export.py` 仅用 `.replace("../", "").replace("..\\\\", "")` 防目录穿越，被 `....//` 或双重编码直接绕过；
   - `batch_get_documents` 只补了 `tenant_id` 横向过滤，却漏掉了 `clearance_level <= caller.max_clearance` 纵向密级校验；
   - Webhook 仅检查了 300 秒时间戳，漏掉了同窗口 `nonce` 唯一防重放与 `hmac.compare_digest` 常量时间比对。
5. **完全忽略不对称算法复杂度攻击（Anti-DoS）**：
   - 未修复 `rule_engine.py` 中嵌套量词邮箱正则的灾难性回溯（ReDoS），未限制自定义规则树的嵌套深度与节点总数，未封堵 `limit=-1`（SQLite 全表返回）慢查询放大漏洞。

---

## 二、官方 5 级平庸参照补丁全量 Diff 对照

```diff
{lvl5_diff.strip()}
```
"""


RUBRIC_MD = """# D 层盲评量表与反通胀三档硬锁规则（满分 30 分 = D1 11 + D2 10 + D3 9）

> **核心校准铁律（严禁人情分与高分粘连）**：
> 1. 评委必须先阅读同目录的 [`OFFICIAL_LEVEL5_BASELINE.md`](OFFICIAL_LEVEL5_BASELINE.md)（《官方 5 级平庸参照补丁样本》），再审阅各 `case-XX/` 的 `code_changes.diff`、`EXPLANATION.md` 与 `code/`。
> 2. **5 级平庸硬封顶（`D ≤ 15.0 / 30`）**：凡是工程优化与安全加固停留在“表层加索引 + 全局一把大锁 + 缺乏权限失效隔离的粗糙缓存 + 字符串替换防穿越/漏防复杂度炸弹”水平、未明显超越官方 5 级样本的，**D1 ≤ 5.5、D2 ≤ 5.0、D3 ≤ 4.5（D 层总分严格 ≤ 15.0 / 30）**！
> 3. **7 级良好硬封顶（`D ≤ 22.0 / 30`）**：虽实现了主要降维与细粒度锁，但**存在任何一处局部耦合、算法未彻底降维或边界漏防**（例如：修改单条 ACL 规则却连带清空整租户预分词文档倒排索引；去重未做集合大小下界剪枝；滑窗逐笔 `list.insert` 未做单调队列 $O(1)$ 优化；自定义正则漏拦多无界通配符 `.*a.*b.*` 或超大花括号重复次数；规则树漏限制单节点扇出子节点数/`IN` 列表长度；检索漏拦纯通配符洪水；或未拦截布尔伪装整数/超 64 位整数溢出），**严禁进入大师档，强制 D1 ≤ 8.2、D2 ≤ 7.5、D3 ≤ 6.3（D 层总分严格 ≤ 22.0 / 30）**！
> 4. **9 级大师档准入（`25.5–30.0 / 30`）**：只有同时实现真正算法降维（含下界剪枝与 $O(1)$ 滑窗）、多维独立 Epoch+CAS 精准失效缓存、细粒度并发锁、全变体防 DoS/类型溢出零死角闭环且 C1–C5 文档声明 100% 严丝合缝的顶尖工程才可进入 **`25.5–30.0 / 30`**！

---

## D1 算法降维与缓存/锁粒度设计（0–11 分，5 级平庸封顶 5.5 分，有局部缺口封顶 8.2 分）
- **9.0–11.0（大师级）**：精准看穿并重构全部核心性能黑洞——① 检索引入预分词倒排表并利用 `regulation_code` 分桶 + 集合大小下界剪枝将近似去重从 $O(N^2)$ 降维至接近线性，且 100% 保持原排序与簇计数语义；② 批次风控改为单次按账户集窗口预取 + 单调序列 $O(1)$ 队列/乱序二分推进 + 单事务批量落盘；③ 审计摘要改为游标流式分块迭代（剔除冗余大载荷列）；④ 开启 SQLite WAL + 线程本地连接池 + 细粒度键级/租户分片锁 + 文档/权限/ACL/策略四维独立版本纪元与 CAS 防回填缓存。
- **6.0–8.2（良好，局部缺口封顶线）**：解决了大部分 N+1 与主要算法瓶颈，锁粒度与缓存失效设计基本合理，但个别环节（如 ACL 变更误清整库文档倒排索引、去重未做集合大小下界剪枝或滑窗每次 `list.insert`）优化不够彻底。
- **0.0–5.5（平庸及以下）**：未消除 $O(N^2)$ 嵌套遍历，或使用全局互斥大锁阻塞全站跨租户并发读写（**凡使用全局粗暴大锁串行化所有请求的，D1 强制 ≤ 5.5 分**），或缓存存在跨租户/撤权脏读隐患。

## D2 纵深安全防御体系化（0–10 分，5 级平庸封顶 5.0 分，有局部漏防封顶 7.5 分）
- **8.5–10.0（大师级）**：构建成体系的白名单与边界熔断防御——① 全参数化查询 + 排序字段枚举白名单；② `Path.resolve().is_relative_to()` 物理路径锚定 + 文件名正则白名单 + 符号链接与双重编码拦截；③ 横向租户隔离与纵向密级（`clearance_level`）全接口闭环 + 诊断/异常彻底脱敏；④ 数据库条件原子更新防 TOCTOU + `hmac.compare_digest` + 时间窗 + 唯一 Nonce 防重放；⑤ 线性零回溯校验消除 ReDoS + 自定义正则拦截嵌套量词/环视/反向引用/多无界通配符/大重复边界 + 规则树深度/节点数/扇出宽度/`IN` 列表硬熔断 + 分页 `limit`/`offset`/词数/通配符硬边界 + 布尔伪装整数与超 64 位整数溢出拦截。
- **5.5–7.5（良好，局部漏防封顶线）**：堵住了绝大部分注入、越权、并发与重放漏洞，但在个别复杂度炸弹或类型边界（如自定义 `REGEX` 多无界通配符/大重复次数、扇出膨胀树、纯通配符洪水查询、布尔伪装整数或超 64 位整数溢出）防御上仍有缺口。
- **0.0–5.0（平庸及以下）**：依赖 `.replace("../", "")` 等脆弱黑名单过滤、遗漏纵向密级校验、遗漏 Nonce 去重，或完全未防御 ReDoS 与深层载荷炸弹。

## D3 补丁外科手术品味与诚实度（0–9 分，5 级平庸封顶 4.5 分，有局部瑕疵封顶 6.3 分）
- **强制核查 `EXPLANATION.md` 第 4 节的 5 条核心工程声明（C1–C5）**：
  - **红线 1**：未填写 `EXPLANATION.md`（保留空白模板或寥寥数语敷衍）的，**D3 强制 ≤ 2.0 分**；
  - **红线 2**：C1–C5 中有 **≥ 2 条**声明在 `code_changes.diff` 与 `code/` 中根本未实现或严重夸大吹嘘的，**D3 强制 ≤ 3.0 分**（发现 1 条不实或表述与实际代码逻辑有偏差，至少扣 2.0 分并锁定 D3 ≤ 6.3 分）；
  - **红线 3**：改动混乱臃肿、残留大量死代码/调试打印、破坏原有模块清晰职责边界或遗漏异常/边界状态清理的，**D3 ≤ 6.3 分**。
- **7.5–9.0（大师级）**：`code_changes.diff` 干净利落如外科手术，模块边界清晰，C1–C5 五条声明与代码实现 100% 严丝合缝，且第 5 节客观诚实剖析了单机缓存/SQLite 边界取舍。
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
