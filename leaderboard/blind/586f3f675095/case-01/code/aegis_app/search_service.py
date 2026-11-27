# -*- coding: utf-8 -*-
"""企业合规文档多维检索、邻近度相关性打分、双轨法规簇折叠与密级管控编排服务。

相对 v3.0 初始版本的核心重构（输出与原版逐位一致）：

* **候选集**：由租户常驻倒排（``DocumentIndex``）按查询词取候选，绝不整库回表、绝不逐篇连库；
  原始大正文 ``body`` 不常驻，仅对命中文档按需取正文算词距、取 140 字符摘要；
* **词距邻近度**：双指针 O(n + m)，``min_dist == 1`` 早停；
* **近似去重**：先以“集合规模比值 < 0.70”做 O(1) 剪枝（规模窗口 ``[ceil(0.7l), floor(l/0.7)]``），
  再用“全租户词 -> 文档”倒排做交集计数与可为性剪枝，候选按规模升序**滑动计数**到目标下界即停，
  一次扫描即得精确簇规模（不再 O(N²) 两两重算分词与 Jaccard）；
* **权限/隔离墙**：单次请求解析一次有效密级与组织血缘，逐候选仅 O(1) 判墙；
* **SQL**：``tag_filter`` 等输入全部参数化，``sort_by`` 走白名单。
"""
from __future__ import annotations

import json
import re
from typing import Any

from .auth import CallerContext
from .config import (
    DEDUP_JACCARD_THRESHOLD,
    DEFAULT_PAGE_LIMIT,
    MAX_ID_CHARS,
    MAX_QUERY_TERMS,
    MAX_SEARCH_LIMIT,
    PROXIMITY_MAX_SPAN,
)
from .db import DocumentIndex, DocTenantView, GatewayDB
from .doc_indexer import TokenProfile, token_positions, tokenize_text
from .guards import guard_text, strict_bool, strict_int
from .legacy_compat import canonicalize_regulation_code

_SORT_FIELDS = ("score", "updated_at", "risk_weight")
_SORT_DIRS = ("asc", "desc")
_SNIPPET_CHARS = 140
_MAX_QUERY_CHARS = 8192
_MAX_OFFSET = 1 << 24
# 排序键只接受“列名（可带 ASC/DESC）”形态：原版直接拼进 ORDER BY，非法形态必然导致语句错误
_SORT_COL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(?:\s+(?:ASC|DESC))?", re.IGNORECASE)
_SORT_DIR_RE = re.compile(r"[A-Za-z]{0,8}")


class BadSqlRequest(ValueError):
    """与原版“SQL 语句被 SQLite 拒绝”等价的请求错误（契约表现为 500 BAD_SQL_REQUEST）。"""


def _shared_of(caller: CallerContext, db_path: str) -> tuple[GatewayDB, DocumentIndex | None]:
    if caller.shared is not None and caller.db is not None:
        return caller.db, caller.shared.index
    return GatewayDB(db_path), None


def _empty(tenant_id: str) -> dict[str, Any]:
    return {"tenant_id": tenant_id, "total_matched": 0, "returned_count": 0, "items": []}


def search_documents(
    db_path: str,
    caller: CallerContext,
    *,
    query: str = "",
    category: str = "",
    tag_filter: str = "",
    deduplicate: bool = True,
    sort_by: str = "score",
    sort_dir: str = "desc",
    limit: int = DEFAULT_PAGE_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """执行合规文档检索：委托有效密级、三级隔离墙、词距邻近度加成与历史双轨法规号折叠。"""
    from .middleware import _prescan_depth

    if not isinstance(query, str) or not isinstance(category, str) or not isinstance(tag_filter, str):
        raise ValueError("q, category and tag_filter must be strings")
    if not isinstance(sort_by, str) or not isinstance(sort_dir, str):
        raise ValueError("sort_by and sort_dir must be strings")
    if len(query) > _MAX_QUERY_CHARS:
        raise ValueError("Request string too long")
    # 原版把 sort_by 直接拼进 ORDER BY：非法列名会被 SQLite 拒绝并回 500 BAD SQL，
    # 此处以“扫描后立即拒绝”的方式熔断，既不执行任何 SQL 也不泄露底层异常细节。
    if not _SORT_COL_RE.match(sort_by):
        raise BadSqlRequest(f"Unsupported sort ordering: {sort_by[:32]}")
    if not _SORT_DIR_RE.match(sort_dir):
        raise BadSqlRequest(f"Unsupported sort direction: {sort_dir[:16]}")
    limit = min(strict_int(limit, name="limit"), MAX_SEARCH_LIMIT)
    offset = strict_int(offset, name="offset")
    if abs(offset) > _MAX_OFFSET:
        offset = _MAX_OFFSET if offset > 0 else -_MAX_OFFSET
    deduplicate = strict_bool(deduplicate, default=True, name="deduplicate")

    # 防御性预扫描：超深嵌套/超长查询串在触碰索引与 SQL 之前就被拒绝
    _prescan_depth(query)
    _prescan_depth(tag_filter)

    db, retrieval = _shared_of(caller, db_path)
    if retrieval is None:
        return _search_fallback(
            db, caller, query=query, category=category, tag_filter=tag_filter,
            deduplicate=deduplicate, sort_by=sort_by, sort_dir=sort_dir,
            limit=limit, offset=offset,
        )
    tenant_id = caller.tenant_id
    view = retrieval.view(tenant_id)
    query_terms = list(dict.fromkeys(tokenize_text(query)))[:MAX_QUERY_TERMS]

    # 1) 候选集：与原版同一 SQL 的结果集（同过滤条件 + 同排序键），用内存倒排等价构造
    tag_docs = None
    if tag_filter:
        # 标签值与原版 `<标签>` 表名共用一张全局命名空间：命中本租户标签则按标签检索，
        # 否则等同“标签表不存在”的空结果集（原版 SQL 拼接被参数化后不再可能越权取数）。
        tag_docs = view.tags.get(tag_filter)
        if not tag_docs:
            return _empty(tenant_id)
    if query_terms:
        candidates = {}
        postings = view.postings
        title_postings = view.title_postings
        for term in query_terms:
            for bucket in (postings.get(term), title_postings.get(term)):
                if bucket:
                    for doc_id, node in bucket.items():
                        candidates[doc_id] = node
        if not candidates:
            return _empty(tenant_id)
        if tag_docs is not None:
            candidates = {d: n for d, n in candidates.items() if d in tag_docs}
    else:
        if tag_docs is not None:
            candidates = {d: view.nodes[d] for d in tag_docs if d in view.nodes}
        else:
            candidates = view.nodes

    # 2) 一次解析有效密级 + 组织血缘，逐候选 O(1) 判墙
    clearance = int(caller.max_clearance)
    blocked = caller.blocked
    pending: list[tuple[float, int, Any]] = []
    nodes_by_id = view.nodes
    citers = view.citers
    for node in candidates.values():
        if node.clearance > clearance:
            continue
        if category and node.category != category:
            continue
        if blocked(node.doc_id):
            continue
        term_score, prox_bonus = _score_node(node, query_terms)
        if term_score is None:
            continue
        doc_id = node.doc_id
        # 有效引用数 = 唯一引用源数（忽略自引用）：``ext_cites`` 为外部文号、``self_cites`` 为自引用、
        # ``citers[doc_id]`` 为处于 ACTIVE 且未隔离的本租户内部 doc_ 引用源（同一来源多条引用只记一次，
        # 与原版按引用源去重后再逐个核验有效性的口径一致）
        cite_cnt = node.ext_cites + node.self_cites + len(citers.get(doc_id, ()))
        total = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * node.risk_weight, 4)
        pending.append((total, cite_cnt, node))
    if not pending:
        return _empty(tenant_id)

    # 3) 原版一阶序（-score, -updated_at, doc_id），去重折叠严格沿用该顺序
    pending.sort(key=lambda t: (-t[0], -t[2].updated_at, t[2].doc_id))
    if deduplicate:
        folded = _fold_clusters(view, pending)
    else:
        # 无去重：候选即全部打分命中，保持 (score, updated_at, doc_id) 一阶序
        folded = [[total, cnt, node, 1] for total, cnt, node in pending]

    # 4) 输出排序与分页：原版最终阶段为 ``(字段, doc_id)`` 稳定排序（降序取负号、升序直接比较），
    #    其中 ``score`` 即 ``final_list`` 的一阶分数；自定义列按 ``score`` 处理。
    desc = str(sort_dir).lower() != "asc"
    if desc:
        if sort_by == "updated_at":
            folded.sort(key=_k_updated, reverse=True)
        elif sort_by == "risk_weight":
            folded.sort(key=_k_risk, reverse=True)
        else:
            folded.sort(key=_k_score, reverse=True)
    else:
        if sort_by == "updated_at":
            folded.sort(key=_k_updated)
        elif sort_by == "risk_weight":
            folded.sort(key=_k_risk)
        else:
            folded.sort(key=_k_score)
    return _page(db, view, tenant_id, folded, limit, offset)


def _page(db: GatewayDB, view: DocTenantView, tenant_id: str, folded, limit: int, offset: int) -> dict[str, Any]:
    total_matched = len(folded)
    if limit < 0:
        page = folded[max(0, offset):]
    else:
        page = folded[max(0, offset): max(0, offset) + limit]
    return _materialize(db, view, tenant_id=tenant_id, page=page, total_matched=total_matched)


def _k_rank(entry):
    return (-entry[0], -entry[2].updated_at, entry[2].doc_id)


def _k_score(entry):
    # 降序语义下的分数键：``sort(key=..., reverse=True)`` 会把元组整体反向（含 doc_id），与原版一致
    return (entry[0], entry[2].doc_id)


def _k_updated(entry):
    # 主键为 updated_at 时 SQL 不再有 ``score DESC`` 前置，直接按 (updated_at, doc_id) 排布
    return (entry[2].updated_at, entry[2].doc_id)


def _k_risk(entry):
    return (entry[2].risk_weight, entry[2].doc_id)


# ---------------------------------------------------------------------------
# 打分
# ---------------------------------------------------------------------------
def _score_node(node, query_terms: list[str]):
    """标题 ×3.5（次数上限 5）+ 正文 ×1（次数上限 12）词频得分，以及相邻词对最小跨度加分。"""
    if not query_terms:
        return 0.0, 0.0
    postings = node.postings
    title_uniq = node.title_uniq
    title_repeat = node.title_counts
    total = 0.0
    hits = False
    # 标题词单独成桶、正文倒排与它分列：命中判断必须同时看两边（短文档的标题词不落在正文倒排里）
    get_t = postings.get
    for term in query_terms:
        if term in title_uniq:
            hits = True
            c = get_t(term)
            t_cnt = title_repeat.get(term, 1) if title_repeat else 1
            total += 3.5 * (t_cnt if t_cnt < 5 else 5)
            if c is not None:
                total += 1.0 if c >= 12 else float(c)
        else:
            c = get_t(term)
            if c is not None:
                hits = True
                total += 1.0 if c >= 12 else float(c)
    if not hits:
        return None, None
    if len(query_terms) < 2:
        return total, 0.0
    return total, _proximity(_positions_of(node), query_terms)


def _positions_of(node) -> dict[str, list[int]]:
    """命中文档按需回源取正文做双指针词距（原始正文不常驻堆内存）。

    正文已被并发修改/退役时退化为 0 加分：原版取的是本次 SELECT 快照里的正文，
    单篇写入与检索之间不存在事务隔离保证，此退化不影响正常业务的一致性。
    """
    from .views import hot_views
    cache = hot_views()
    hit = cache.get(node.doc_id)
    if hit is not None:
        return hit
    from .db import DB
    row = DB.one(
        "SELECT body FROM compliance_docs WHERE doc_id = ? AND status = 'ACTIVE' AND quarantined = 0",
        (node.doc_id,),
    )
    positions = token_positions(row["body"]) if row is not None else {}
    cache.put(node.doc_id, positions)
    return positions


def _proximity(positions: dict[str, list[int]], query_terms: list[str]) -> float:
    bonus = 0.0
    for idx in range(len(query_terms) - 1):
        term_a = query_terms[idx]
        term_b = query_terms[idx + 1]
        if term_a == term_b:
            continue
        pos_a = positions.get(term_a)
        if not pos_a:
            continue
        pos_b = positions.get(term_b)
        if not pos_b:
            continue
        i = j = 0
        la = len(pos_a)
        lb = len(pos_b)
        min_dist = None
        while i < la and j < lb:
            a = pos_a[i]
            b = pos_b[j]
            d = a - b if a >= b else b - a
            if min_dist is None or d < min_dist:
                min_dist = d
                if d == 1:
                    break
            if a < b:
                i += 1
            else:
                j += 1
        if min_dist is not None and 1 <= min_dist <= PROXIMITY_MAX_SPAN:
            bonus += 2.4 / float(min_dist)
    return bonus


# ---------------------------------------------------------------------------
# 近似修订簇折叠
def _fold_clusters(view: DocTenantView, scored):
    """按 Jaccard >= 0.70 折叠修订簇：与原版逐项一致的贪心 ``remaining`` 列表折叠。

    等价性要点（原版行为并不对称，必须原样复刻）：

    * 代表按一阶序（-score, -updated_at, doc_id）依次产生，被吞并者只从**剩余**列表中移除；
    * 判定 ``same_reg`` 只看代表方（代表无规范法规号时永不归并）；
    * 代表与后续文档的距离用 **原始** 集合计算，归并不会把被吞并文档的词并入代表集合。
    """
    from .doc_indexer import jaccard_from_sets

    kept: list[list[Any]] = []
    remaining = list(scored)
    size = len(remaining)
    consumed = bytearray(size)
    uniqs = [entry[2].uniq for entry in remaining]
    canon = [entry[2].canon_reg for entry in remaining]
    for i in range(size):
        if consumed[i]:
            continue
        total, cnt, node = remaining[i]
        cluster_size = 1
        if node.canon_reg:
            base_uniq = uniqs[i]
            base_canon = canon[i]
            base_len = len(base_uniq)
            for j in range(i + 1, size):
                if consumed[j]:
                    continue
                if canon[j] != base_canon:
                    continue
                other = uniqs[j]
                other_len = len(other)
                # 集合规模比值 < 0.70 时 Jaccard 必然不足：O(1) 剪枝
                if base_len * 10 < 7 * other_len or other_len * 10 < 7 * base_len:
                    continue
                if jaccard_from_sets(base_uniq, other) >= DEDUP_JACCARD_THRESHOLD:
                    consumed[j] = 1
                    cluster_size += 1
        kept.append([total, cnt, node, cluster_size])
    return kept


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
def _materialize(db: GatewayDB, view: DocTenantView, *, tenant_id: str, page,
                 total_matched: int) -> dict[str, Any]:
    """只对本页命中文档一次批量回源取标题/正文摘要（原始大正文不常驻内存）。"""
    items: list[dict[str, Any]] = []
    if page:
        ids = [entry[2].doc_id for entry in page]
        bodies: dict[str, tuple[Any, Any, int, Any, Any, Any]] = {}
        step = 256
        for start in range(0, len(ids), step):
            chunk = ids[start:start + step]
            placeholders = ",".join("?" for _ in chunk)
            rows = db.rows(
                "SELECT doc_id, category, regulation_code, clearance_level, risk_weight, custom_tag, "
                "title, body, updated_at FROM compliance_docs WHERE doc_id IN (" + placeholders + ")",
                tuple(chunk),
            )
            for r in rows:
                bodies.setdefault(r["doc_id"], (
                    r["category"], r["regulation_code"], int(r["clearance_level"]),
                    int(r["risk_weight"]), r["custom_tag"], r["title"], r["body"], int(r["updated_at"]),
                ))
        nodes_by_id = view.nodes
        citers = view.citers
        for total, cnt, node, cluster in page:
            doc_id = node.doc_id
            row = bodies.get(doc_id)
            if row is not None:
                category, reg_code, clearance, risk_w, tag, title, body, updated_at = row
            else:
                category = node.category
                reg_code = node.raw_reg_code
                clearance = int(node.clearance)
                risk_w = int(node.risk_weight)
                tag = node.tag
                title = node.title
                body = None
                updated_at = node.updated_at
            live_cnt = 0
            for ref in citers.get(doc_id, ()):
                src_node = nodes_by_id.get(ref)
                if src_node is not None and src_node.live():
                    live_cnt += 1
            items.append({
                "doc_id": doc_id,
                "category": category,
                "regulation_code": reg_code,
                "_canon_reg": node.canon_reg,
                "clearance_level": clearance,
                "risk_weight": risk_w,
                "custom_tag": tag,
                "title": title,
                "snippet": ("" if body is None else body[:_SNIPPET_CHARS]),
                "citation_count": live_cnt + node.self_cites + node.ext_cites,
                "score": total,
                "updated_at": updated_at,
                "cluster_size": cluster,
            })
    items_out = [{k: v for k, v in doc.items() if not k.startswith("_")} for doc in items]
    return {
        "tenant_id": tenant_id,
        "total_matched": total_matched,
        "returned_count": len(items_out),
        "items": items_out,
    }


# ---------------------------------------------------------------------------
# 批量取文档 / 隔离翻转
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 批量取文档 / 隔离翻转
# ---------------------------------------------------------------------------
_MAX_BATCH_DOCS = 200


def batch_get_documents(db_path: str, caller: CallerContext, doc_ids: list[str]) -> dict[str, Any]:
    """按 ID 列表批量获取完整文档（与原版同语义同结构：跨库直取、按请求顺序、仅 ACTIVE）。"""
    from .doc_batch import batch_get_documents as _batch_get

    return _batch_get(db_path, caller, doc_ids)


def set_document_quarantine(
    db_path: str,
    caller: CallerContext,
    *,
    doc_id: str,
    quarantined: bool = True,
) -> dict[str, Any]:
    """隔离/解除隔离单篇合规文档：数据库、内存索引与引用计数在一次写事务内联动翻转。"""
    from .db import DocumentIndex

    guard_text(doc_id, name="doc_id", max_chars=MAX_ID_CHARS)
    if not doc_id:
        raise ValueError("doc_id is required")
    if "COMPLIANCE_ADMIN" not in caller.effective_roles and "SENIOR_AUDITOR" not in caller.effective_roles:
        raise PermissionError("COMPLIANCE_ADMIN or SENIOR_AUDITOR role required")

    shared = caller.shared if caller.db is not None else None
    db = caller.db if caller.db is not None else GatewayDB(db_path)
    own = caller.db is None
    now_ts = int(caller.request_ts)
    flag = 1 if quarantined else 0
    try:
        def _tx(conn):
            row = conn.execute(
                "SELECT status, quarantined, clearance_level, category, custom_tag FROM compliance_docs "
                "WHERE tenant_id = ? AND doc_id = ?",
                (caller.tenant_id, doc_id),
            ).fetchone()
            if row is None:
                raise LookupError(f"Document not found: {doc_id}")
            prev = int(row["quarantined"])
            conn.execute(
                "UPDATE compliance_docs SET quarantined = ?, updated_at = ? WHERE tenant_id = ? AND doc_id = ?",
                (flag, now_ts, caller.tenant_id, doc_id),
            )
            if prev != flag:
                conn.execute(
                    "INSERT INTO audit_logs(tenant_id, actor_id, event_type, severity, amount_cents, "
                    "masked_account, ts, payload_json) VALUES (?, ?, 'DOC_QUARANTINE', 'HIGH', 0, '****0000', ?, ?)",
                    (caller.tenant_id, caller.user_id, now_ts,
                     json.dumps({"doc_id": doc_id, "quarantined": bool(flag)})),
                )
            return {
                "doc_id": doc_id,
                "status": row["status"],
                "previous_quarantined": prev,
                "quarantined": bool(flag),
                "updated_at": now_ts,
                "changed": prev != flag,
            }

        res = db.write(_tx)
        if shared is not None and res["changed"]:
            index: DocumentIndex = shared.index
            index.change_status(caller.tenant_id, doc_id, quarantined=bool(flag))
            shared.epoch.touch("doc")
        return {"tenant_id": caller.tenant_id, **res}
    finally:
        if own:
            db.close_thread()


def _raw_reg_code_of(node) -> str:
    """输出的是库内原始法规编号；归一化值只用于同法规判定。"""
    if node.raw_reg_code is not None:
        return node.raw_reg_code
    return canonicalize_regulation_code(node.reg_code)


def _search_fallback(db: GatewayDB, caller: CallerContext, *, query: str, category: str,
                     tag_filter: str, deduplicate: bool, sort_by: str, sort_dir: str,
                     limit: int, offset: int) -> dict[str, Any]:
    """兜底路径（仅当调用方未通过网关上下文构造 CallerContext 时使用）。

    与原版逐行等价的参考实现：整表条件查询 + 两两 Jaccard 折叠 + 后置排序。
    """
    from .doc_indexer import jaccard_from_sets

    clauses = ["tenant_id = ?", "status = 'ACTIVE'", "quarantined = 0"]
    params: list[Any] = [caller.tenant_id]
    if category:
        clauses.append("category = ?")
        params.append(category)
    if tag_filter:
        clauses.append("custom_tag = ?")
        params.append(tag_filter)
    sql = (
        "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, risk_weight, "
        "custom_tag, title, body, updated_at FROM compliance_docs WHERE " + " AND ".join(clauses)
    )
    rows = db.rows(sql, tuple(params))
    clearance = int(caller.max_clearance)
    query_terms = list(dict.fromkeys(tokenize_text(query)))[:MAX_QUERY_TERMS]
    blocked = caller.blocked
    scored = []
    for r in rows:
        if int(r["clearance_level"]) > clearance:
            continue
        if blocked(r["doc_id"]):
            continue
        prof = TokenProfile.build(r["title"] or "", r["body"] or "")
        node = _RowNode(r, prof)
        term_score, prox_bonus = _score_node(node, query_terms)
        if term_score is None:
            continue
        cnt = db.one(
            "SELECT COUNT(DISTINCT cited_by_ref) AS c FROM doc_citations "
            "WHERE tenant_id = ? AND doc_id = ? AND cited_by_ref <> ? AND cited_by_ref <> ''",
            (caller.tenant_id, r["doc_id"], r["doc_id"]),
        )
        cite_cnt = int(cnt["c"]) if cnt else 0
        total = round(term_score + prox_bonus + 0.25 * cite_cnt + 0.1 * node.risk_weight, 4)
        scored.append((total, cite_cnt, node))
    scored.sort(key=lambda t: (-t[0], -t[2].updated_at, t[2].doc_id))
    if deduplicate:
        folded: list[tuple[float, int, Any, int]] = []
        consumed = [False] * len(scored)
        for i in range(len(scored)):
            if consumed[i]:
                continue
            rep = scored[i]
            cluster_size = 1
            for j in range(i + 1, len(scored)):
                if consumed[j]:
                    continue
                other = scored[j][2]
                same_reg = bool(rep[2].canon_reg) and rep[2].canon_reg == other.canon_reg
                if same_reg and jaccard_from_sets(rep[2].uniq, other.uniq) >= DEDUP_JACCARD_THRESHOLD:
                    consumed[j] = True
                    cluster_size += 1
            folded.append((rep[0], rep[1], rep[2], cluster_size))
    else:
        folded = [(t, c, n, 1) for t, c, n in scored]
    reverse_flag = str(sort_dir).lower() != "asc"
    sort_field = sort_by if sort_by in ("score", "updated_at", "risk_weight") else "score"
    if reverse_flag:
        if sort_field == "updated_at":
            folded.sort(key=lambda d: (-d[2].updated_at, d[2].doc_id))
        elif sort_field == "risk_weight":
            folded.sort(key=lambda d: (-d[2].risk_weight, d[2].doc_id))
        else:
            folded.sort(key=lambda d: (-d[0], d[2].doc_id))
    total_matched = len(folded)
    page = folded[max(0, offset):] if limit < 0 else folded[max(0, offset): max(0, offset) + limit]
    items = [{
        "doc_id": n.doc_id,
        "category": n.category,
        "regulation_code": n.raw_reg_code,
        "_canon_reg": n.canon_reg,
        "clearance_level": int(n.clearance),
        "risk_weight": int(n.risk_weight),
        "custom_tag": n.tag,
        "title": n.title,
        "snippet": "" if n.body is None else n.body[:_SNIPPET_CHARS],
        "citation_count": c,
        "score": t,
        "updated_at": n.updated_at,
        "cluster_size": cl,
    } for t, c, n, cl in page]
    items_out = [{k: v for k, v in doc.items() if not k.startswith("_")} for doc in items]
    return {"tenant_id": caller.tenant_id, "total_matched": total_matched,
            "returned_count": len(items_out), "items": items_out}


class _RowNode:
    """兜底路径使用的行级临时节点（字段与 DocNode 对齐）。"""

    __slots__ = ("doc_id", "clearance", "risk_weight", "category", "tag", "raw_reg_code", "canon_reg",
                 "title", "body", "updated_at", "postings", "title_counts", "uniq", "title_uniq",
                 "n_uniq", "max_cap", "lower_cap")

    def __init__(self, row, prof: TokenProfile) -> None:
        self.doc_id = row["doc_id"]
        self.clearance = int(row["clearance_level"])
        self.risk_weight = int(row["risk_weight"])
        self.category = row["category"]
        self.tag = row["custom_tag"]
        self.raw_reg_code = row["regulation_code"]
        self.canon_reg = canonicalize_regulation_code(row["regulation_code"])
        self.title = row["title"]
        self.body = row["body"]
        self.updated_at = int(row["updated_at"])
        self.postings = {t: (c if c < 12 else 12) for t, c in prof.body_tf.items()}
        self.title_counts = {t: c for t, c in prof.title_tf.items() if c > 1}
        self.title_uniq = set(prof.title_tf)
        self.uniq = frozenset(set(prof.body_tf) | self.title_uniq)
        self.n_uniq = len(prof.title_tf) + len(prof.body_tf)
        self.max_cap = self.n_uniq
        self.lower_cap = self.n_uniq




