import sqlite3

from .config import MAX_CITATIONS, MAX_ID_CHARS, MAX_TEXT_BODY_CHARS


def batch_get_documents(
    db_path: str,
    caller,
    doc_ids,
) -> dict:
    """兼容入口：按 ID 列表批量获取合规文档（保留原版的“跨库直取、按请求顺序、仅 ACTIVE”语义）。"""
    if not isinstance(doc_ids, list) or not doc_ids:
        raise ValueError("doc_ids must be a non-empty list")
    if len(doc_ids) > MAX_CITATIONS:
        raise ValueError(f"doc_ids exceeds limit of {MAX_CITATIONS}")
    ids: list[str] = []
    for raw in doc_ids:
        if not isinstance(raw, str):
            raise ValueError("doc_ids must be a list of document ids")
        if len(raw) > MAX_ID_CHARS:
            raise ValueError("doc_id too long")
        ids.append(raw)

    from .db import DB, GatewayDB

    db = caller.db if caller is not None and getattr(caller, "db", None) is not None else DB
    if not isinstance(db, GatewayDB) or db.path != db_path:
        db = GatewayDB(db_path)
        own = True
    else:
        own = False
    try:
        by_id = {}
        step = 256
        for start in range(0, len(ids), step):
            chunk = ids[start:start + step]
            placeholders = ",".join("?" for _ in chunk)
            cur = db.cursor(
                "SELECT doc_id, tenant_id, category, regulation_code, clearance_level, "
                "risk_weight, custom_tag, title, body, status, quarantined, updated_at "
                f"FROM compliance_docs WHERE doc_id IN ({placeholders})",
                chunk,
            )
            for r in cur.fetchall():
                by_id.setdefault(r["doc_id"], r)
            cur.close()
    finally:
        if own:
            db.close_thread()

    items = []
    for did in ids:
        r = by_id.get(did)
        if not r or r["status"] != "ACTIVE":
            continue
        items.append(
            {
                "doc_id": r["doc_id"],
                "tenant_id": r["tenant_id"],
                "category": r["category"],
                "regulation_code": r["regulation_code"],
                "clearance_level": int(r["clearance_level"]),
                "risk_weight": int(r["risk_weight"]),
                "custom_tag": r["custom_tag"],
                "title": r["title"],
                "body": r["body"],
                "updated_at": int(r["updated_at"]),
            }
        )
    return {"requested": len(ids), "found": len(items), "items": items}


_ = (sqlite3, MAX_TEXT_BODY_CHARS)
