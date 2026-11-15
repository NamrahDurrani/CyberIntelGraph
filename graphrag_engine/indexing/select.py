"""Choose the small advisory subset that GraphRAG will read (cost control)."""
from __future__ import annotations

import json
import re

from canonical.ids import CVE_RE, TECH_RE


def load_chunks_by_doc(path: str) -> dict[str, list[dict]]:
    by_doc: dict[str, list[dict]] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                c = json.loads(line)
                by_doc.setdefault(c["doc_id"], []).append(c)
    for rows in by_doc.values():
        rows.sort(key=lambda c: c["chunk_index"])
    return by_doc


def doc_stats(by_doc: dict[str, list[dict]]) -> list[dict]:
    out = []
    for doc_id, rows in by_doc.items():
        ids = set()
        for c in rows:
            ids.update(x.upper() for x in c.get("cve_ids") or [])
            ids.update(x.upper() for x in c.get("technique_ids") or [])
            if not c.get("cve_ids") and not c.get("technique_ids"):
                ids.update(m.upper() for m in CVE_RE.findall(c.get("text", "")))
                ids.update(TECH_RE.findall(c.get("text", "")))
        words = sum(len((c.get("text") or "").split()) for c in rows)
        out.append({"doc_id": doc_id, "title": rows[0].get("title", ""), "chunks": len(rows),
                    "words": words, "distinct_ids": len(ids),
                    "id_density": round(len(ids) / len(rows), 3)})
    return sorted(out, key=lambda d: d["doc_id"])


def select_docs(by_doc: dict[str, list[dict]], n: int = 5, explicit: list[str] | None = None,
                min_chunks: int = 5, max_chunks: int = 80) -> list[dict]:
    """Explicit names are matched as case-insensitive substrings of doc_id (e.g. 'aa20-302a').
    Otherwise take the n advisories with the most distinct CVE/technique ids per chunk,
    among those of manageable size - dense, readable reports that cost few calls."""
    stats = {d["doc_id"]: d for d in doc_stats(by_doc)}
    if explicit:
        chosen = []
        for want in explicit:
            hits = sorted(d for d in stats if want.strip().lower() in d.lower())
            if not hits:
                raise ValueError(f"no advisory matches {want!r}")
            if len(hits) > 1 and want.strip().lower() not in {h.lower() for h in hits}:
                raise ValueError(f"{want!r} is ambiguous: {hits[:4]}")
            chosen.append(stats[hits[0]])
        return chosen
    pool = [d for d in stats.values() if min_chunks <= d["chunks"] <= max_chunks]
    pool.sort(key=lambda d: (-d["id_density"], d["doc_id"]))
    return pool[:n]
