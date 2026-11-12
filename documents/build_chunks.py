"""Convert the raw advisory HTML files into stable, traceable chunks.

Run from the project root:
    python documents\\build_chunks.py
Reads data/processed/*advis*normalized*.json (metadata) and the raw HTML it points
to; writes data/processed/advisory_chunks.jsonl + advisory_chunks_manifest.json.
Raw and processed source files are only read, never modified.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canonical.build import pick                               # noqa: E402
from canonical.ids import slug                                 # noqa: E402
from canonical.mappings import ALIASES                         # noqa: E402
from documents import CHUNK_SCHEMA_VERSION                    # noqa: E402
from documents.chunking import (CVE_RE, TECH_RE, chunk_blocks,  # noqa: E402
                                embedding_text)

TITLE_KEYS = ("title", "name", "document_title")
URL_KEYS = ("source_url", "url")
DATE_KEYS = ("published_at", "published", "published_date", "date_published")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def txt(v):
    if v is None or v == "":
        return None
    return v if isinstance(v, str) else str(v)


def make_doc_id(value, used: set) -> str:
    """Readable stable id: advisory_<last url segment or id>; collisions get a hash."""
    s = str(value).strip()
    if re.match(r"^https?://", s, re.I):
        u = urlparse(s)
        s = u.path.rstrip("/").rsplit("/", 1)[-1] or u.netloc
    key = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "doc"
    did = f"advisory_{key}"
    if did in used:
        did = f"{did}-{hashlib.sha1(str(value).encode()).hexdigest()[:6]}"
    used.add(did)
    return did


def resolve_raw(ref, raw_dir: str):
    """Find the raw HTML file a processed record points at."""
    if not ref:
        return None
    ref = str(ref)
    for cand in (ref, os.path.join(raw_dir, os.path.basename(ref.replace("\\", "/")))):
        if os.path.isfile(cand):
            return cand
    base = os.path.basename(ref.replace("\\", "/"))
    for root, _, files in os.walk(raw_dir):
        if base in files:
            return os.path.join(root, base)
    return None


def load_records(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("records", []) if isinstance(data, dict) else data


def build_chunks(processed_dir, raw_dir, out_path, parser, max_words=250,
                 min_words=8, limit=None) -> dict:
    found = sorted(glob.glob(os.path.join(processed_dir, "*advis*normalized*.json")))
    if not found:
        return {"status": "FAILED", "error": "no processed advisories file "
                f"(*advis*normalized*.json) in {processed_dir}"}
    adv_path = found[0]
    records = load_records(adv_path)

    docs = []                                    # same id logic as canonical/build.py
    for i, r in enumerate(records):
        raw_id = str(pick(r, ALIASES["doc_id"], f"advisory-{i:04d}"))
        docs.append({"rec": r, "raw_id": raw_id,
                     "report_id": "IntelligenceReport:" + (slug(raw_id) or f"doc{i}")})
    docs.sort(key=lambda d: d["report_id"])
    if limit:
        docs = docs[:limit]

    used: set = set()
    rows, per_doc, failed = [], [], []
    skipped_labels: Counter = Counter()
    stats = Counter()
    for d in docs:
        r = d["rec"]
        doc_id = make_doc_id(d["raw_id"], used)
        ref = r.get("raw_file_reference")
        raw_path = resolve_raw(ref, raw_dir)
        if not raw_path:
            failed.append({"doc_id": doc_id, "reason": "raw_file_not_found", "ref": txt(ref)})
            continue
        try:
            blocks = parser.parse(raw_path)
            chunks, st = chunk_blocks(blocks, max_words=max_words, min_words=min_words)
        except Exception as ex:                  # one bad page must not stop the run
            failed.append({"doc_id": doc_id, "reason": "parse_error",
                           "detail": f"{type(ex).__name__}: {str(ex)[:200]}"})
            continue
        skipped_labels.update(getattr(parser, "last_skipped", {}) or {})
        for k, v in st.items():
            stats[k] += v
        if not chunks:
            failed.append({"doc_id": doc_id, "reason": "no_chunks_produced"})
            continue
        raw_sha = sha256_file(raw_path)
        meta = {"title": txt(pick(r, TITLE_KEYS)), "source_url": txt(pick(r, URL_KEYS)),
                "published_at": txt(pick(r, DATE_KEYS)), "retrieved_at": txt(r.get("retrieved_at"))}
        for c in chunks:
            rows.append({
                "chunk_id": f"{doc_id}_chunk_{c.index:03d}",
                "doc_id": doc_id, "report_id": d["report_id"], "chunk_index": c.index,
                "heading_path": c.heading_path, "text": c.text,
                "embedding_text": embedding_text(c.heading_path, c.text),
                "word_count": c.words, "token_estimate": int(c.words * 1.3),
                "page_start": c.page_start, "page_end": c.page_end, "kinds": c.kinds,
                "cve_ids": sorted({m.upper() for m in CVE_RE.findall(c.text)}),
                "technique_ids": sorted(set(TECH_RE.findall(c.text))),
                **meta,
                "raw_file_reference": txt(ref), "raw_sha256": raw_sha,
                "parser": getattr(parser, "name", "unknown"),
                "parser_version": getattr(parser, "version", None),
                "content_sha256": hashlib.sha256(c.text.encode("utf-8")).hexdigest(),
            })
        per_doc.append({"doc_id": doc_id, "chunks": len(chunks), "raw_sha256": raw_sha})

    rows.sort(key=lambda x: (x["doc_id"], x["chunk_index"]))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    wc = [r["word_count"] for r in rows] or [0]
    manifest = {
        "schema_version": CHUNK_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "SUCCESS" if not failed else "PARTIAL",
        "parser": getattr(parser, "name", "unknown"),
        "parser_version": getattr(parser, "version", None),
        "params": {"max_words": max_words, "min_words": min_words},
        "input": {"processed_file": os.path.basename(adv_path),
                  "sha256": sha256_file(adv_path), "records": len(records)},
        "documents_chunked": len(per_doc), "documents_failed": len(failed),
        "chunks": len(rows),
        "words_per_chunk": {"min": min(wc), "median": statistics.median(wc), "max": max(wc)},
        "stats": dict(stats), "skipped_item_labels": dict(skipped_labels),
        "failed_documents": failed, "per_document": per_doc,
    }
    mpath = os.path.join(os.path.dirname(out_path) or ".", "advisory_chunks_manifest.json")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed-dir", default=os.path.join("data", "processed"))
    ap.add_argument("--raw-dir", default=os.path.join("data", "raw", "advisories"))
    ap.add_argument("--out", default=os.path.join("data", "processed", "advisory_chunks.jsonl"))
    ap.add_argument("--max-words", type=int, default=250)
    ap.add_argument("--min-words", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None, help="only the first N documents (testing)")
    a = ap.parse_args()
    from documents.parse import DoclingParser
    print("Loading Docling (first start can take a minute) ...")
    m = build_chunks(a.processed_dir, a.raw_dir, a.out, DoclingParser(),
                     a.max_words, a.min_words, a.limit)
    print("=== Milestone 6: advisory chunking ===")
    brief = {k: v for k, v in m.items() if k != "per_document"}
    print(json.dumps(brief, indent=2, ensure_ascii=False))
    sys.exit(0 if m.get("status") == "SUCCESS" else 1)


if __name__ == "__main__":
    main()
