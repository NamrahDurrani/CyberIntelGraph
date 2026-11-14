"""Why does keyword search miss some identifier questions?  (Milestone 8.1; no model, no API)

    python scripts/diagnose_bm25_misses.py

For every CVE / technique probe whose answer chunk is NOT in the BM25 top-10, sorts the miss into:
  A  the id is in the structured field but NOT written in the chunk text   -> data/chunking issue
  B  the id is written in the text but the tokenizer did not index it      -> tokenizer issue
  C  the id is indexed but other chunks out-scored it                      -> ranking issue
and prints the raw characters around the id so odd symbols become visible.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np                                                    # noqa: E402

from rag import DEFAULT_CHUNKS                                         # noqa: E402
from rag.bm25 import BM25Index, normalise_text                         # noqa: E402
from rag.evaluate import make_identifier_probes                        # noqa: E402
from rag.index import load_chunks                                      # noqa: E402


def main():
    chunks = load_chunks(DEFAULT_CHUNKS)
    texts = [c.get("embedding_text") or c.get("text", "") for c in chunks]
    bm = BM25Index(texts)
    probes = make_identifier_probes(chunks, 40)
    field = {"cve": "cve_ids", "technique": "technique_ids"}
    cats, rows, totals = Counter(), [], Counter()
    for p in probes:
        kind, needle = p["kind"], p["needle"]
        totals[kind] += 1
        top = [r for r, _ in bm.search(p["question"], 10)]
        have = [i for i, c in enumerate(chunks) if needle in c.get(field[kind], [])]
        if any(i in have for i in top):
            continue
        n_low = normalise_text(needle)
        literal = [i for i in have if n_low in normalise_text(texts[i])]
        token = needle.lower()
        indexed = token in bm.postings
        if not literal:
            cat = "A: id in field but not in chunk text"
        elif not indexed:
            cat = "B: id in text but not indexed by tokenizer"
        else:
            cat = "C: indexed but out-ranked"
        cats[(kind, cat)] += 1
        s = bm.scores(p["question"])
        order = np.lexsort((np.arange(len(s)), -s))
        rank_of = {int(r): k for k, r in enumerate(order, start=1)}
        best = min(rank_of[i] for i in have)
        snippet = ""
        src = literal[0] if literal else have[0]
        pos = normalise_text(texts[src]).find(n_low)
        if pos >= 0:
            snippet = repr(texts[src][max(0, pos - 25): pos + len(needle) + 25])
        rows.append({"kind": kind, "needle": needle, "category": cat, "chunks_with_id": len(have),
                     "best_bm25_rank": best, "postings_df": len(bm.postings.get(token, [])), "snippet": snippet})
    print(f"probes: {dict(totals)}   misses in BM25 top-10: {len(rows)}")
    for (kind, cat), n in sorted(cats.items()):
        print(f"  {kind:<10} {cat:<46} {n}")
    for r in rows[:12]:
        print(f"\n  {r['kind']} {r['needle']}  [{r['category'][0]}] chunks_with_id={r['chunks_with_id']} "
              f"best_rank={r['best_bm25_rank']} df={r['postings_df']}\n    {r['snippet']}")
    os.makedirs(os.path.join("outputs", "reports"), exist_ok=True)
    path = os.path.join("outputs", "reports", f"bm25_miss_diagnosis_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"totals": totals, "misses": rows}, fh, indent=1, ensure_ascii=False)
    print("\nreport:", path)


if __name__ == "__main__":
    main()
