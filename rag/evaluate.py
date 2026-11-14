"""Retrieval evaluation (no LLM calls, so no API limits).

Probes:
  cve        "Which advisory discusses CVE-...?"            (auto, from the chunk file)
  technique  "Which advisory describes ATT&CK technique T...?" (auto)
  curated    hand-written questions in config/rag_eval_questions.json
Doc-level hit: a retrieved chunk comes from an advisory that really contains the answer.
Needle hit (id probes only): the retrieved chunk itself contains the identifier. Semantic
search is expected to be weaker here - that gap is the baseline Milestone 8 (hybrid) must beat.

    python rag/evaluate.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag import DEFAULT_CHUNKS, DEFAULT_INDEX_DIR  # noqa: E402


def sample_evenly(items: list, n: int) -> list:
    if len(items) <= n:
        return list(items)
    return [items[int(i * len(items) / n)] for i in range(n)]


def make_identifier_probes(chunks: list[dict], max_each: int = 40) -> list[dict]:
    cve_docs: dict[str, set] = {}
    tech_docs: dict[str, set] = {}
    for c in chunks:
        for x in c.get("cve_ids", []):
            cve_docs.setdefault(x, set()).add(c["doc_id"])
        for x in c.get("technique_ids", []):
            tech_docs.setdefault(x, set()).add(c["doc_id"])
    probes = []
    for cve in sample_evenly(sorted(cve_docs), max_each):
        probes.append({"kind": "cve", "question": f"Which advisory discusses {cve}?",
                       "gold_docs": sorted(cve_docs[cve]), "needle": cve})
    for t in sample_evenly(sorted(tech_docs), max_each):
        probes.append({"kind": "technique",
                       "question": f"Which advisory describes ATT&CK technique {t}?",
                       "gold_docs": sorted(tech_docs[t]), "needle": t})
    return probes


def load_curated(path: str) -> list[dict]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        qs = json.load(fh).get("questions", [])
    return [{"kind": "curated", "question": q["question"], "gold_docs": q["gold_docs"],
             "needle": None} for q in qs]


def _needle_in(chunk: dict, kind: str, needle: str) -> bool:
    return needle in chunk.get("cve_ids" if kind == "cve" else "technique_ids", [])


def evaluate(retriever, probes: list[dict], ks=(1, 3, 5, 10)) -> dict:
    kmax = max(ks)
    rows: dict[str, list] = {}
    for p in probes:
        hits = retriever.retrieve(p["question"], kmax)
        gold = set(p["gold_docs"])
        doc_rank = next((h.rank for h in hits if h.chunk["doc_id"] in gold), None)
        needle_rank = None
        if p.get("needle"):
            needle_rank = next((h.rank for h in hits if _needle_in(h.chunk, p["kind"], p["needle"])), None)
        rows.setdefault(p["kind"], []).append({"p": p, "doc_rank": doc_rank, "needle_rank": needle_rank,
                                               "top": [h.chunk_id for h in hits[:3]]})
    out = {"k_values": list(ks), "kinds": {}, "misses": {}}
    for kind, rs in rows.items():
        n = len(rs)

        def rate(key, k):
            return round(sum(1 for r in rs if r[key] is not None and r[key] <= k) / n, 3)
        entry = {"n": n,
                 "doc_hit@k": {str(k): rate("doc_rank", k) for k in ks},
                 "doc_mrr": round(sum(1 / r["doc_rank"] for r in rs if r["doc_rank"]) / n, 3)}
        has_needle = any(r["p"].get("needle") for r in rs)      # only identifier probes have one
        if has_needle:
            entry["needle_hit@k"] = {str(k): rate("needle_rank", k) for k in ks}
        out["kinds"][kind] = entry
        out["misses"][kind] = [{"question": r["p"]["question"], "gold_docs": r["p"]["gold_docs"][:3],
                                "top3": r["top"]} for r in rs
                               if (r["needle_rank"] if has_needle else r["doc_rank"]) is None][:8]
    return out


def print_report(res: dict):
    ks = res["k_values"]
    head = "  ".join(f"@{k:<4}" for k in ks)
    print(f"\n{'probe':<10} {'n':>3}   doc-hit {head}   MRR   | needle-hit {head}")
    for kind, e in res["kinds"].items():
        d = "  ".join(f"{e['doc_hit@k'][str(k)]:<5}" for k in ks)
        nd = "  ".join(f"{e['needle_hit@k'][str(k)]:<5}" for k in ks) if "needle_hit@k" in e else "-"
        print(f"{kind:<10} {e['n']:>3}   {'':8}{d}   {e['doc_mrr']:<5} | {'':11}{nd}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks", default=DEFAULT_CHUNKS)
    ap.add_argument("--index", default=DEFAULT_INDEX_DIR)
    ap.add_argument("--curated", default=os.path.join("config", "rag_eval_questions.json"))
    ap.add_argument("--max-each", type=int, default=40)
    ap.add_argument("--report-dir", default=os.path.join("outputs", "reports"))
    a = ap.parse_args()
    from rag.embedder import SentenceTransformerEmbedder
    from rag.index import VectorIndex, load_chunks
    from rag.retrieve import Retriever
    chunks = load_chunks(a.chunks)
    index = VectorIndex.load(a.index)
    retriever = Retriever(index, chunks, SentenceTransformerEmbedder(index.manifest["model"]))
    probes = make_identifier_probes(chunks, a.max_each) + load_curated(a.curated)
    res = evaluate(retriever, probes)
    res.update(model=index.manifest["model"], chunks=len(chunks), probes=len(probes),
               generated_at=datetime.now(timezone.utc).isoformat())
    print_report(res)
    os.makedirs(a.report_dir, exist_ok=True)
    path = os.path.join(a.report_dir, f"rag_eval_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, ensure_ascii=False)
    print("\nreport:", path)


if __name__ == "__main__":
    main()
