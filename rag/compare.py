"""Compare retrieval modes on the same probes (Milestone 8). No LLM calls, no API limits.

    python rag/compare.py

Runs dense (= the Milestone 7 baseline), bm25, hybrid and hybrid_ids over:
  cve / technique   auto-generated identifier probes (as in Milestone 7)
  curated           the 3 Milestone 7 questions (config/rag_eval_questions.json)
  titles            plain-language "which advisory covers ..." questions
                    (config/hybrid_eval_questions.json) - a guard that adding keyword
                    search does not damage ordinary semantic questions

Honesty note: the identifier probes are generated from the same structured fields
(cve_ids / technique_ids) that the hybrid_ids tier looks up. Compare `hybrid` with
`hybrid_ids` to see how much of a gain comes from that lookup, and judge `bm25` and
`hybrid` as the cleaner text-only evidence.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag import DEFAULT_CHUNKS, DEFAULT_INDEX_DIR  # noqa: E402
from rag.evaluate import evaluate, load_curated, make_identifier_probes  # noqa: E402
from rag.hybrid import MODES, HybridRetriever  # noqa: E402


def load_titles(path: str) -> list[dict]:
    probes = load_curated(path)
    for p in probes:
        p["kind"] = "titles"
    return probes


def baseline_check(dense_result: dict, reports_dir: str) -> str:
    """Does our dense row reproduce the Milestone 7 report? Returns a one-line verdict."""
    files = sorted(glob.glob(os.path.join(reports_dir, "rag_eval_*.json")))
    if not files:
        return "[info] no Milestone 7 report found to compare the dense row with"
    with open(files[-1], encoding="utf-8") as fh:
        old = json.load(fh)
    diffs = []
    for kind in ("cve", "technique", "curated"):
        a, b = old["kinds"].get(kind), dense_result["kinds"].get(kind)
        if a and b and (a["doc_hit@k"] != b["doc_hit@k"] or a.get("needle_hit@k") != b.get("needle_hit@k")):
            diffs.append(kind)
    if not diffs:
        return f"[PASS] dense mode reproduces the Milestone 7 baseline ({os.path.basename(files[-1])})"
    return (f"[WARN] dense mode differs from the Milestone 7 report for: {', '.join(diffs)} "
            "(small differences are possible: M8 made tie-breaking deterministic)")


def print_tables(results: dict):
    modes = list(results)
    ks = results[modes[0]]["k_values"]
    kinds = list(results[modes[0]]["kinds"])
    head = "".join(f"{'@' + str(k):>6}" for k in ks)
    for kind in kinds:
        n = results[modes[0]]["kinds"][kind]["n"]
        has_needle = "needle_hit@k" in results[modes[0]]["kinds"][kind]
        print(f"\n== {kind} (n={n}) ==")
        print(f"{'mode':<12}{'doc-hit':<9}{head}{'   MRR':>7}" + (f"   | needle-hit{head}" if has_needle else ""))
        for m in modes:
            e = results[m]["kinds"][kind]
            d = "".join(f"{e['doc_hit@k'][str(k)]:>6}" for k in ks)
            line = f"{m:<12}{'':<9}{d}{e['doc_mrr']:>7}"
            if has_needle:
                line += "   |            " + "".join(f"{e['needle_hit@k'][str(k)]:>6}" for k in ks)
            print(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks", default=DEFAULT_CHUNKS)
    ap.add_argument("--index", default=DEFAULT_INDEX_DIR)
    ap.add_argument("--curated", default=os.path.join("config", "rag_eval_questions.json"))
    ap.add_argument("--titles", default=os.path.join("config", "hybrid_eval_questions.json"))
    ap.add_argument("--modes", default="dense,bm25,hybrid:1,hybrid:3,hybrid_ids:3",
                    help="comma list of mode or mode:id_weight, e.g. hybrid:1,hybrid:3,hybrid:5")
    ap.add_argument("--max-each", type=int, default=40)
    ap.add_argument("--report-dir", default=os.path.join("outputs", "reports"))
    a = ap.parse_args()
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]
    for m in modes:
        if m.split(":")[0] not in MODES:
            sys.exit(f"unknown mode {m!r}; choose from {MODES} (optionally mode:id_weight)")

    from rag.index import VectorIndex, load_chunks
    chunks = load_chunks(a.chunks)
    index = VectorIndex.load(a.index)
    embedder = None
    if any(m.split(":")[0] != "bm25" for m in modes):
        from rag.embedder import SentenceTransformerEmbedder
        embedder = SentenceTransformerEmbedder(index.manifest["model"])
    probes = (make_identifier_probes(chunks, a.max_each) + load_curated(a.curated) + load_titles(a.titles))
    results = {}
    for m in modes:
        name, _, w = m.partition(":")
        kw = {"id_weight": float(w)} if w else {}
        results[m] = evaluate(HybridRetriever(index, chunks, embedder, mode=name, **kw), probes)
        print(f"evaluated mode {m}", flush=True)
    print_tables(results)
    verdict = baseline_check(results["dense"], a.report_dir) if "dense" in results else ""
    if verdict:
        print("\n" + verdict)
    os.makedirs(a.report_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(a.report_dir, f"hybrid_eval_{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"modes": results, "probes": len(probes), "chunks": len(chunks),
                   "model": index.manifest["model"], "baseline_check": verdict,
                   "generated_at": datetime.now(timezone.utc).isoformat()}, fh, indent=1, ensure_ascii=False)
    print("\nreport:", path)


if __name__ == "__main__":
    main()
