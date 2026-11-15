"""Milestone 9 indexer: advisories -> entities/relationships -> communities -> community reports.

    python graphrag_engine/indexing/run_index.py --dry-run          # free: shows docs, windows, estimated calls
    python graphrag_engine/indexing/run_index.py --docs 5           # real run (resumable; finished work is cached)
    python graphrag_engine/indexing/run_index.py --pick aa20-302a,aa22-216a
    python graphrag_engine/indexing/run_index.py --skip-reports     # extraction + graph only

Outputs (data/graphrag/): selection.json, entities.json, relationships.json, communities.json,
community_reports.json, run_summary.json, cache/ (LLM answers). Everything is evidence type
`llm_extracted_candidate`; nothing here is written into the canonical graph.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from graphrag_engine.indexing import extract as ex                       # noqa: E402
from graphrag_engine.indexing.communities import build_graph, community_table, detect_communities  # noqa: E402
from graphrag_engine.indexing.llm_cache import CachedLLM, CallBudgetExceeded  # noqa: E402
from graphrag_engine.indexing.reports import write_report               # noqa: E402
from graphrag_engine.indexing.resolve import build_canonical_index, merge  # noqa: E402
from graphrag_engine.indexing.select import load_chunks_by_doc, select_docs  # noqa: E402

DEFAULT_CHUNKS = os.path.join("data", "processed", "advisory_chunks.jsonl")
SCHEMA_VERSION = "1.0"


def _write(path: str, records, meta: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"metadata": {**meta, "count": len(records)}, "records": records}, fh, indent=1, ensure_ascii=False)


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def estimate(windows: list, max_communities: int, skip_reports: bool) -> dict:
    chars = sum(len(w.text) + len(ex.SYSTEM) for w in windows)
    calls = len(windows) + (0 if skip_reports else max_communities)
    return {"windows": len(windows), "input_tokens_extraction_est": chars // 4,
            "calls_extraction": len(windows), "calls_reports_max": 0 if skip_reports else max_communities,
            "calls_total_max": calls}


def run(a, llm=None, sleep=None, clock=None) -> dict:
    if not os.path.isfile(a.chunks):
        sys.exit(f"{a.chunks} not found - run from the project root (C:\\CyberIntelGraph) after Milestone 6")
    by_doc = load_chunks_by_doc(a.chunks)
    explicit = [x for x in (a.pick or "").split(",") if x.strip()]
    selected = select_docs(by_doc, n=a.docs, explicit=explicit or None)
    windows = []
    chunk_meta: dict[str, dict] = {}
    for d in selected:
        ws = ex.make_windows(by_doc[d["doc_id"]], a.window_words)
        windows += ws
        for w in ws:
            for cid, text in w.chunk_texts.items():
                chunk_meta[cid] = {"source_url": w.source_url, "_text_l": text.lower(), "_window": w.window_id}
    est = estimate(windows, a.max_communities, a.skip_reports)
    print("=== Milestone 9: GraphRAG indexing ===")
    print(f"advisories selected: {len(selected)}")
    for d in selected:
        print(f"  {d['doc_id']:<42} chunks {d['chunks']:>3}  words {d['words']:>6}  distinct ids {d['distinct_ids']:>3}")
    print(f"windows (= extraction calls): {est['windows']} | est. input tokens: ~{est['input_tokens_extraction_est']:,} "
          f"| max calls incl. reports: {est['calls_total_max']}")
    if a.dry_run:
        print("dry run: no LLM calls made")
        return {"dry_run": True, "selected": [d["doc_id"] for d in selected], **est}

    if llm is None:
        from rag.llm import GroqClient
        llm = GroqClient(model=a.model, max_completion_tokens=a.max_tokens, reasoning_effort=a.effort, temperature=0.1)
    cache = CachedLLM(llm, os.path.join(a.out_dir, "cache"), a.model, min_interval=a.min_interval,
                      max_calls=a.max_calls, **({"sleep": sleep} if sleep else {}), **({"clock": clock} if clock else {}))
    results, failures, stopped, splits = [], 0, None, [0]

    def process(w, depth=0):
        """Extract one window; if the API says the request is too large, halve it and retry (max 3 levels)."""
        r = ex.extract_window(cache, w)
        if r.get("too_large") and depth < 3:
            parts = ex.split_window(w)
            if parts:
                splits[0] += 1
                print(f"  {w.window_id}: request too large for the model - splitting into {len(parts)} parts")
                return [x for p in parts for x in process(p, depth + 1)]
        return [r]

    for i, w in enumerate(windows, start=1):
        try:
            batch = process(w)
        except CallBudgetExceeded as e:
            stopped = str(e)
            break
        results += batch
        for r in batch:
            if "error" in r:
                if not r.get("too_large"):
                    failures += 1
                print(f"  [{i}/{len(windows)}] {r['window_id']}: FAILED - {r['error'][:400]}")
            else:
                failures = 0
                print(f"  [{i}/{len(windows)}] {r['window_id']}: {len(r['entities'])} entities, "
                      f"{len(r['relationships'])} relationships{' (cached)' if r['from_cache'] else ''}")
        if failures >= 3:
            stopped = "3 failures in a row (rate limit or API problem) - stopping; re-run later to resume"
            break
    ok = [r for r in results if "error" not in r]
    if not ok and not stopped:
        stopped = "no window could be extracted (see the errors above)"
    if stopped and not a.allow_partial:
        print(f"\nSTOPPED: {stopped}\nextracted {len(ok)}/{len(windows)} windows (cached). Re-run the same command to continue.")
        return {"stopped": stopped, "windows_done": len(ok), "windows_total": len(windows), "llm_calls": cache.calls}

    canonical = None
    if a.canonical and os.path.isfile(a.canonical):
        with open(a.canonical, encoding="utf-8") as fh:
            canonical = build_canonical_index(json.load(fh)["records"])
    entities, rels = merge(ok, chunk_meta, canonical)
    g = build_graph(entities, rels)
    comms = detect_communities(g, seed=a.seed)
    table = community_table(g, comms, entities, rels)
    ent_by_id = {e["node_id"]: e for e in entities}
    reports, report_stop = [], None
    if not a.skip_reports:
        for comm in [c for c in table if c["size"] >= a.min_community_size][: a.max_communities]:
            try:
                rep = write_report(cache, comm, ent_by_id, rels)
            except CallBudgetExceeded as e:
                report_stop = str(e)
                break
            reports.append(rep)
            print(f"  report {comm['community_id']}: {rep.get('title') or rep.get('error')}")

    dropped = Counter()
    raw_e = raw_r = 0
    for r in ok:
        dropped.update(r["dropped"])
        raw_e += r["raw_counts"]["entities"]
        raw_r += r["raw_counts"]["relationships"]
    meta = {"schema_version": SCHEMA_VERSION, "prompt_version": ex.PROMPT_VERSION, "model": a.model,
            "chunks_file": os.path.basename(a.chunks), "chunks_sha256": _sha(a.chunks), "seed": a.seed,
            "evidence_type": "llm_extracted_candidate", "generated_at": datetime.now(timezone.utc).isoformat()}
    os.makedirs(a.out_dir, exist_ok=True)
    _write(os.path.join(a.out_dir, "selection.json"), selected, meta)
    _write(os.path.join(a.out_dir, "entities.json"), entities, meta)
    _write(os.path.join(a.out_dir, "relationships.json"), rels, meta)
    _write(os.path.join(a.out_dir, "communities.json"), table, meta)
    _write(os.path.join(a.out_dir, "community_reports.json"), reports, meta)
    summary = {
        **meta, "advisories": len(selected), "windows": len(windows), "windows_ok": len(ok),
        "windows_failed": len(results) - len(ok), "windows_split": splits[0],
        "truncated_replies": sum(1 for r in ok if r.get("finish_reason") == "length"), "llm_calls": cache.calls, "cache_hits": cache.cache_hits,
        "tokens_used_this_run": cache.tokens, "entities": len(entities), "relationships": len(rels),
        "entities_linked": sum(e["linked"] for e in entities),
        "entities_in_canonical": sum(1 for e in entities if e["in_canonical"]),
        "entities_ambiguous": sum(1 for e in entities if e["ambiguous_with"]),
        "raw_entities_from_llm": raw_e, "raw_relationships_from_llm": raw_r, "dropped": dict(dropped),
        "communities": len(table), "communities_reported": len([r for r in reports if "error" not in r]),
        "communities_singletons": sum(1 for c in table if c["size"] == 1),
        "report_errors": len([r for r in reports if "error" in r]), "stopped": stopped, "reports_stopped": report_stop,
    }
    _write(os.path.join(a.out_dir, "run_summary.json"), [summary], meta)
    os.makedirs(os.path.join("outputs", "reports"), exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with open(os.path.join("outputs", "reports", f"graphrag_index_{stamp}.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print("\n" + json.dumps({k: summary[k] for k in ("advisories", "windows_ok", "llm_calls", "cache_hits", "entities",
                                                    "entities_linked", "relationships", "communities",
                                                    "communities_reported", "dropped")}, indent=2))
    if summary["windows_failed"]:
        print(f"[WARN] {summary['windows_failed']} window(s) failed and are missing from the graph. Re-run the same "
              "command to retry them (finished work comes from the cache); apply_milestone_9_docs.py refuses until none fail.")
    if summary["truncated_replies"]:
        print(f"[WARN] {summary['truncated_replies']} extraction repl(ies) ended at the token limit - output may be cut; "
              "consider --max-tokens 4500 (new calls) or a smaller --window-words")
    if report_stop:
        print(f"REPORTS STOPPED: {report_stop}")
    return summary


def main():
    from rag.llm import DEFAULT_GROQ_MODEL
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks", default=DEFAULT_CHUNKS)
    ap.add_argument("--out-dir", default=os.path.join("data", "graphrag"))
    ap.add_argument("--canonical", default=os.path.join("data", "canonical", "entities.json"))
    ap.add_argument("--docs", type=int, default=5, help="how many advisories to auto-select (5-10 recommended)")
    ap.add_argument("--pick", default="", help="comma list of advisory ids, e.g. aa20-302a,aa22-216a")
    ap.add_argument("--window-words", type=int, default=1400)
    ap.add_argument("--model", default=DEFAULT_GROQ_MODEL)
    ap.add_argument("--max-tokens", type=int, default=3500)
    ap.add_argument("--effort", default="low")
    ap.add_argument("--min-interval", type=float, default=2.5, help="seconds between LLM calls")
    ap.add_argument("--max-calls", type=int, default=120, help="hard budget of NEW LLM calls per run")
    ap.add_argument("--min-community-size", type=int, default=3)
    ap.add_argument("--max-communities", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--skip-reports", action="store_true")
    ap.add_argument("--allow-partial", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
