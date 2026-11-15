"""Checker for the Milestone 9 GraphRAG output (data/graphrag).   python scripts/check_graphrag_output.py"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canonical.models import Evidence, Relationship               # noqa: E402
from graphrag_engine.indexing.extract import ENTITY_TYPES          # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--dir", default=os.path.join("data", "graphrag"))
ap.add_argument("--chunks", default=os.path.join("data", "processed", "advisory_chunks.jsonl"))
a = ap.parse_args()
fails = 0


def check(ok, msg, level="FAIL"):
    global fails
    print(f"  [{'PASS' if ok else level}] {msg}")
    if not ok and level == "FAIL":
        fails += 1


def load(name):
    with open(os.path.join(a.dir, f"{name}.json"), encoding="utf-8") as fh:
        return json.load(fh)


print("Checking the GraphRAG output ...")
try:
    ents, rels, comms, reps, summ = (load(n) for n in ("entities", "relationships", "communities", "community_reports", "run_summary"))
except FileNotFoundError as ex:
    sys.exit(f"  [FAIL] {ex.filename} missing - run graphrag_engine\\indexing\\run_index.py first")
chunk_ids = set()
if os.path.isfile(a.chunks):
    with open(a.chunks, encoding="utf-8") as fh:
        chunk_ids = {json.loads(l)["chunk_id"] for l in fh if l.strip()}
E, R, C, P = ents["records"], rels["records"], comms["records"], reps["records"]
S = summ["records"][0]

for name, doc in (("entities", ents), ("relationships", rels), ("communities", comms), ("community_reports", reps)):
    check(doc["metadata"].get("evidence_type") == "llm_extracted_candidate" and doc["metadata"]["count"] == len(doc["records"]),
          f"{name}.json metadata ok (evidence type, count {len(doc['records'])})")
ids = [e["node_id"] for e in E]
check(len(ids) == len(set(ids)), "entity node ids unique")
check(all(e["type"] in ENTITY_TYPES for e in E), "all entity types are allowed types")
check(all(e["evidence"] for e in E), "every entity has at least one evidence record", "WARN")
bad = []
for r in R:
    try:
        Relationship(**r)
        for ev in r["evidence"]:
            Evidence(**ev)
    except Exception as ex:                                             # noqa: BLE001
        bad.append((r["rel_id"], str(ex)[:80]))
check(not bad, "every relationship validates against the canonical Relationship model" + (f" - first: {bad[0]}" if bad else ""))
check(all(r["source_id"] in set(ids) and r["target_id"] in set(ids) for r in R), "no relationship points at a missing entity")
check(all(r["evidence"] and all(ev["evidence_type"] == "llm_extracted_candidate" for ev in r["evidence"]) for r in R),
      "every relationship has evidence, all of type llm_extracted_candidate")
if chunk_ids:
    ev_chunks = {ev["record_ref"] for r in R for ev in r["evidence"]} | {ev["record_ref"] for e in E for ev in e["evidence"]}
    check(ev_chunks <= chunk_ids, f"all evidence chunk ids exist in the chunk file ({len(ev_chunks)} distinct)")
else:
    print("  (info) chunk file not found: evidence chunk ids not verified")
members = [n for c in C for n in c["node_ids"]]
check(sorted(members) == sorted(ids), "communities partition the graph (each entity in exactly one community)")
cids = {c["community_id"] for c in C}
check(all(p["community_id"] in cids for p in P), "every community report belongs to a known community")
errs = [p for p in P if "error" in p]
check(not errs, f"all community reports were written ({len(P)} reports)", "WARN")
if chunk_ids:
    sup = {c for p in P if "error" not in p for f in p["findings"] for c in f["support"]}
    check(sup <= chunk_ids, "report findings cite only real chunk ids")
unsup = sum(p.get("unsupported_findings", 0) for p in P if "error" not in p)
total_f = sum(len(p["findings"]) for p in P if "error" not in p)
print(f"  (info) report findings without a supporting chunk: {unsup} of {total_f}")
d = S["dropped"]
raw_e, raw_r = S["raw_entities_from_llm"], S["raw_relationships_from_llm"]
ne = d.get("entity_not_in_text", 0)
check(raw_e == 0 or ne / raw_e < 0.30, f"model hallucinated few entities: {ne} of {raw_e} dropped as not in the text", "WARN")
nr = d.get("rel_quote_not_in_text", 0) + d.get("rel_unknown_endpoint", 0)
check(raw_r == 0 or nr / raw_r < 0.40, f"relationship drop rate acceptable: {nr} of {raw_r} dropped (quote not in text / unknown endpoint)", "WARN")
print(f"  (info) entities {len(E)} (linked {S['entities_linked']}, in canonical {S['entities_in_canonical']}, ambiguous {S['entities_ambiguous']}) | "
      f"relationships {len(R)} | communities {S['communities']} (singletons {S['communities_singletons']}, reported {S['communities_reported']})")
print(f"  (info) LLM calls this run {S['llm_calls']} (cache hits {S['cache_hits']}) | model {S['model']} | prompt v{S['prompt_version']}")
print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
