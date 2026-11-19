"""Independent, READ-ONLY check of the live Neo4j graph against the files it was built from
(data/canonical + data/graphrag_outputs/export/graphrag_graph.json). It does not trust the sync
script: expected counts come from the files, actual counts from the database.

    python scripts/check_neo4j_graph.py

Credentials come from .env (NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD); nothing secret is printed or saved.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from graphrag_engine.synchronization import sync_neo4j as sy   # noqa: E402

Q = {
    "constraints": "SHOW CONSTRAINTS YIELD name RETURN collect(name) AS names",
    "canonical_by_type": "MATCH (n:Entity) WHERE n.origin = 'canonical' RETURN n.entity_type AS t, count(n) AS c",
    "candidates": "MATCH (n:Candidate) RETURN count(n) AS c",
    "bad_candidates": ("MATCH (n:Candidate) WHERE n.origin <> 'graphrag' "
                       "OR NOT 'llm_extracted_candidate' IN coalesce(n.evidence_types, []) RETURN count(n) AS c"),
    "canonical_with_candidate_label": "MATCH (n:Entity:Candidate) WHERE n.origin = 'canonical' RETURN count(n) AS c",
    "canonical_edges_touching_candidates": ("MATCH (a)-[r]->(b) WHERE r.origin = 'canonical' "
                                            "AND (a:Candidate OR b:Candidate) RETURN count(r) AS c"),
    "bad_related_to": ("MATCH ()-[r:RELATED_TO]->() WHERE r.origin <> 'graphrag' "
                       "OR r.evidence_type <> 'llm_extracted_candidate' RETURN count(r) AS c"),
    "text_units": "MATCH (t:TextUnit) RETURN count(t) AS c",
    "communities": "MATCH (c:Community) RETURN count(c) AS c",
    "rels_by_type": "MATCH ()-[r]->() RETURN type(r) AS t, count(r) AS c",
    "dup_entities": "MATCH (n:Entity) WITH n.entity_id AS id, count(*) AS k WHERE k > 1 RETURN count(*) AS c",
    "dup_rels": ("MATCH ()-[r]->() WITH r.rel_id AS id, count(*) AS k WHERE id IS NOT NULL AND k > 1 "
                 "RETURN count(*) AS c"),
    "sample": ("UNWIND $rows AS row MATCH (a:Entity {entity_id: row.s})-[r]->(b:Entity {entity_id: row.t}) "
               "WHERE type(r) = row.type AND r.rel_id = row.rid RETURN count(r) AS c"),
    "units_without_chunks": ("MATCH (t:TextUnit) WHERE t.chunk_ids IS NULL OR size(t.chunk_ids) = 0 "
                             "RETURN count(t) AS c"),
    "candidates_without_source": ("MATCH (n:Candidate) WHERE NOT (n)-[:EXTRACTED_FROM]->(:TextUnit) "
                                  "RETURN count(n) AS c"),
    "has_weakness_vulns": "MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->(:Weakness) RETURN count(DISTINCT v) AS c",
}
REQUIRED_CONSTRAINTS = {"entity_id_unique", "text_unit_id_unique", "community_key_unique"}


def expected_from_files(export, ents, rels) -> dict:
    """Everything the database SHOULD contain, derived from the files alone."""
    plan = sy.build_plan(export, ents, rels)
    canon_ids = {e["canonical_id"] for e in ents}
    rel_types = {}
    for name, _q, rows in plan["steps"]:
        if name.startswith("relationships "):
            rel_types[name.split(" ", 1)[1]] = len(rows)
        elif name.startswith("links "):
            rel_types[name.split(" ", 1)[1]] = len(rows)
    gr_nodes = (export or {}).get("nodes", [])
    all_rels = sorted(rels, key=lambda r: r["rel_id"])
    step = max(1, len(all_rels) // 200)
    return {
        "canonical_by_type": dict(Counter(e["entity_type"] for e in ents)),
        "candidates": sum(1 for n in gr_nodes if n["entity_id"] not in canon_ids),
        "text_units": len((export or {}).get("text_units", [])),
        "communities": len((export or {}).get("communities", [])),
        "rels_by_type": rel_types,
        "total_nodes": plan["counts"].get("nodes", 0),
        "total_relationships": plan["counts"].get("relationships", 0),
        "has_weakness_vulns": len({r["source_id"] for r in rels if r["rel_type"] == "HAS_WEAKNESS"
                                   and r["source_id"] in canon_ids and r["target_id"] in canon_ids}),
        "sample": [{"rid": r["rel_id"], "s": r["source_id"], "t": r["target_id"], "type": r["rel_type"]}
                   for r in all_rels[::step][:200]
                   if r["source_id"] in canon_ids and r["target_id"] in canon_ids],
    }


def run_checks(read, exp: dict) -> list[tuple[str, bool, str]]:
    """read(cypher, **params) -> list[dict]. Returns [(level, ok, message)]; level FAIL or WARN."""
    out = []

    def add(ok, msg, level="FAIL"):
        out.append((level, bool(ok), msg))

    def one(key, **p):
        rows = read(Q[key], **p)
        return int(rows[0]["c"]) if rows else 0

    names = set((read(Q["constraints"]) or [{"names": []}])[0]["names"])
    add(REQUIRED_CONSTRAINTS <= names, f"the 3 uniqueness constraints exist ({sorted(REQUIRED_CONSTRAINTS - names) or 'all present'})")
    got = {r["t"]: int(r["c"]) for r in read(Q["canonical_by_type"])}
    add(got == exp["canonical_by_type"], f"canonical nodes per type match ({sum(got.values())} nodes)")
    if got != exp["canonical_by_type"]:
        for k in sorted(set(got) | set(exp["canonical_by_type"])):
            if got.get(k) != exp["canonical_by_type"].get(k):
                out.append(("INFO", True, f"    {k}: files {exp['canonical_by_type'].get(k)} vs Neo4j {got.get(k)}"))
    add(one("candidates") == exp["candidates"], f"candidate nodes match the export ({exp['candidates']})")
    add(one("text_units") == exp["text_units"], f"text units match ({exp['text_units']})")
    add(one("communities") == exp["communities"], f"communities match ({exp['communities']})")
    rels = {r["t"]: int(r["c"]) for r in read(Q["rels_by_type"])}
    add(rels == exp["rels_by_type"], f"relationships per type match ({sum(rels.values())} in total)")
    if rels != exp["rels_by_type"]:
        for k in sorted(set(rels) | set(exp["rels_by_type"])):
            if rels.get(k) != exp["rels_by_type"].get(k):
                out.append(("INFO", True, f"    {k}: files {exp['rels_by_type'].get(k)} vs Neo4j {rels.get(k)}"))
    add(one("dup_entities") == 0, "no duplicate entity_id")
    add(one("dup_rels") == 0, "no duplicate relationship rel_id")
    # printed facts vs pencil notes
    add(one("bad_candidates") == 0, "every candidate node is origin=graphrag with evidence type llm_extracted_candidate")
    add(one("canonical_with_candidate_label") == 0, "no canonical node was labelled Candidate")
    add(one("canonical_edges_touching_candidates") == 0, "no canonical relationship touches a candidate node")
    add(one("bad_related_to") == 0, "every RELATED_TO is origin=graphrag, evidence type llm_extracted_candidate")
    # traceability
    add(one("units_without_chunks") == 0, "every text unit maps back to at least one of our chunk ids")
    add(one("candidates_without_source") == 0, "every candidate is linked to a text unit (EXTRACTED_FROM)", "WARN")
    if exp["sample"]:
        hit = one("sample", rows=exp["sample"])
        add(hit == len(exp["sample"]), f"{len(exp['sample'])} sampled canonical relationships exist with the right endpoints and type")
    add(one("has_weakness_vulns") == exp["has_weakness_vulns"],
        f"vulnerabilities with a weakness link: files {exp['has_weakness_vulns']}")
    return out


def main():
    export_path = os.path.join("data", "graphrag_outputs", "export", "graphrag_graph.json")
    with open(export_path, encoding="utf-8") as fh:
        export = json.load(fh)
    ents, rels = sy.load_canonical(os.path.join("data", "canonical"))
    exp = expected_from_files(export, ents, rels)
    driver, db = sy.connect()

    def read(q, **p):
        with driver.session(database=db) as s:
            return s.execute_read(lambda tx: [r.data() for r in tx.run(q, **p)])

    print("\nChecking Neo4j against the files ...")
    results = run_checks(read, exp)
    driver.close()
    fails = 0
    for level, ok, msg in results:
        tag = "INFO" if level == "INFO" else ("PASS" if ok else level)
        print(f"  [{tag}] {msg}")
        fails += (not ok and level == "FAIL")
    print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"{fails} CHECK(S) FAILED")
    os.makedirs(os.path.join("outputs", "reports"), exist_ok=True)
    path = os.path.join("outputs", "reports", f"neo4j_check_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"ok": not fails, "failed": fails,
                   "checks": [{"level": l, "ok": o, "message": m} for l, o, m in results],
                   "expected": {k: v for k, v in exp.items() if k != "sample"}}, fh, indent=1)
    print("report:", path)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
