"""Step 2 of Milestone 10: canonical graph + validated GraphRAG export -> Neo4j (one direction only).

    python graphrag_engine\\synchronization\\sync_neo4j.py --dry-run            # plan only, no connection
    python graphrag_engine\\synchronization\\sync_neo4j.py --check-connection   # proves the credentials work
    python graphrag_engine\\synchronization\\sync_neo4j.py                      # write
    python graphrag_engine\\synchronization\\sync_neo4j.py --verify-twice       # the Milestone 10 done-criterion

Design rules (roadmap): map to canonical types, validate relationship endpoints, keep TextUnit references,
MERGE only (repeatable), batch writes, log counts. Nothing is ever deleted. Credentials come from the
environment or .env: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD (and optionally NEO4J_DATABASE); never printed.

Graph model written
  (:Entity:<Type> {entity_id, name, entity_type, origin})   canonical nodes, plus GraphRAG candidates (:Candidate)
  (:TextUnit {text_unit_id, text, chunk_ids, ...})           GraphRAG's chunks, mapped back to our chunk ids
  (:Community {community_key, level, title, summary, ...})   GraphRAG communities and their reports
  (a)-[:<REL_TYPE> {rel_id, evidence_type, ...}]->(b)         canonical relationships, and GraphRAG's RELATED_TO
  (:Entity)-[:EXTRACTED_FROM]->(:TextUnit), (:TextUnit)-[:PART_OF]->(:IntelligenceReport), (:Entity)-[:IN_COMMUNITY]->(:Community)
GraphRAG-derived facts on a node that already exists canonically are stored in gr_* properties and never
overwrite canonical properties.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

LABEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
REL_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
AURA_FREE_NODES, AURA_FREE_RELS = 200_000, 400_000      # Neo4j docs: AuraDB Free (verify current limits)

CONSTRAINTS = [
    "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS FOR (n:Entity) REQUIRE n.entity_id IS UNIQUE",
    "CREATE CONSTRAINT text_unit_id_unique IF NOT EXISTS FOR (n:TextUnit) REQUIRE n.text_unit_id IS UNIQUE",
    "CREATE CONSTRAINT community_key_unique IF NOT EXISTS FOR (n:Community) REQUIRE n.community_key IS UNIQUE",
]
Q_NODE = ("UNWIND $rows AS row\nMERGE (n:Entity {entity_id: row.entity_id})\nSET n:`__LABEL__`\n__EXTRA__SET n += row.props")
Q_TU = "UNWIND $rows AS row\nMERGE (t:TextUnit {text_unit_id: row.text_unit_id})\nSET t += row.props"
Q_COMM = "UNWIND $rows AS row\nMERGE (c:Community {community_key: row.community_key})\nSET c += row.props"
Q_REL = ("UNWIND $rows AS row\nMATCH (a:Entity {entity_id: row.source_id})\nMATCH (b:Entity {entity_id: row.target_id})\n"
         "MERGE (a)-[r:`__TYPE__` {rel_id: row.rel_id}]->(b)\nSET r += row.props")
Q_LINK_TU = ("UNWIND $rows AS row\nMATCH (a:Entity {entity_id: row.a})\nMATCH (t:TextUnit {text_unit_id: row.b})\n"
             "MERGE (a)-[r:EXTRACTED_FROM {rel_id: row.rel_id}]->(t)")
Q_LINK_REPORT = ("UNWIND $rows AS row\nMATCH (t:TextUnit {text_unit_id: row.a})\nMATCH (e:Entity {entity_id: row.b})\n"
                 "MERGE (t)-[r:PART_OF {rel_id: row.rel_id}]->(e)")
Q_LINK_COMM = ("UNWIND $rows AS row\nMATCH (a:Entity {entity_id: row.a})\nMATCH (c:Community {community_key: row.b})\n"
               "MERGE (a)-[r:IN_COMMUNITY {rel_id: row.rel_id}]->(c)")


def load_env_file(path: str = ".env") -> None:
    """Fill missing environment variables from .env (values are never printed)."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
            if m and not line.lstrip().startswith("#"):
                os.environ.setdefault(m.group(1), m.group(2).strip().strip('"').strip("'"))


def sanitize_value(v):
    if isinstance(v, bool) or isinstance(v, (int, str)):
        return v
    if isinstance(v, float):
        return None if math.isnan(v) or math.isinf(v) else v
    if isinstance(v, (list, tuple)):
        items = [sanitize_value(x) for x in v if x is not None]
        if any(isinstance(x, (list, dict)) or x is None for x in items):
            return json.dumps(list(v), ensure_ascii=False, sort_keys=True, default=str)
        kinds = {type(x) for x in items}
        if len(kinds) > 1:
            return [str(x) for x in items]
        return items
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False, sort_keys=True, default=str)
    return str(v)


def sanitize_props(d: dict) -> dict:
    """Neo4j properties: primitives or flat lists of one primitive type. Everything else becomes a JSON string."""
    out = {}
    for k, v in d.items():
        if v is None:
            continue
        s = sanitize_value(v)
        if s is not None:
            out[str(k)] = s
    return out


def evidence_summary(evidence: list[dict]) -> dict:
    evidence = evidence or []
    return {"evidence_types": sorted({e.get("evidence_type") for e in evidence if e.get("evidence_type")}),
            "evidence_sources": sorted({e.get("source") for e in evidence if e.get("source")}),
            "evidence_record_refs": [e["record_ref"] for e in evidence if e.get("record_ref")][:5],
            "evidence_urls": [e["source_url"] for e in evidence if e.get("source_url")][:3],
            "evidence_json": json.dumps(evidence[:5], ensure_ascii=False, sort_keys=True, default=str) if evidence else None}


def load_canonical(directory: str):
    def rec(name):
        p = os.path.join(directory, name)
        if not os.path.isfile(p):
            return []
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)["records"]
    return rec("entities.json"), rec("relationships.json")


def check_names(labels, types):
    bad = [x for x in labels if not LABEL_RE.match(x)] + [x for x in types if not REL_RE.match(x)]
    if bad:
        raise ValueError(f"unsafe label / relationship type refused (Cypher cannot parameterise them): {bad[:3]}")


def build_plan(export: dict | None, canonical_entities: list[dict], canonical_rels: list[dict],
               do_canonical: bool = True, do_graphrag: bool = True) -> dict:
    steps, counts, skipped = [], Counter(), Counter()
    canon_ids = {e["canonical_id"] for e in canonical_entities}
    canon_type = {e["canonical_id"]: e["entity_type"] for e in canonical_entities}
    gr_nodes = export["nodes"] if (export and do_graphrag) else []
    planned_ids = set(canon_ids) | {n["entity_id"] for n in gr_nodes}

    # ---- canonical nodes (grouped by label, written first)
    by_label = defaultdict(list)
    if do_canonical:
        for e in sorted(canonical_entities, key=lambda r: r["canonical_id"]):
            props = {k: v for k, v in e.items() if k not in ("canonical_id", "evidence")}
            props.update(evidence_summary(e.get("evidence")))
            props["origin"] = "canonical"
            by_label[e["entity_type"]].append({"entity_id": e["canonical_id"], "props": sanitize_props(props)})
    # ---- GraphRAG nodes: existing canonical nodes get gr_* only; the rest are candidates
    cand_by_label, linked_by_label = defaultdict(list), defaultdict(list)
    for n in gr_nodes:
        gr = {"gr_description": n["description"], "gr_titles": n["titles"], "gr_ids": n["graphrag_ids"],
              "gr_text_unit_ids": n["text_unit_ids"], "gr_chunk_ids": n.get("chunk_ids", []),
              "gr_frequency": n["frequency"], "gr_degree": n["degree"], "seen_in_graphrag": True}
        if n["entity_id"] in canon_ids:      # keep the canonical node's own label (GraphRAG may call a Malware a Tool)
            linked_by_label[canon_type[n["entity_id"]]].append({"entity_id": n["entity_id"], "props": sanitize_props(gr)})
        else:
            props = {**gr, "name": n["name"], "entity_type": n["entity_type"], "origin": "graphrag",
                     "canonical_type": n["canonical_type"], "evidence_types": [n["evidence_type"]]}
            cand_by_label[n["entity_type"]].append({"entity_id": n["entity_id"], "props": sanitize_props(props)})
    check_names(list(by_label) + list(cand_by_label) + list(linked_by_label), [])
    for label, rows in sorted(by_label.items()):
        steps.append((f"canonical nodes :{label}", Q_NODE.replace("__LABEL__", label).replace("__EXTRA__", ""), rows))
        counts["nodes"] += len(rows)
    for label, rows in sorted(linked_by_label.items()):
        steps.append((f"graphrag facts on canonical :{label}", Q_NODE.replace("__LABEL__", label).replace("__EXTRA__", ""), rows))
    for label, rows in sorted(cand_by_label.items()):
        steps.append((f"graphrag candidate nodes :{label}",
                      Q_NODE.replace("__LABEL__", label).replace("__EXTRA__", "SET n:Candidate\n"), rows))
        counts["nodes"] += len(rows)
    counts["candidate_nodes"] = sum(len(r) for r in cand_by_label.values())
    # ---- text units and communities
    if export and do_graphrag:
        tus = [{"text_unit_id": t["text_unit_id"], "props": sanitize_props(
            {"text": t["text"], "n_tokens": t["n_tokens"], "doc_id": t["doc_id"], "chunk_ids": t["chunk_ids"], "origin": "graphrag"})}
            for t in export["text_units"]]
        comms = [{"community_key": c["community_key"], "props": sanitize_props(
            {k: c[k] for k in ("community", "level", "parent", "size", "title", "summary", "rank", "findings_json", "origin")})}
            for c in export["communities"]]
        if tus:
            steps.append(("text units", Q_TU, tus))
        if comms:
            steps.append(("communities", Q_COMM, comms))
        counts["nodes"] += len(tus) + len(comms)
    # ---- relationships, endpoints validated against every node we will have
    rels_by_type = defaultdict(list)
    if do_canonical:
        for r in sorted(canonical_rels, key=lambda r: r["rel_id"]):
            if r["source_id"] not in planned_ids or r["target_id"] not in planned_ids:
                skipped["canonical_rel_endpoint_missing"] += 1
                continue
            props = {k: v for k, v in (r.get("properties") or {}).items() if k != "rel_id"}
            props.update(evidence_summary(r.get("evidence")))
            props.update({"evidence_type": r["evidence_type"], "origin": "canonical"})
            rels_by_type[r["rel_type"]].append({"rel_id": r["rel_id"], "source_id": r["source_id"],
                                                "target_id": r["target_id"], "props": sanitize_props(props)})
    if export and do_graphrag:
        for r in export["relationships"]:
            if r["source_id"] not in planned_ids or r["target_id"] not in planned_ids:
                skipped["graphrag_rel_endpoint_missing"] += 1
                continue
            props = {"evidence_type": r["evidence_type"], "evidence_types": [r["evidence_type"]], "origin": "graphrag",
                     "description": r["description"], "weight": r["weight"], "text_unit_ids": r["text_unit_ids"],
                     "chunk_ids": r.get("chunk_ids", [])}
            rels_by_type[r["rel_type"]].append({"rel_id": r["rel_id"], "source_id": r["source_id"],
                                                "target_id": r["target_id"], "props": sanitize_props(props)})
    check_names([], list(rels_by_type))
    for rtype, rows in sorted(rels_by_type.items()):
        steps.append((f"relationships {rtype}", Q_REL.replace("__TYPE__", rtype), rows))
        counts["relationships"] += len(rows)
    # ---- links
    if export and do_graphrag:
        tu_ids = {t["text_unit_id"] for t in export["text_units"]}
        ck = {c["community_key"] for c in export["communities"]}
        gnodes = {n["entity_id"] for n in gr_nodes}
        l1 = [{"a": a, "b": b, "rel_id": f"EXTRACTED_FROM|{a}|{b}"} for a, b in export["links"]["entity_text_unit"] if a in gnodes and b in tu_ids]
        l2 = [{"a": a, "b": b, "rel_id": f"PART_OF|{a}|{b}"} for a, b in export["links"]["text_unit_report"] if a in tu_ids and b in planned_ids]
        l3 = [{"a": a, "b": b, "rel_id": f"IN_COMMUNITY|{a}|{b}"} for a, b in export["links"]["entity_community"] if a in gnodes and b in ck]
        if len(export["links"]["text_unit_report"]) > len(l2):
            skipped["text_unit_report_link_no_report"] += len(export["links"]["text_unit_report"]) - len(l2)
        for name, q, rows in (("links EXTRACTED_FROM", Q_LINK_TU, l1), ("links PART_OF", Q_LINK_REPORT, l2), ("links IN_COMMUNITY", Q_LINK_COMM, l3)):
            if rows:
                steps.append((name, q, rows))
                counts["relationships"] += len(rows)
    return {"steps": steps, "counts": dict(counts), "skipped": dict(skipped)}


def describe_plan(plan: dict) -> str:
    lines = [f"  {name:<46} {len(rows):>7} rows" for name, _q, rows in plan["steps"]]
    c = plan["counts"]
    lines.append(f"  planned: {c.get('nodes', 0)} nodes ({c.get('candidate_nodes', 0)} GraphRAG candidates), {c.get('relationships', 0)} relationships")
    if plan["skipped"]:
        lines.append(f"  skipped (endpoint validation): {plan['skipped']}")
    if c.get("nodes", 0) > 0.8 * AURA_FREE_NODES or c.get("relationships", 0) > 0.8 * AURA_FREE_RELS:
        lines.append(f"  [WARN] close to AuraDB Free limits ({AURA_FREE_NODES:,} nodes / {AURA_FREE_RELS:,} relationships)")
    return "\n".join(lines)


def run_steps(driver, steps, database=None, batch_size=500, log=print) -> Counter:
    totals = Counter()
    with driver.session(database=database) as session:
        for name, query, rows in steps:
            before = Counter(totals)
            for i in range(0, len(rows), batch_size):
                batch = rows[i:i + batch_size]

                def work(tx, q=query, b=batch):
                    return tx.run(q, rows=b).consume().counters
                c = session.execute_write(work)
                totals["nodes_created"] += c.nodes_created
                totals["relationships_created"] += c.relationships_created
                totals["properties_set"] += c.properties_set
            log(f"  {name:<46} {len(rows):>7} rows | +{totals['nodes_created'] - before['nodes_created']} nodes, "
                f"+{totals['relationships_created'] - before['relationships_created']} relationships")
    return totals


def ensure_constraints(driver, database=None):
    with driver.session(database=database) as session:
        for q in CONSTRAINTS:
            session.execute_write(lambda tx, q=q: tx.run(q).consume())


def graph_counts(driver, database=None) -> dict:
    queries = {"entities": "MATCH (n:Entity) RETURN count(n) AS c", "text_units": "MATCH (n:TextUnit) RETURN count(n) AS c",
               "communities": "MATCH (n:Community) RETURN count(n) AS c", "relationships": "MATCH ()-[r]->() RETURN count(r) AS c"}
    out = {}
    with driver.session(database=database) as session:
        for k, q in queries.items():
            out[k] = session.execute_read(lambda tx, q=q: tx.run(q).single()["c"])
    return out


def connect():
    load_env_file()
    uri, user, pwd = os.environ.get("NEO4J_URI"), os.environ.get("NEO4J_USERNAME"), os.environ.get("NEO4J_PASSWORD")
    missing = [n for n, v in (("NEO4J_URI", uri), ("NEO4J_USERNAME", user), ("NEO4J_PASSWORD", pwd)) if not v]
    if missing:
        sys.exit(f"missing {', '.join(missing)} - put them in .env (see docs/pipeline/16_neo4j_sync.md)")
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(uri, auth=(user, pwd))
    driver.verify_connectivity()
    host = re.sub(r"^[a-z+]+://", "", uri).split("/")[0]
    print(f"connected to {host} as {user}")
    return driver, (os.environ.get("NEO4J_DATABASE") or None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", default=os.path.join("data", "graphrag_outputs", "export", "graphrag_graph.json"))
    ap.add_argument("--canonical-dir", default=os.path.join("data", "canonical"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check-connection", action="store_true")
    ap.add_argument("--canonical-only", action="store_true")
    ap.add_argument("--graphrag-only", action="store_true")
    ap.add_argument("--verify-twice", action="store_true")
    ap.add_argument("--batch-size", type=int, default=500)
    a = ap.parse_args()
    if a.check_connection:
        driver, db = connect()
        print("graph now holds:", graph_counts(driver, db))
        driver.close()
        return
    export = None
    if not a.canonical_only:
        if not os.path.isfile(a.export):
            sys.exit(f"{a.export} not found - run graphrag_engine\\export\\export_graphrag.py first (in .venv-graphrag)")
        with open(a.export, encoding="utf-8") as fh:
            export = json.load(fh)
    ents, rels = load_canonical(a.canonical_dir)      # always read: needed to know which GraphRAG nodes already exist
    if not ents:
        print(f"[warn] no canonical entities in {a.canonical_dir}: GraphRAG nodes will all be candidates")
    plan = build_plan(export, ents, rels, do_canonical=not a.graphrag_only, do_graphrag=not a.canonical_only)
    print("=== Milestone 10: Neo4j synchronization plan ===")
    print(describe_plan(plan))
    if a.dry_run:
        print("dry run: nothing was sent to Neo4j")
        return
    driver, db = connect()
    ensure_constraints(driver, db)
    first = run_steps(driver, plan["steps"], db, a.batch_size)
    counts1 = graph_counts(driver, db)
    print("graph now holds:", counts1, "| created this pass:", dict(first))
    if a.verify_twice:
        print("--- second pass (must create nothing) ---")
        second = run_steps(driver, plan["steps"], db, a.batch_size)
        counts2 = graph_counts(driver, db)
        same = counts1 == counts2 and second["nodes_created"] == 0 and second["relationships_created"] == 0
        print("graph now holds:", counts2, "| created this pass:", dict(second))
        print("IDEMPOTENT: PASS - same counts, nothing created" if same else "IDEMPOTENT: FAIL - counts changed between passes")
        driver.close()
        sys.exit(0 if same else 1)
    driver.close()


if __name__ == "__main__":
    main()
