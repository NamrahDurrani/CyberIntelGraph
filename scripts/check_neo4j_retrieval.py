"""Milestone 11 live check: runs the retrieval functions against YOUR Neo4j Aura graph
and verifies them against independent Cypher counts. Read-only.

    python scripts\\check_neo4j_retrieval.py

Exit code 0 = no FAIL. Writes outputs\\reports\\neo4j_retrieval_<timestamp>.json
(scripts\\apply_milestone_11_docs.py reads it)."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from neo4j_engine.connection.client import (Neo4jClient, Neo4jConfigError, Neo4jSettings,  # noqa: E402
                                            ReadOnlyViolation, assert_read_only)
from neo4j_engine.repositories.graph_repository import GraphRepository  # noqa: E402
from neo4j_engine.schema.introspect import introspect  # noqa: E402
from neo4j_engine.schema.mapping import CANONICAL_LABELS, REL_TYPES, GraphMap  # noqa: E402

# Counts reported by the Milestone 10 sync on 2026-11-17 (WARN, not FAIL, if they differ later)
M10 = {"Entity": 6297, "TextUnit": 8, "Community": 8, "relationships": 28616}
results: list[dict] = []


def rec(name: str, status: str, detail: str = "") -> None:
    results.append({"name": name, "status": status, "detail": detail})
    print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""))


def main() -> int:
    try:
        settings = Neo4jSettings.from_env()
    except Neo4jConfigError as exc:
        print(f"ERROR: {exc}"); return 2
    print(f"connecting: {settings.describe()}\n\nChecking the Cypher retrieval layer ...")
    t0 = time.perf_counter()
    try:
        client = Neo4jClient(settings).connect()
    except Exception as exc:
        print(f"ERROR: cannot connect: {type(exc).__name__}: {exc}")
        print("hint: if the message mentions the database, set NEO4J_DATABASE=neo4j in .env")
        return 3
    extra: dict = {"connected_via": getattr(client, "connected_via", None)}
    rep: dict = {"labels": [], "rel_types": [], "node_counts": {}, "rel_counts": {}, "indexes": []}   # defaults: finish() must work after any failure
    gm = None
    print(f"connected (trusting {extra['connected_via']})")
    try:
        rep = introspect(client)
        gm = GraphMap.from_report(rep)
        repo = GraphRepository(client, gm)
        rec("connected and schema read", "PASS", f"{len(rep['labels'])} labels, {len(rep['rel_types'])} relationship types")

        missing = [l for l in ("Entity", "TextUnit", "Community", *CANONICAL_LABELS) if l not in rep["labels"]]
        rec("expected labels exist", "FAIL" if missing else "PASS", f"missing {missing}" if missing else "")
        missing = [t for t in REL_TYPES if t not in rep["rel_types"]]
        rec("expected relationship types exist", "FAIL" if missing else "PASS", f"missing {missing}" if missing else "")
        if gm.n("id") and gm.n("name"):
            rec("id and name properties resolved", "PASS", f"id={gm.n('id')}, name={gm.n('name')}")
        else:
            rec("id and name properties resolved", "FAIL", f"unresolved {gm.unresolved()}; see outputs\\reports\\neo4j_schema_*.json (run schema --write)")
            return finish(client, rep, gm, extra)
        rec("optional fields", "PASS" if not gm.unresolved() else "WARN", "all resolved" if not gm.unresolved() else f"not present: {gm.unresolved()}")

        total_rels = sum(rep["rel_counts"].values())
        diffs = {k: (rep["node_counts"].get(k), v) for k, v in M10.items() if k != "relationships" and rep["node_counts"].get(k) != v}
        if total_rels != M10["relationships"]:
            diffs["relationships"] = (total_rels, M10["relationships"])
        rec("graph size matches the Milestone 10 sync", "PASS" if not diffs else "WARN", "" if not diffs else f"(found, M10) {diffs}")
        have = {i["name"] for i in rep["indexes"]}
        miss = [n for n in ("m11_entity_name_range", "m11_entity_name_text") if n not in have]
        rec("Milestone 11 indexes exist", "PASS" if not miss else "WARN", "" if not miss else "run: python neo4j_engine\\cli.py schema --apply-indexes")

        idp, namep = gm.q("id"), gm.q("name")
        # --- find / resolve -----------------------------------------------------------
        tech_row = client.run_read(f"MATCH (t:AttackTechnique) WHERE NOT ({gm.candidate_pred('t')}) AND t.{idp} ENDS WITH ':T1059.001' RETURN t.{idp} AS id LIMIT 1")
        want = tech_row[0]["id"] if tech_row else None
        found = repo.find_entities("T1059.001", types=["AttackTechnique"])
        ok = bool(found) and want is not None and found[0]["id"] == want and found[0]["match_rank"] == 0
        rec("exact id lookup T1059.001 ranks the canonical technique first", "PASS" if ok else "FAIL", f"got {found[0]['id'] if found else None}, expected {want}")
        if want:
            ent = repo.get_entity(want)
            rec("get_entity returns degree by relationship type", "PASS" if ent["degree"] else "FAIL", json.dumps(ent["degree"]))

        # --- actor -> techniques --------------------------------------------------------
        top = client.run_read(
            f"MATCH (a:ThreatActor)-[:USES]->(t:AttackTechnique) WHERE NOT ({gm.candidate_pred('a')})\n"
            f"RETURN a.{idp} AS id, a.{namep} AS name, count(DISTINCT t) AS n ORDER BY n DESC LIMIT 1")
        if not top:
            rec("a canonical actor with USES techniques exists", "FAIL", "none found - check relationship direction"); return finish(client, rep, gm, extra)
        actor_id, actor_name, expected = top[0]["id"], top[0]["name"], top[0]["n"]
        res = repo.techniques_for_actor(actor_id, limit=1000)
        direct_ids = {t["id"] for t in res["techniques"] if any(p["derivation"] == "direct" and p["claim_class"] == "documented" for p in t["paths"])}
        rec("techniques_for_actor documented count equals an independent Cypher count", "PASS" if len(direct_ids) == expected else "FAIL",
            f"{actor_name}: function {len(direct_ids)} vs Cypher {expected}")
        classes = {t["claim_class"] for t in res["techniques"]}
        rec("every technique has a valid claim class", "PASS" if classes <= {"documented", "inferred", "candidate"} else "FAIL", str(res["counts"]))
        bad = [t["id"] for t in res["techniques"] if t["claim_class"] == "documented" and not any(p["derivation"] == "direct" for p in t["paths"])]
        rec("nothing is 'documented' without a direct canonical edge", "PASS" if not bad else "FAIL", f"{bad[:5]}")
        bad = [t["id"] for t in res["techniques"] if t["claim_class"] == "candidate" and any(p["claim_class"] == "documented" for p in t["paths"])]
        rec("candidate-class techniques have no documented path", "PASS" if not bad else "FAIL", f"{bad[:5]}")
        undirected = client.run_read(f"MATCH (a:Entity {{{idp}: $id}})-[:USES]-(t:AttackTechnique) RETURN count(DISTINCT t) AS n", {"id": actor_id})[0]["n"]
        rec("USES direction is actor -> technique", "PASS" if undirected == expected else "WARN", f"directed {expected}, undirected {undirected}")
        extra["actor_example"] = {"id": actor_id, "name": actor_name, "counts": res["counts"]}

        # --- neighbours -------------------------------------------------------------------
        deg = repo.get_entity(actor_id)["degree"]
        nb = repo.neighbors(actor_id, include_candidates=True, limit=1000)
        rec("neighbors count equals the degree total", "PASS" if nb["count"] == sum(deg.values()) else "FAIL", f"neighbors {nb['count']}, degree {sum(deg.values())}")

        # --- path -------------------------------------------------------------------------
        if direct_ids:
            tid = sorted(direct_ids)[0]
            path = repo.find_path(actor_id, tid, max_hops=3)
            rec("shortest path actor -> its technique is 1 hop", "PASS" if path["found"] and path["paths"][0]["hops"] == 1 else "FAIL", f"{path['paths'][0]['hops'] if path['paths'] else 'no path'}")

        # --- provenance / candidates ---------------------------------------------------------
        cand = client.run_read(f"MATCH (n:Entity) WHERE {gm.candidate_pred('n')} RETURN n.{idp} AS id LIMIT 1")
        if cand:
            pv = repo.provenance(cand[0]["id"])
            rec("candidate provenance reaches a text unit", "PASS" if pv["text_units"] and pv["evidence_status"] == "candidate" else "FAIL",
                f"{cand[0]['id']}: {len(pv['text_units'])} text unit(s), status {pv['evidence_status']}")
        else:
            rec("candidate provenance reaches a text unit", "WARN", "no candidate nodes found")
        rep_t = client.run_read(f"MATCH (:IntelligenceReport)-[:MENTIONS]-(t:AttackTechnique) RETURN t.{idp} AS id LIMIT 1")
        if rep_t:
            pv = repo.provenance(rep_t[0]["id"])
            rec("canonical entity provenance lists the advisories that mention it", "PASS" if pv["reports"] else "FAIL", f"{rep_t[0]['id']}: {len(pv['reports'])} report(s)")
        else:
            rec("canonical entity provenance lists the advisories that mention it", "WARN", "no MENTIONS edges to a technique")

        # --- temporal -----------------------------------------------------------------------------
        if gm.n("date"):
            ch = repo.changed_since("1970-01-01", limit=5)
            rec("temporal query works", "PASS" if ch["entities"] else "WARN", f"date property {gm.n('date')}")
        else:
            rec("temporal query works", "WARN", "no date property on entities; temporal retrieval reports itself unavailable")

        # --- safety + speed --------------------------------------------------------------------------
        try:
            assert_read_only("MATCH (n) DETACH DELETE n"); rec("write queries are refused by the client", "FAIL")
        except ReadOnlyViolation:
            rec("write queries are refused by the client", "PASS")
        slow = max(client.query_log, key=lambda q: q["seconds"])
        rec("slowest query under 10 s", "PASS" if slow["seconds"] < 10 else "WARN", f"{slow['seconds']} s: {slow['cypher'][:70]}")
        extra["slowest_query_seconds"] = slow["seconds"]
        extra["queries_run"] = len(client.query_log)
    except Exception as exc:  # never leave without a report
        rec("unexpected error", "FAIL", f"{type(exc).__name__}: {exc}")
    return finish(client, rep, gm, extra, started=t0)


def finish(client, rep, gm, extra, started: float | None = None) -> int:
    client.close()
    fails = [r for r in results if r["status"] == "FAIL"]
    warns = [r for r in results if r["status"] == "WARN"]
    result = "ALL CHECKS PASSED" if not fails else f"{len(fails)} CHECK(S) FAILED"
    print(f"\nRESULT: {result}" + (f" ({len(warns)} warning(s))" if warns else ""))
    out = ROOT / "outputs" / "reports" / f"neo4j_retrieval_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"result": result, "checks": results, "graph_map": gm.to_dict() if gm else {}, "node_counts": rep["node_counts"],
                               "rel_counts": rep["rel_counts"], **extra}, indent=2, default=str), encoding="utf-8")
    print(f"report: {out.relative_to(ROOT)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
