"""Close Milestone 10 in the documentation, from REAL results: the latest independent
check report (outputs/reports/neo4j_check_*.json) and the export report inside
data/graphrag_outputs/export/graphrag_graph.json. Idempotent.

    python scripts/apply_milestone_10_docs.py --idempotent-confirmed
(pass the flag only after sync_neo4j.py --verify-twice printed IDEMPOTENT: PASS)
"""
import glob
import json
import os
import re
import sys

MARK_CL = "## Milestone 10 - canonical graph and GraphRAG candidates in Neo4j"
MARK_ST = "## Milestone 10 - done"
REPORT = os.path.join("docs", "CHANGE_REPORT_2026-11-17_M10_neo4j_sync.md")


def read(p):
    with open(p, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(p, t):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)


checks = sorted(glob.glob(os.path.join("outputs", "reports", "neo4j_check_*.json")))
if not checks:
    print("REFUSED - run python scripts\\check_neo4j_graph.py first")
    sys.exit(1)
chk = json.loads(read(checks[-1]))
if not chk["ok"]:
    print("REFUSED - the latest database check has failures:", [c["message"] for c in chk["checks"] if not c["ok"] and c["level"] == "FAIL"][:3])
    sys.exit(1)
if "--idempotent-confirmed" not in sys.argv:
    print("REFUSED - run sync_neo4j.py --verify-twice; if it prints IDEMPOTENT: PASS, add --idempotent-confirmed")
    sys.exit(1)
exp = chk["expected"]
exp_path = os.path.join("data", "graphrag_outputs", "export", "graphrag_graph.json")
rep = json.loads(read(exp_path)).get("report", {}) if os.path.exists(exp_path) else {}
warns = [c["message"] for c in chk["checks"] if not c["ok"] and c["level"] == "WARN"]
canon = " · ".join(f"{k} {v:,}" for k, v in sorted(exp["canonical_by_type"].items()))
rels = " · ".join(f"{k} {v:,}" for k, v in sorted(exp["rels_by_type"].items()))
print(f"checked: {exp['total_nodes']} nodes, {exp['total_relationships']} relationships, {sum(1 for c in chk['checks'] if c['ok'])} checks ok")

report = f"""# Change report - Milestone 10: canonical graph and GraphRAG candidates in Neo4j

## Result (from the independent database check, `{os.path.basename(checks[-1])}`)
| Item | Value |
|---|---|
| Nodes in Neo4j | {exp['total_nodes']:,} |
| Relationships in Neo4j | {exp['total_relationships']:,} |
| Canonical nodes by type | {canon} |
| GraphRAG candidate nodes | {exp['candidates']} |
| Text units / communities | {exp['text_units']} / {exp['communities']} |
| Relationships by type | {rels} |
| Vulnerabilities with a weakness link | {exp['has_weakness_vulns']:,} |
| Independent checks passed | {sum(1 for c in chk['checks'] if c['ok'])} of {len(chk['checks'])} |
| Repeatability (`--verify-twice`) | PASS (second pass created nothing; confirmed by the operator) |

Warnings: {warns or 'none'}

## GraphRAG export (pilot advisory)
{json.dumps(rep, indent=1) if rep else 'export report not found'}

## Rules that keep printed facts and pencil notes apart
- Candidates carry labels `:Entity:Candidate`, `origin: graphrag`, evidence type `llm_extracted_candidate`.
- GraphRAG relationships are the separate type `RELATED_TO`; no canonical relationship touches a candidate.
- GraphRAG facts on an existing canonical node live in `gr_*` properties and never overwrite canonical properties.
- Every text unit maps back to our chunk ids; every candidate is linked to its text unit.

## Not done
Milestone 11 (indexes, Cypher retrieval functions); typing GraphRAG relationships; more than one advisory;
the official GraphRAG search methods and evidence validation (Milestones 9.5-9.6 in the migration plan).
"""
write(REPORT, report)
print("wrote", REPORT)

entry = f"""{MARK_CL}
- Canonical graph ({exp['total_nodes']:,} nodes, {exp['total_relationships']:,} relationships in total) and the pilot GraphRAG candidates synchronised to Neo4j with MERGE; repeat run creates nothing.
- Added an independent database check (`scripts/check_neo4j_graph.py`).

"""
for path in ("CHANGELOG.md", "PROJECT_STATUS.md"):
    if not os.path.exists(path):
        print(f"[WARN] {path} not found, skipped")
        continue
    t = read(path)
    if path == "CHANGELOG.md":
        if MARK_CL in t:
            print("CHANGELOG.md: entry already present, skipped")
            continue
        i = t.find("\n## ")
        t = (t[:i + 1] + entry + t[i + 1:]) if i != -1 else t.rstrip("\n") + "\n\n" + entry
        write(path, t)
        print("updated CHANGELOG.md")
        continue
    out, in_pending, removed = [], False, []
    for line in t.splitlines(keepends=True):
        if line.startswith("## "):
            in_pending = line.strip().lower().startswith("## pending")
        if in_pending and re.match(r"^- Milestone 10\b", line):
            removed.append(line.strip()[:60])
            continue
        out.append(line)
    t2 = "".join(out)
    if MARK_ST not in t2:
        t2 = t2.rstrip("\n") + f"\n\n{MARK_ST}\n- Neo4j holds the canonical graph plus the pilot GraphRAG candidates ({exp['total_nodes']:,} nodes, {exp['total_relationships']:,} relationships).\n- Next: Milestone 11 (Neo4j indexes and Cypher retrieval).\n"
    if t2 != t:
        write(path, t2)
        print("updated PROJECT_STATUS.md; removed from Pending:", removed or "nothing")
    else:
        print("PROJECT_STATUS.md: already up to date")
print("RESULT: OK")
