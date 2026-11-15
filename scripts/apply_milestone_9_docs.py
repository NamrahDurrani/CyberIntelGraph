"""Write the Milestone 9 change report (real numbers from data/graphrag/run_summary.json) and update
CHANGELOG.md / PROJECT_STATUS.md. Idempotent. Refuses to run on an incomplete index."""
import json
import os
import re
import sys

MARK_CL = "## Milestone 9 - GraphRAG indexing (own extraction pipeline)"
MARK_ST = "## Milestone 9 - own pipeline done; official GraphRAG run pending (decision 0012)"


def read(p):
    with open(p, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(p, t):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)


d = os.path.join("data", "graphrag")
try:
    S = json.loads(read(os.path.join(d, "run_summary.json")))["records"][0]
    reports = json.loads(read(os.path.join(d, "community_reports.json")))["records"]
except FileNotFoundError as ex:
    print(f"REFUSED - {ex.filename} missing: run graphrag_engine\\indexing\\run_index.py first")
    sys.exit(1)
if S.get("stopped") or S.get("reports_stopped") or S["windows_failed"] or S["report_errors"]:
    print("REFUSED - the index is incomplete (stopped / failed windows / report errors). Re-run run_index.py until it finishes.")
    sys.exit(1)
date = S["generated_at"][:10]
REPORT = os.path.join("docs", f"CHANGE_REPORT_{date}_M9_graphrag.md")
dropped = S["dropped"]
titles = "\n".join(f"- **{r['community_id']}** ({r['size']} entities): {r['title']} - {r['summary'][:180]}"
                   for r in reports if "error" not in r)
write(REPORT, f"""# Change report - Milestone 9: GraphRAG indexing (own extraction pipeline)

## What was built
`graphrag_engine/` - select a small advisory subset, extract entities and relationships with the LLM
(every item grounded in the text and tagged `llm_extracted_candidate`), merge and link to the canonical
graph, detect communities (Louvain), write community reports, answer broad questions with global search.
Decision 0011 explains why this is our own lightweight implementation of the GraphRAG method rather than
the `graphrag` package.

## Run summary (model {S['model']}, prompt v{S['prompt_version']}, seed {S['seed']})
| Item | Value |
|---|---|
| Advisories read | {S['advisories']} |
| Extraction windows (= calls) | {S['windows']} (ok {S['windows_ok']}, failed {S['windows_failed']}) |
| New LLM calls this run / cache hits | {S['llm_calls']} / {S['cache_hits']} |
| Tokens used this run | {S['tokens_used_this_run']} |
| Entities | {S['entities']} (linked to canonical ids {S['entities_linked']}, found in canonical graph {S['entities_in_canonical']}, ambiguous {S['entities_ambiguous']}) |
| Relationships | {S['relationships']} |
| LLM output before grounding | {S['raw_entities_from_llm']} entities, {S['raw_relationships_from_llm']} relationships |
| Dropped by grounding checks | {json.dumps(dropped)} |
| Communities | {S['communities']} (singletons {S['communities_singletons']}, reported {S['communities_reported']}) |

## Community reports
{titles}
""")
print("wrote", REPORT)

entry = f"""{MARK_CL}
- New `graphrag_engine/`: advisory selection, grounded LLM extraction (cached, paced, call-budgeted), canonical linking, Louvain communities, community reports, global search.
- New `scripts/check_graphrag_output.py`; decision 0011; `docs/pipeline/13_graphrag.md`.
- Also: related-bonus double-count fix in `rag/hybrid.py`.

"""
if os.path.exists("CHANGELOG.md"):
    t = read("CHANGELOG.md")
    if MARK_CL in t:
        print("CHANGELOG.md: entry already present, skipped")
    else:
        i = t.find("\n## ")
        write("CHANGELOG.md", (t[:i + 1] + entry + t[i + 1:]) if i != -1 else t.rstrip("\n") + "\n\n" + entry)
        print("updated CHANGELOG.md")
if os.path.exists("PROJECT_STATUS.md"):
    t = read("PROJECT_STATUS.md")
    out, in_pending, removed = [], False, []
    for line in t.splitlines(keepends=True):
        if line.startswith("## "):
            in_pending = line.strip().lower().startswith("## pending")
        if in_pending and re.match(r"^- Milestone 9\b", line):
            removed.append(line.strip()[:70])
            continue
        out.append(line)
    t2 = "".join(out)
    if MARK_ST not in t2:
        t2 = t2.rstrip("\n") + (f"\n\n{MARK_ST}\n- GraphRAG index (own extraction pipeline) over {S['advisories']} advisories: {S['entities']} entities, "
                                f"{S['relationships']} relationships, {S['communities']} communities, {S['communities_reported']} reports "
                                f"(see `{REPORT.replace(os.sep, '/')}`).\n- Next: Milestone 10 (GraphRAG -> Neo4j).\n")
    if t2 != t:
        write("PROJECT_STATUS.md", t2)
        print("updated PROJECT_STATUS.md; removed from Pending:", removed or "nothing")
    else:
        print("PROJECT_STATUS.md: already up to date")
print("RESULT: OK")
