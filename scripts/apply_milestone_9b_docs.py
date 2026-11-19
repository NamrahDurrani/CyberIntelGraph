"""Summarise the official Microsoft GraphRAG run and update the docs (Milestone 9). Run in the graphrag venv.

    python scripts\\apply_milestone_9b_docs.py

Prints a summary (paste it back if you want a second pair of eyes), writes
docs/CHANGE_REPORT_<date>_M9b_ms_graphrag.md, adds a CHANGELOG entry and closes Milestone 9 in PROJECT_STATUS.md.
Idempotent. Refuses if the output files are missing.
"""
import glob
import os
import re
import sys
from datetime import datetime, timezone

import pandas as pd

OUT = os.path.join("data", "graphrag_outputs")
MARK_CL = "## Milestone 9b - official Microsoft GraphRAG run"
OLD_ST = "## Milestone 9 - own pipeline done; official GraphRAG run pending (decision 0012)"
NEW_ST = "## Milestone 9 - done (official Microsoft GraphRAG run + own baseline)"
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def load(name):
    p = os.path.join(OUT, "output", f"{name}.parquet")
    return pd.read_parquet(p) if os.path.isfile(p) else None


frames = {n: load(n) for n in ("documents", "text_units", "entities", "relationships", "communities", "community_reports")}
if frames["entities"] is None or frames["relationships"] is None:
    print("REFUSED - no entities/relationships parquet in data\\graphrag_outputs\\output: has `graphrag index` finished?")
    sys.exit(1)
E, R = frames["entities"], frames["relationships"]
C, P, T, D = frames["communities"], frames["community_reports"], frames["text_units"], frames["documents"]
cache_files = [f for f in glob.glob(os.path.join(OUT, "cache", "**", "*"), recursive=True) if os.path.isfile(f)]
by_dir = {}
for f in cache_files:
    d = os.path.basename(os.path.dirname(f))
    by_dir[d] = by_dir.get(d, 0) + 1

lines = []
lines.append(f"documents {len(D) if D is not None else 'n/a'} | text units {len(T) if T is not None else 'n/a'} | "
             f"entities {len(E)} | relationships {len(R)} | communities {len(C) if C is not None else 'n/a'} | "
             f"community reports {len(P) if P is not None else 'n/a'}")
lines.append(f"cached LLM/embedding responses on disk: {len(cache_files)}  by folder: {by_dir}")
types = E["type"].value_counts()
lines.append("entity types: " + ", ".join(f"{k}={v}" for k, v in types.items()))
top = E.sort_values(["degree", "frequency"], ascending=False).head(10)
lines.append("top 10 entities by degree: " + "; ".join(f"{r.title} [{r.type}] deg {r.degree}" for r in top.itertuples()))
ids = E["title"].astype(str)
lines.append(f"entities whose title contains a CVE id: {int(ids.str.contains(CVE).sum())}; an ATT&CK id: {int(ids.str.contains(TECH).sum())}")
lines.append(f"relationship columns: {list(R.columns)} (no relationship-type column unless listed)")
lines.append(f"relationship weight: min {R['weight'].min()}, median {R['weight'].median()}, max {R['weight'].max()}")
if C is not None:
    lines.append("communities per level: " + ", ".join(f"level {k}: {v}" for k, v in C["level"].value_counts().sort_index().items()))
if P is not None and len(P):
    lines.append("community report titles (by rank): " + "; ".join(
        f"{r.title} (rank {r.rank})" for r in P.sort_values("rank", ascending=False).head(8).itertuples()))
print("\n".join(lines))

date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
report = os.path.join("docs", f"CHANGE_REPORT_{date}_M9b_ms_graphrag.md")
write(report, f"""# Change report - Milestone 9b: official Microsoft GraphRAG run

GraphRAG 3.3.0 in `.venv-graphrag`, chat model Groq openai/gpt-oss-20b, local bge-small embeddings, settings in
`graphrag_engine/indexing/ms/settings.yaml`, output in `data/graphrag_outputs/output` (not committed).
The real schema is recorded in `docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md`.

## Result of the run
""" + "\n".join(f"- {l}" for l in lines) + """

## What Milestone 10 must handle (read from the real output)
- Entity `type` values come from the prompt's list, upper-cased (for example THREAT_ACTOR); there are no canonical ids.
- Relationships carry source and target TITLES, a description and a weight, but no relationship type.
- Every entity, relationship and text unit keeps `text_unit_ids`; text units map back to our chunk ids through `input_manifest.json`.
""")
print("wrote", report)

entry = f"""{MARK_CL}
- Ran the official `graphrag` 3.3.0 (own venv, Groq gpt-oss-20b, local bge-small embeddings) and inspected the real output schema.
- New: `scripts/prepare_ms_graphrag_input.py`, `serve_local_embeddings.py`, `check_ms_graphrag_setup.py`, `inspect_graphrag_output.py`, `apply_milestone_9b_docs.py`; `docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md`.

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
    if OLD_ST in t:
        bullet = (f"\n- Official GraphRAG run on {len(D) if D is not None else '?'} advisory: {len(E)} entities, {len(R)} relationships, "
                  f"{len(C) if C is not None else '?'} communities (`{report.replace(os.sep, '/')}`); real schema in `docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md`.")
        t = t.replace(OLD_ST, NEW_ST + bullet, 1)
        write("PROJECT_STATUS.md", t)
        print("updated PROJECT_STATUS.md")
    else:
        print("PROJECT_STATUS.md: nothing to change (already closed, or heading not found)")
print("RESULT: OK")
