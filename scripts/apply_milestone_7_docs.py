"""Write the Milestone 7 change report and update CHANGELOG.md / PROJECT_STATUS.md from
the REAL index manifest and the latest retrieval evaluation. Also removes the stale
"Milestone 5/6/7" lines from the Pending list in PROJECT_STATUS.md. Idempotent."""
import glob
import json
import os
import re
import sys

IDX = os.path.join("data", "index", "naive_rag", "manifest.json")
REPORT = os.path.join("docs", "CHANGE_REPORT_2026-11-13_M7_naive-rag.md")
MARK_CL = "## Milestone 7 - naive RAG baseline"
MARK_ST = "## Milestone 7 - done"


def read(p):
    with open(p, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(p, t):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)


evals = sorted(glob.glob(os.path.join("outputs", "reports", "rag_eval_*.json")))
if not os.path.exists(IDX) or not evals:
    print("REFUSED - build the index (python rag\\build_index.py) and run python rag\\evaluate.py first")
    sys.exit(1)
m = json.loads(read(IDX))
ev = json.loads(read(evals[-1]))
ks = [str(k) for k in ev["k_values"]]

rows = []
for kind, e in ev["kinds"].items():
    d = " / ".join(str(e["doc_hit@k"][k]) for k in ks)
    n = " / ".join(str(e["needle_hit@k"][k]) for k in ks) if "needle_hit@k" in e else "n/a"
    rows.append(f"| {kind} | {e['n']} | {d} | {e['doc_mrr']} | {n} |")
table = ("| Probe | n | Doc hit @ " + " / ".join(ks) + " | Doc MRR | Needle hit @ " + " / ".join(ks) + " |\n"
         "|---|---|---|---|---|\n" + "\n".join(rows))
print(f"index: {m['count']} vectors, dim {m['dim']}, model {m['model']}")
print(table)

report = f"""# Change report - Milestone 7: naive RAG baseline

## Pipeline
advisory chunks -> embeddings ({m['model']}, dim {m['dim']}) -> exact vector index
({m['count']} chunks) -> top-k retrieval -> Groq gpt-oss-20b answer with [chunk_id] citations.
Semantic search only, on purpose: Milestone 8 adds keyword (BM25) search and is measured against this.

## Added
- `rag/` package: embedder, flat vector index, retriever, Groq client, grounded answer step
  with citation checking, CLIs (`build_index.py`, `ask.py`, `evaluate.py`).
- `config/rag_eval_questions.json` (curated retrieval questions)
- `scripts/check_rag_index.py`, `scripts/apply_milestone_7_docs.py`
- `tests/unit/test_rag.py`; docs: decision 0008, pipeline page 11.
- `requirements.txt`: `sentence-transformers`, `numpy`.

## Index
Model {m['model']} | dim {m['dim']} | chunks {m['count']} | text field `{m['text_field']}` | built {m['created_at']}

## Retrieval baseline ({ev['probes']} probes, report `{os.path.basename(evals[-1])}`)
{table}

Doc hit = a retrieved chunk comes from an advisory that really contains the answer.
Needle hit = the retrieved chunk itself contains the CVE / technique id (identifier probes only).
A gap between the two is the weakness of pure semantic search that Milestone 8 must close.

The API key is read from the environment or a Git-ignored `.env`; it is never stored in the repository.
"""
write(REPORT, report)
print("wrote", REPORT)

entry = f"""{MARK_CL}
- Added `rag/`: local embeddings ({m['model']}), exact vector index over {m['count']} chunks, Groq `openai/gpt-oss-20b` answers with checked [chunk_id] citations.
- Added retrieval evaluation (identifier probes + curated questions) as the baseline for Milestone 8.

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
    # PROJECT_STATUS.md: drop finished milestones from the Pending list, then add the section
    out, in_pending, removed = [], False, []
    for line in t.splitlines(keepends=True):
        if line.startswith("## "):
            in_pending = line.strip().lower().startswith("## pending")
        if in_pending and re.match(r"^- Milestone (5|6|7)\b", line):
            removed.append(line.strip()[:70])
            continue
        out.append(line)
    t2 = "".join(out)
    if MARK_ST not in t2:
        t2 = t2.rstrip("\n") + (f"\n\n{MARK_ST}\n- Naive RAG baseline: {m['count']} chunks indexed, Groq gpt-oss-20b answers with citations.\n"
                                "- Next: Milestone 8 (hybrid retrieval: BM25 + semantic).\n")
    if t2 != t:
        write(path, t2)
        print("updated PROJECT_STATUS.md; removed from Pending:", removed or "nothing")
    else:
        print("PROJECT_STATUS.md: already up to date")
print("RESULT: OK")
