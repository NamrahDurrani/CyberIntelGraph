"""Write the Milestone 8 change report and update CHANGELOG.md / PROJECT_STATUS.md from the
REAL comparison run (outputs/reports/hybrid_eval_*.json). Idempotent. Refuses to run before
`python rag\\compare.py` has produced a report."""
import glob
import json
import os
import re
import sys

MARK_CL = "## Milestone 8 - hybrid retrieval"
MARK_ST = "## Milestone 8 - done"


def read(p):
    with open(p, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(p, t):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)


reports = sorted(glob.glob(os.path.join("outputs", "reports", "hybrid_eval_*.json")))
if not reports:
    print("REFUSED - run python rag\\compare.py first (it writes outputs\\reports\\hybrid_eval_*.json)")
    sys.exit(1)
ev = json.loads(read(reports[-1]))
modes = list(ev["modes"])
first = ev["modes"][modes[0]]
ks = [str(k) for k in first["k_values"]]
date = ev["generated_at"][:10]
REPORT = os.path.join("docs", f"CHANGE_REPORT_{date}_M8_hybrid-rag.md")

tables = []
for kind, e0 in first["kinds"].items():
    needle = "needle_hit@k" in e0
    head = "| Mode | Doc hit @ " + " / ".join(ks) + " | Doc MRR |" + (" Needle hit @ " + " / ".join(ks) + " |" if needle else "")
    sep = "|---|---|---|" + ("---|" if needle else "")
    rows = []
    for m in modes:
        e = ev["modes"][m]["kinds"][kind]
        row = f"| {m} | " + " / ".join(str(e["doc_hit@k"][k]) for k in ks) + f" | {e['doc_mrr']} |"
        if needle:
            row += " " + " / ".join(str(e["needle_hit@k"][k]) for k in ks) + " |"
        rows.append(row)
    tables.append(f"### {kind} probes (n={e0['n']})\n{head}\n{sep}\n" + "\n".join(rows))
tables_md = "\n\n".join(tables)
print(tables_md)

report = f"""# Change report - Milestone 8: hybrid retrieval

## What changed
- New `rag/bm25.py`: identifier-preserving BM25 keyword search (no new dependency).
- New `rag/hybrid.py`: `HybridRetriever` with four modes - `dense` (Milestone 7), `bm25`, `hybrid`
  (dense + BM25 merged by Reciprocal Rank Fusion) and `hybrid_ids` (hybrid + identifier lookup tier).
- New `rag/compare.py`: runs all modes on the same probes and writes `outputs/reports/hybrid_eval_*.json`.
- `rag/ask.py`: `--mode` option, default `hybrid_ids`; prints how each passage was found (`via ...`).
- `rag/answer.py`: records `via` for each retrieved passage (no other change).
- `rag/evaluate.py`: probe kinds without an identifier no longer get needle-hit columns.
- Fix `rag/index.py`: ties are now broken by row for real (argpartition did not guarantee it).
- Fix `scripts/check_rag_index.py`: the self-retrieval check now allows identical twin chunks, and
  the near-identical-vector warning used a wrong formula (it subtracted a sample count from the
  full count).
- Tests: `tests/unit/test_hybrid.py`. Config: `config/hybrid_eval_questions.json`.

## Results ({ev['probes']} probes, {ev['chunks']} chunks, report `{os.path.basename(reports[-1])}`)
Doc hit = a retrieved chunk comes from an advisory that really contains the answer.
Needle hit = the retrieved chunk itself contains the CVE / technique id.
The identifier probes are generated from the same structured fields that `hybrid_ids` looks up, so
compare `hybrid` with `hybrid_ids` to see how much of any gain comes from that lookup.

{tables_md}

Baseline check: {ev.get('baseline_check') or 'n/a'}
"""
write(REPORT, report)
print("wrote", REPORT)

entry = f"""{MARK_CL}
- Added `rag/bm25.py`, `rag/hybrid.py`, `rag/compare.py`: BM25 keyword search fused with the embedding search (RRF) plus an identifier lookup tier; `ask.py --mode` (default `hybrid_ids`).
- Fixed deterministic tie-breaking in `rag/index.py` and two faulty checks in `scripts/check_rag_index.py`.

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
        write(path, (t[:i + 1] + entry + t[i + 1:]) if i != -1 else t.rstrip("\n") + "\n\n" + entry)
        print("updated CHANGELOG.md")
        continue
    out, in_pending, removed = [], False, []
    for line in t.splitlines(keepends=True):
        if line.startswith("## "):
            in_pending = line.strip().lower().startswith("## pending")
        if in_pending and re.match(r"^- Milestone 8\b", line):
            removed.append(line.strip()[:70])
            continue
        out.append(line)
    t2 = "".join(out)
    stale = "- Next: Milestone 8 (hybrid retrieval: BM25 + semantic).\n"
    if MARK_ST not in t2 and stale in t2:
        t2 = t2.replace(stale, "")            # that "next" item is done now
    if MARK_ST not in t2:
        t2 = t2.rstrip("\n") + (f"\n\n{MARK_ST}\n- Hybrid retrieval (dense + BM25 + identifier lookup) measured against the Milestone 7 baseline; see "
                                f"`{REPORT.replace(os.sep, '/')}`.\n- Next: Milestone 9 (see the roadmap in the project report).\n")
    if t2 != t:
        write(path, t2)
        print("updated PROJECT_STATUS.md; removed from Pending:", removed or "nothing")
    else:
        print("PROJECT_STATUS.md: already up to date")
print("RESULT: OK")
