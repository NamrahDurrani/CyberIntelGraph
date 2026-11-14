"""Add the Milestone 8.1 entry to CHANGELOG.md (idempotent)."""
import os

MARK = "## Milestone 8.1 - identifier-weighted fusion"
ENTRY = f"""{MARK}
- `rag/hybrid.py`: keyword search votes `id_weight` (3x) in rank fusion when the question names a CVE or technique id.
- `rag/compare.py`: modes accept `mode:weight` (e.g. `hybrid:1,hybrid:3,hybrid:5`).
- New `scripts/diagnose_bm25_misses.py`: classifies keyword-search misses as data, tokenizer or ranking problems.
- Docs: decision 0010, section 7 of `docs/pipeline/12_hybrid_rag.md`.

"""
p = "CHANGELOG.md"
if not os.path.exists(p):
    raise SystemExit("CHANGELOG.md not found")
with open(p, encoding="utf-8", newline="") as fh:
    t = fh.read()
if MARK in t:
    print("CHANGELOG.md: entry already present, skipped")
else:
    i = t.find("\n## ")
    t = (t[:i + 1] + ENTRY + t[i + 1:]) if i != -1 else t.rstrip("\n") + "\n\n" + ENTRY
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)
    print("updated CHANGELOG.md")
