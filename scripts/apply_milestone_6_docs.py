"""Write the Milestone 6 change report and update CHANGELOG.md / PROJECT_STATUS.md
from the REAL manifest. Run after documents\\build_chunks.py. Idempotent."""
import json
import os
import sys

MARK = "Milestone 6"
MAN = os.path.join("data", "processed", "advisory_chunks_manifest.json")
REPORT = os.path.join("docs", "CHANGE_REPORT_2026-11-11_M6_docling-chunking.md")


def read(p):
    with open(p, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(p, t):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)


if not os.path.exists(MAN):
    print("REFUSED - run python documents\\build_chunks.py first")
    sys.exit(1)
m = json.loads(read(MAN))
if m["documents_chunked"] == 0:
    print("REFUSED - no documents were chunked")
    sys.exit(1)
w = m["words_per_chunk"]
fails = m["failed_documents"]
print(f"documents chunked {m['documents_chunked']} | failed {m['documents_failed']} | chunks {m['chunks']} | "
      f"words/chunk min {w['min']} median {w['median']} max {w['max']}")

report = f"""# Change report - Milestone 6: Docling parsing and chunking

## What was added
- `documents/` package: `parse.py` (Docling adapter, HTML only, no AI models), `chunking.py`
  (parser-independent chunker), `build_chunks.py` (CLI).
- `scripts/check_chunks_output.py`, `scripts/apply_milestone_6_docs.py`
- tests: `test_chunking.py`, `test_build_chunks.py`, `test_docling_real.py`
- docs: decision 0007, pipeline page 10.
- `requirements.txt`: `docling`.

## Result (from data/processed/advisory_chunks_manifest.json)
| Item | Value |
|---|---|
| Parser | {m['parser']} {m['parser_version']} |
| Documents chunked / failed | {m['documents_chunked']} / {m['documents_failed']} |
| Chunks | {m['chunks']} |
| Words per chunk (min / median / max) | {w['min']} / {w['median']} / {w['max']} |
| Parameters | max {m['params']['max_words']} words, min {m['params']['min_words']} words |
| Tables | {m['stats'].get('tables', 0)} |
| Tiny chunks dropped | {m['stats'].get('dropped_tiny', 0)} |
| Skipped item types | {m['skipped_item_labels']} |

Failed documents: {fails if fails else 'none'}

Raw and processed source files were only read, never modified.
"""
write(REPORT, report)
print("wrote", REPORT)

entry = f"""## Milestone 6 - 2026-11-11 - Docling parsing and advisory chunking
- Added `documents/` (Docling HTML parser, chunker, builder), checker and tests.
- Output: `data/processed/advisory_chunks.jsonl` - {m['chunks']} chunks from {m['documents_chunked']} advisories.
- Each chunk keeps doc id, heading path, source URL, date and raw-file SHA-256.

"""
for path in ("CHANGELOG.md", "PROJECT_STATUS.md"):
    if not os.path.exists(path):
        print(f"[WARN] {path} not found, skipped")
        continue
    t = read(path)
    if MARK in t:
        print(f"{path}: already has a Milestone 6 entry, skipped")
        continue
    if path == "CHANGELOG.md":
        i = t.find("\n## ")
        t = (t[:i + 1] + entry + t[i + 1:]) if i != -1 else t.rstrip("\n") + "\n\n" + entry
    else:
        t = t.rstrip("\n") + (f"\n\n## Milestone 6 - done\n- {m['chunks']} advisory chunks from "
                              f"{m['documents_chunked']} documents (Docling HTML).\n- Next: Milestone 7 (naive RAG).\n")
    write(path, t)
    print("updated", path)
print("RESULT: OK")
