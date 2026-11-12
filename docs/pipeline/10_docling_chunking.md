# 10 - Docling parsing and chunking (Milestone 6)

HTML advisories -> Docling -> Blocks (heading/text/table) -> chunker -> JSONL.

| Path | Role |
|---|---|
| `documents/parse.py` | Docling adapter; maps Docling items to Blocks |
| `documents/chunking.py` | Chunk rules (see decision 0007) |
| `documents/build_chunks.py` | Reads processed advisories + raw HTML, writes chunks + manifest |
| `scripts/check_chunks_output.py` | Independent output check |
| `scripts/apply_milestone_6_docs.py` | Change report + CHANGELOG/STATUS from the manifest |

Run:
```
python -m unittest discover -s tests\unit
python documents\build_chunks.py --limit 3     # quick trial
python documents\build_chunks.py               # all advisories
python scripts\check_chunks_output.py
python scripts\apply_milestone_6_docs.py
```
Outputs: `data/processed/advisory_chunks.jsonl`, `advisory_chunks_manifest.json`.
