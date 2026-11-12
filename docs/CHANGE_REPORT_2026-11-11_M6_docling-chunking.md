# Change report - Milestone 6: Docling parsing and chunking

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
| Parser | docling 2.150.0 |
| Documents chunked / failed | 53 / 0 |
| Chunks | 2734 |
| Words per chunk (min / median / max) | 1 / 89.0 / 531 |
| Parameters | max 250 words, min 8 words |
| Tables | 547 |
| Tiny chunks dropped | 185 |
| Skipped item types | {'picture': 68} |

Failed documents: none

Raw and processed source files were only read, never modified.
