# Decision 0009 - Hybrid retrieval (Milestone 8)

Status: accepted - 2026-11-13

## Decisions
1. **Keyword search is our own BM25** (pure Python + NumPy), not a library. No install on a disk-limited machine, and the tokenizer is ours: identifiers (CVE, CWE, ATT&CK ids, advisory ids) stay whole.
2. **Merge with Reciprocal Rank Fusion** (k = 60, depth 100, equal weights): no score calibration between cosine and BM25.
3. **Identifier lookup tier**, using the structured `cve_ids`, `technique_ids` and `doc_id` fields from Milestone 6. Exact matches +0.10, related (parent / sub-technique, advisory id) +0.05 - both above the 0.0328 maximum an RRF pair can award, so matches lead. No match = identical to `hybrid`.
4. **Four modes kept side by side** (`dense`, `bm25`, `hybrid`, `hybrid_ids`) so each component is measured; `ask.py` defaults to `hybrid_ids` because the tier cannot change questions without identifiers.
5. **BM25 is built at start-up** from the chunk file (about a second), so there is no second index to go stale.
6. **Fixed two Milestone 7 defects**: non-deterministic tie-breaking in `VectorIndex.search`, and two faulty checks in `scripts/check_rag_index.py`.
7. **Evaluation caveat recorded**: identifier probes share their source fields with the lookup tier; `hybrid` vs `hybrid_ids` is the control.
