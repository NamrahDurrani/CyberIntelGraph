# Change report - Milestone 8: hybrid retrieval

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

## Results (88 probes, 2734 chunks, report `hybrid_eval_20261114T052658Z.json`)
Doc hit = a retrieved chunk comes from an advisory that really contains the answer.
Needle hit = the retrieved chunk itself contains the CVE / technique id.
The identifier probes are generated from the same structured fields that `hybrid_ids` looks up, so
compare `hybrid` with `hybrid_ids` to see how much of any gain comes from that lookup.

### cve probes (n=40)
| Mode | Doc hit @ 1 / 3 / 5 / 10 | Doc MRR | Needle hit @ 1 / 3 / 5 / 10 |
|---|---|---|---|
| dense | 0.425 / 0.55 / 0.6 / 0.7 | 0.502 | 0.275 / 0.375 / 0.45 / 0.525 |
| bm25 | 0.975 / 0.975 / 0.975 / 0.975 | 0.975 | 0.975 / 0.975 / 0.975 / 0.975 |
| hybrid | 0.7 / 0.75 / 0.825 / 1.0 | 0.767 | 0.7 / 0.75 / 0.825 / 1.0 |
| hybrid_ids | 1.0 / 1.0 / 1.0 / 1.0 | 1.0 | 1.0 / 1.0 / 1.0 / 1.0 |

### technique probes (n=40)
| Mode | Doc hit @ 1 / 3 / 5 / 10 | Doc MRR | Needle hit @ 1 / 3 / 5 / 10 |
|---|---|---|---|
| dense | 0.025 / 0.175 / 0.25 / 0.5 | 0.137 | 0.0 / 0.0 / 0.0 / 0.025 |
| bm25 | 0.8 / 0.85 / 0.85 / 0.85 | 0.825 | 0.675 / 0.85 / 0.85 / 0.85 |
| hybrid | 0.125 / 0.225 / 0.25 / 0.4 | 0.195 | 0.025 / 0.025 / 0.025 / 0.1 |
| hybrid_ids | 1.0 / 1.0 / 1.0 / 1.0 | 1.0 | 1.0 / 1.0 / 1.0 / 1.0 |

### curated probes (n=3)
| Mode | Doc hit @ 1 / 3 / 5 / 10 | Doc MRR |
|---|---|---|
| dense | 0.667 / 1.0 / 1.0 / 1.0 | 0.833 |
| bm25 | 0.667 / 1.0 / 1.0 / 1.0 | 0.833 |
| hybrid | 1.0 / 1.0 / 1.0 / 1.0 | 1.0 |
| hybrid_ids | 1.0 / 1.0 / 1.0 / 1.0 | 1.0 |

### titles probes (n=5)
| Mode | Doc hit @ 1 / 3 / 5 / 10 | Doc MRR |
|---|---|---|
| dense | 0.8 / 1.0 / 1.0 / 1.0 | 0.9 |
| bm25 | 0.8 / 1.0 / 1.0 / 1.0 | 0.9 |
| hybrid | 1.0 / 1.0 / 1.0 / 1.0 | 1.0 |
| hybrid_ids | 1.0 / 1.0 / 1.0 / 1.0 | 1.0 |

Baseline check: [PASS] dense mode reproduces the Milestone 7 baseline (rag_eval_20261113T133057Z.json)
