# 12 - Hybrid retrieval (Milestone 8): everything that changed and why

## 1. The problem, as a library
Milestone 7 gave the project a librarian who understands **topics**. Ask for "the book about
ransomware in hospitals" and she finds it. Ask for "the book with serial number CVE-2024-3400" and she
hands you books about vulnerabilities in general, because to her an identifier is just an unusual word.
Your own run showed it: technique-id questions found the right advisory 2.5% of the time at top-1,
and the live `ask.py` test for CVE-2024-3400 returned five unrelated advisories.

Milestone 8 adds a **catalog desk** that matches exact text, and a rule for combining the two.

```
question --> meaning search (embeddings)  --\
         --> keyword search (BM25)         ---> merge (RRF) --> + identifier bonus --> top-k --> LLM
         --> identifiers in the question  --/
```

## 2. Two bugs found in Milestone 7 (and fixed)
Your `check_rag_index.py` printed one FAIL and one WARN. Neither meant a broken index.

| Symptom | Real cause | Fix |
|---|---|---|
| FAIL: sampled chunks do not retrieve themselves first | 23 chunks have identical text to another chunk (your duplicate check: 2,711 unique of 2,734). Identical twins tie for first place, and `argpartition` in `VectorIndex.search` does not break ties by row, although its docstring said so. In a simulation it returned the lower row only about half the time. | `search` now orders fully by (score, row). The check now passes when no *other* chunk out-scores the sample (ties allowed) and prints how many twin chunks exist. |
| WARN: 2,194 near-identical vectors | A formula error: the check subtracted the unique count of a sample of about 547 from the size of the *whole* index (2,734 - 540 = 2,194). | It now compares the sample with its own unique count. |

I earlier suggested the WARN was only a threshold issue. That was wrong: it was this formula.

## 3. What was built
| Path | Role |
|---|---|
| `rag/bm25.py` | Keyword search. Its tokenizer keeps `CVE-2024-3400`, `CWE-79`, `T1059.001` (and its parent `T1059`) and `AA20-302A` as single tokens. Built in memory at start-up, so there is no new index file to go stale. No new install. |
| `rag/hybrid.py` | `HybridRetriever` with four modes: `dense` (Milestone 7), `bm25`, `hybrid`, `hybrid_ids`. Same `retrieve(question, k)` interface as before. |
| `rag/compare.py` | Runs all four modes on the same questions and prints one table. Writes `outputs/reports/hybrid_eval_*.json`. |
| `rag/ask.py` | New `--mode` option (default `hybrid_ids`). Each source line says how it was found, e.g. `via dense#3 bm25#1 id:CVE-2024-3400`. |
| `scripts/apply_milestone_8_docs.py` | Writes the change report with your real numbers, updates `CHANGELOG.md` and `PROJECT_STATUS.md`. Refuses to run before `compare.py`. |
| `config/hybrid_eval_questions.json` | Five plain-language "which advisory covers ..." questions, as a guard that keyword search does not hurt ordinary questions. |
| `tests/unit/test_hybrid.py` | 23 new tests. |

Small edits: `rag/answer.py` records `via`; `rag/evaluate.py` no longer prints needle columns for probe kinds that have no identifier.

## 4. How the merge works (Reciprocal Rank Fusion)
Each list awards a chunk `1 / (60 + rank)` points; points add up. Cosine scores and BM25 scores are never compared directly.

- Chunk A: meaning rank 3, keyword rank 1 -> 1/63 + 1/61 = 0.0323
- Chunk B: meaning rank 1, not in the keyword list -> 1/61 = 0.0164

A wins because both searches like it. Like asking two librarians and trusting the book both name.

**Identifier bonus (`hybrid_ids` only).** If the question contains an identifier, chunks whose structured fields contain it get a bonus bigger than the most any chunk can earn from the two lists (0.0328):
- exact CVE / technique match: +0.10
- related: +0.05 (the parent or sub-techniques of a technique, or any chunk of advisory `AA20-302A`)

Inside a bonus group the normal merged order decides. If the identifier is in no chunk, the result is exactly `hybrid`.

## 5. How to read the results
- `dense` row = your Milestone 7 baseline. `compare.py` checks that it matches the earlier report.
- `bm25` and `hybrid` rows are the cleanest evidence, because they use only the chunk text.
- `hybrid_ids` uses the same structured fields that generated the identifier probes, so part of its gain is built in. The gap between `hybrid` and `hybrid_ids` shows how much.
- The `titles` rows check that ordinary semantic questions did not get worse. Five questions is a small guard, so add more.

## 6. Honest limits
- Written and tested on a synthetic mini-corpus: 23 new unit tests plus the 20 from Milestone 7, but **not run against the real 2,734 chunks or the real embedding model**. Real numbers come from your machine.
- My unit tests caught one bug before delivery: the first tokenizer also split identifiers into loose pieces (`2024`, `3400`), which would have added noise.
- Rank-fusion constants (60, depth 100, bonuses) are standard defaults, not tuned.
