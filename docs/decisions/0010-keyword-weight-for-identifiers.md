# Decision 0010 - Keyword weight for identifier questions (Milestone 8.1)

Status: accepted - 2026-11-14

Context: the first real comparison showed plain `hybrid` (equal weights) at 0.125 technique doc-hit@1
against 0.80 for BM25 alone.

Decision: when a question contains a CVE or ATT&CK technique id, BM25 votes `id_weight` = 3 times as
strongly in rank fusion. Advisory ids alone and questions with no identifier keep weight 1. The value 3 is a
starting point to be judged from `rag/compare.py` (modes `hybrid:1`, `hybrid:3`, `hybrid:5`), not a tuned constant.

Also: `scripts/diagnose_bm25_misses.py` classifies keyword-search misses (data, tokenizer or ranking) before any
tokenizer change is made.
