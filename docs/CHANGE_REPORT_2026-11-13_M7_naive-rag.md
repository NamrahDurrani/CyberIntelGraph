# Change report - Milestone 7: naive RAG baseline

## Pipeline
advisory chunks -> embeddings (BAAI/bge-small-en-v1.5, dim 384) -> exact vector index
(2734 chunks) -> top-k retrieval -> Groq gpt-oss-20b answer with [chunk_id] citations.
Semantic search only, on purpose: Milestone 8 adds keyword (BM25) search and is measured against this.

## Added
- `rag/` package: embedder, flat vector index, retriever, Groq client, grounded answer step
  with citation checking, CLIs (`build_index.py`, `ask.py`, `evaluate.py`).
- `config/rag_eval_questions.json` (curated retrieval questions)
- `scripts/check_rag_index.py`, `scripts/apply_milestone_7_docs.py`
- `tests/unit/test_rag.py`; docs: decision 0008, pipeline page 11.
- `requirements.txt`: `sentence-transformers`, `numpy`.

## Index
Model BAAI/bge-small-en-v1.5 | dim 384 | chunks 2734 | text field `embedding_text` | built 2026-11-13T07:43:35.770637+00:00

## Retrieval baseline (83 probes, report `rag_eval_20261113T133057Z.json`)
| Probe | n | Doc hit @ 1 / 3 / 5 / 10 | Doc MRR | Needle hit @ 1 / 3 / 5 / 10 |
|---|---|---|---|---|
| cve | 40 | 0.425 / 0.55 / 0.6 / 0.7 | 0.502 | 0.275 / 0.375 / 0.45 / 0.525 |
| technique | 40 | 0.025 / 0.175 / 0.25 / 0.5 | 0.137 | 0.0 / 0.0 / 0.0 / 0.025 |
| curated | 3 | 0.667 / 1.0 / 1.0 / 1.0 | 0.833 | n/a |

Doc hit = a retrieved chunk comes from an advisory that really contains the answer.
Needle hit = the retrieved chunk itself contains the CVE / technique id (identifier probes only).
A gap between the two is the weakness of pure semantic search that Milestone 8 must close.

The API key is read from the environment or a Git-ignored `.env`; it is never stored in the repository.
