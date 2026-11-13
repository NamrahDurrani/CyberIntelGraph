# Decision 0008 - Naive RAG baseline (Milestone 7)

Status: accepted - 2026-11-13

## Decisions
1. **Embeddings: local `BAAI/bge-small-en-v1.5`** (about 130 MB, CPU, 384 dims) instead of
   BGE-M3 (over 2 GB). The guide allows "BGE-M3 or a compatible" model; disk space (about
   5 GB free) ruled out BGE-M3 and a hosted service needs no key for this step if kept local.
   Chunk text embedded = `embedding_text` (heading path + text). Inputs over 512 tokens are truncated
   (affects only the longest table chunks).
2. **Index: exact flat search over a NumPy matrix** (4 MB for 2,734 chunks), saved as
   `vectors.npy` + `ids.json` + `manifest.json` (model, dim, SHA-256 of the chunk file). No FAISS
   or server needed at this size; the class API matches what FAISS/a database would offer.
   A stale index (chunk file changed) is detected by hash.
3. **LLM: Groq `openai/gpt-oss-20b`, free tier**, via Groq's OpenAI-compatible endpoint using
   only the standard library. Defaults: top-5 chunks, <= 300 words per chunk in the prompt,
   `max_completion_tokens` 1500, `reasoning_effort` low, retries on 429/5xx honouring
   `retry-after`. The model sits behind `complete(system, user)`, so it can be swapped.
4. **Grounded answers:** the system prompt allows only the supplied passages, requires a
   `[chunk_id]` after every claim, and a fixed "cannot find" sentence otherwise. Every answer is
   checked: cited ids must be among the retrieved chunks; uncited answers and unknown ids are flagged.
5. **Semantic search only, deliberately.** Exact identifiers (CVE, T-ids) are weak spots for
   embeddings. `rag/evaluate.py` measures this (doc hit vs needle hit) so Milestone 8's
   hybrid retrieval is compared with a real baseline, not an assumption.
6. **Secrets:** `GROQ_API_KEY` from the environment or a Git-ignored `.env`; never logged,
   never in error messages, never committed.

## Consequences
Free-tier rate limits make many LLM calls slow; evaluation is therefore retrieval-only
(no LLM calls). End-to-end answers are demonstrated with `rag/ask.py`.
