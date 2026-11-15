# Decision 0012 - Milestone 9 uses the official Microsoft GraphRAG package

Status: accepted - 2026-11-15. Partly supersedes decision 0011.

## Context
The roadmap defines Milestone 9 as "Microsoft GraphRAG indexing": run GraphRAG, inspect its real output
schema, and, if the package conflicts with the main environment, use its own venv and record that here.
Decision 0011 replaced the package with our own implementation of the method. That was my call, and it
did not match the roadmap; the owner asked for real GraphRAG indexing.

## Decisions
1. Run the official `graphrag` 3.3.0 (pinned in `requirements-graphrag.txt`) in a dedicated venv,
   `.venv-graphrag`. Measured: the install is about 1.2 GB and resolves on Python 3.12; its pins
   (numpy 2.x, pandas 3.x, pyarrow, LanceDB, LiteLLM) are kept away from the main environment.
2. Chat model: Groq `openai/gpt-oss-20b` through GraphRAG's LiteLLM layer (provider `groq`).
   Embeddings: the local bge-small model behind `scripts/serve_local_embeddings.py`, an OpenAI-compatible
   endpoint (tested with the openai SDK and LiteLLM). Groq has no embeddings API.
3. Free-tier protection in `settings.yaml`: one request at a time, a sliding-window rate limit, chunks of
   500 tokens, no gleaning pass, community-report input capped at 2,500 tokens. The limit values are
   conservative guesses until checked against the account's real limits.
4. Same five advisories as our own pipeline (`scripts/prepare_ms_graphrag_input.py`), so the two
   extractions can be compared. `input_manifest.json` maps GraphRAG text units back to our chunk ids.
5. The real output schema is inspected with `scripts/inspect_graphrag_output.py` and recorded in
   `docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md` - no column names assumed (Milestone 9 done-criterion).
6. Our own pipeline (`graphrag_engine/indexing/*.py`) stays as a grounded-extraction baseline: its grounding checks and
   canonical linking are reused for Milestone 10 and it is the comparison in Milestone 17.
