# 11 - Naive RAG baseline (Milestone 7)

```
advisory_chunks.jsonl -> embed (bge-small) -> data/index/naive_rag/ (vectors.npy, ids.json, manifest.json)
question -> embed -> top-k chunks -> prompt (+ citation rules) -> Groq gpt-oss-20b -> answer + checked citations
```

| Path | Role |
|---|---|
| `rag/embedder.py` | Local embedding model (swappable) |
| `rag/index.py` | Flat vector index: build, save, load, search, staleness check |
| `rag/retrieve.py` | Question -> ranked chunks with metadata |
| `rag/llm.py` | Groq client (retries, key handling, no secrets in errors) |
| `rag/answer.py` | Prompt, LLM call, citation verification |
| `rag/build_index.py`, `rag/ask.py`, `rag/evaluate.py` | Command-line tools |
| `scripts/check_rag_index.py` | Independent index check (no model, no network) |

Run:
```
pip install sentence-transformers
python rag/build_index.py
python scripts/check_rag_index.py
python rag/evaluate.py
$env:GROQ_API_KEY="<your key>"          # this window only
python rag/ask.py "Which malware was used against healthcare in AA20-302A?"
python rag/ask.py "..." --no-llm        # retrieval only, no API call
```
