# 14 - Milestone 9, the real thing: Microsoft GraphRAG on your five advisories

## 1. Why this exists
Your roadmap says Milestone 9 is **Microsoft GraphRAG indexing**: run GraphRAG itself and look at what it really produces.
My first Milestone 9 built our own pipeline of the same method and called it "GraphRAG-style". You were right to push
back: that did not do what the roadmap asks. It is kept as a baseline, and this is the official run.

Think of it as hiring Microsoft's own detective agency but letting it use **your** filing room:
- the agency (GraphRAG 3.3.0) does the reading, wall-pinning, clustering and briefing itself;
- the analyst brain is Groq's gpt-oss-20b (same as everywhere in your project);
- the library card catalogue (embeddings) is your local bge-small model, served on your own PC, because Groq has none.

```
advisories (5 text files) --GraphRAG--> text units --LLM--> entities + relationships --Leiden--> communities
        --LLM--> community reports        embeddings: GraphRAG --> local server (bge-small) --> LanceDB
output: data\graphrag_outputs\output\*.parquet  (+ graph.graphml)
```

## 2. What is in this package
| Path | Role |
|---|---|
| `graphrag_engine/indexing/ms/settings.yaml` | GraphRAG configuration: Groq chat model, local embeddings, cyber entity types, free-tier protections. Validated with GraphRAG's own config loader. |
| `scripts/prepare_ms_graphrag_input.py` | writes one text file per advisory (same 5 as before) and `input_manifest.json` (our chunk ids with character spans) |
| `scripts/serve_local_embeddings.py` | OpenAI-compatible embeddings server around bge-small; tested against the openai SDK and LiteLLM |
| `scripts/check_ms_graphrag_setup.py` | preflight: install, config, key (never printed), input, embeddings server, disk, tiktoken; `--init-prompts` copies GraphRAG's default prompt files |
| `scripts/inspect_graphrag_output.py` | prints and records the REAL schema of every output file; maps text units back to our chunk ids |
| `requirements-graphrag.txt` | `graphrag==3.3.0` for the dedicated venv |
| `scripts/rename_graphrag_wording.py` | removes the "GraphRAG-style" wording from the docs already committed |
| `docs/decisions/0012-official-microsoft-graphrag.md` | the decision, replacing 0011 for this milestone |

## 3. How it is configured (and why)
- **Own venv.** The roadmap asks for one if packages conflict. GraphRAG pins numpy 2.x, pandas 3.x, LanceDB, LiteLLM; the install is about 1.2 GB.
- **One request at a time + sliding-window limit.** A free tier throttles and rejects large requests (your earlier HTTP 413). GraphRAG's retry and rate-limit settings are used instead of our own pacing.
- **500-token chunks, no gleaning, report input capped at 2,500 tokens.** GraphRAG's default prompts are long (the extraction prompt alone is about 780 words); prompt + chunk + the reply budget must fit Groq's request limit.
- **Cyber entity types**: threat_actor, malware, tool, vulnerability, attack_technique, software, organization, campaign, mitigation, sector.
- **Limits marked CHECK in `settings.yaml` are guesses.** Read your real limits at console.groq.com/settings/limits and edit `requests_per_period` and `tokens_per_period`.

## 4. Run it (PowerShell, project root `C:\CyberIntelGraph`)
```powershell
# 0. disk: the new environment needs about 1.3 GB plus room for outputs
Get-PSDrive C

# 1. a SEPARATE environment for GraphRAG (the main .venv stays untouched)
python -m venv .venv-graphrag
.\.venv-graphrag\Scripts\Activate.ps1
python -m pip install --no-cache-dir -r requirements-graphrag.txt
python -m pip install --no-cache-dir sentence-transformers   # only if the embedding server will also run from this venv; otherwise skip

# 2. window A (main .venv, with sentence-transformers): embeddings server - leave it running
python scripts\serve_local_embeddings.py

# 3. window B (.venv-graphrag): load the key from .env into THIS window, prepare input, preflight
Get-Content .env | ForEach-Object { if ($_ -match '^\s*([^#=]+)=(.*)$') { Set-Item "env:$($matches[1].Trim())" $matches[2].Trim() } }
python scripts\prepare_ms_graphrag_input.py
python scripts\check_ms_graphrag_setup.py --init-prompts
python scripts\check_ms_graphrag_setup.py                      # expect READY

# 4. validate the configuration without running anything, then index
graphrag index --root graphrag_engine\indexing\ms --dry-run
graphrag index --root graphrag_engine\indexing\ms

# 5. inspect what GraphRAG REALLY produced
python scripts\inspect_graphrag_output.py
```
Notes:
- GraphRAG caches every LLM call under `data\graphrag_outputs\cache`; if a run stops, run the same command again and it resumes.
- If the free tier is too tight, `graphrag index --root graphrag_engine\indexing\ms --method fast` builds the graph with NLP instead of the LLM and only uses the LLM for community reports.
- The first run downloads a tokenizer file (`o200k_base`), so it needs internet.
- If you would rather run the embeddings server from the main `.venv` and GraphRAG from `.venv-graphrag`, that is exactly the layout above.
- Query once indexing is done: `graphrag query --root graphrag_engine\indexing\ms --method global --query "What attack patterns recur?"`

## 5. What is verified and what is not
Verified here: the settings file loads in GraphRAG 3.3.0's own loader; the embeddings server works with the openai SDK and LiteLLM
(float and base64 formats); the preflight, input preparation and schema inspector work on synthetic data built from GraphRAG's real
column names (`human_readable_id`, `text_unit_ids`, `frequency`, `degree`, `combined_degree`, `rating_explanation` ...).

NOT verified: a full `graphrag index` run. It needs Groq and a tokenizer download, neither reachable from where this was built.
Open risks: whether gpt-oss-20b follows GraphRAG's prompts and structured-output requests on Groq, and whether your real Groq limits
fit the settings. The first `--dry-run` and a small run will tell.
