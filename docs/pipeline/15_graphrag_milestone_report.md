# 15 - GraphRAG milestone report (Milestone 9): what we did, what went wrong, how we fixed it

Dates: 2026-11-14 to 2026-11-16. Written from the real outputs you pasted; numbers are yours, not estimates.

## 1. What GraphRAG is, in one picture
Milestones 7 and 8 gave you a clerk who finds the right paragraph. Some questions ("which attack patterns recur?") need an analyst instead.
GraphRAG is that analyst: she **reads** the advisories, **pins** every actor, tool and vulnerability on a wall (entities), **connects** them with strings
(relationships), notices **clusters** (communities), and writes one **briefing per cluster** (community reports). Broad questions are answered from the briefings.

## 2. What was built, in two phases
### Phase A - our own extraction pipeline (`graphrag_engine/indexing/*.py`)
Select 5 advisories -> pack text into windows -> Groq gpt-oss-20b extracts entities and relationships -> every item checked against the source text ->
merge and link to canonical ids -> Louvain communities -> community reports -> global search. Cached, paced and call-budgeted.

| Result (5 advisories, 20 windows) | Value |
|---|---|
| Entities / linked to canonical ids | 220 / 101 |
| Relationships | 165 |
| Communities / reported | 62 (37 singletons) / 12 |
| Grounding drops | 18 of 328 entities, 23 of 204 relationships |
| Checker | all checks passed; global search answered with citations |

### Phase B - the official Microsoft GraphRAG 3.3.0 (what the roadmap asks for)
Own virtual environment (`.venv-graphrag`, Python 3.12.10, about 1.3 GB), Groq gpt-oss-20b as chat model through GraphRAG's LiteLLM layer, your local bge-small
model as the embeddings endpoint (`scripts/serve_local_embeddings.py`), settings in `graphrag_engine/indexing/ms/settings.yaml`.
The pilot ran on one advisory (`aa22-103a`):

| Result (1 advisory) | Value |
|---|---|
| Text units / documents | 8 / 1 (all 8 text units map back to our chunk ids) |
| Entities / relationships | 106 / 81 |
| Communities / reports | 8 (level 0: 5, level 1: 3) / 8 |
| LLM calls (from the cache folders) | 44: extract 8, summarise descriptions 28, community reports 8; plus 9 embedding batches |
| Real schema | recorded in `docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md` - every column Milestone 10 needs is present |

The two phases are not like-for-like (5 advisories against 1); the own pipeline stays as a baseline and as a comparison for Milestone 17.

## 3. What the real output taught us
- Entity types: ATTACK_TECHNIQUE 51, SOFTWARE 15, MITIGATION 12, SECTOR 10, ORGANIZATION 9, MALWARE 3, VULNERABILITY 2, TOOL 2, THREAT_ACTOR 1, CAMPAIGN 1.
- The 51 "techniques" have **no ATT&CK id in their title** (0 of 106 titles contain a Txxxx id), and ICS technique ids (T08xx) are not in our canonical graph anyway.
- The highest-degree entities are generic or authors: APT ACTORS (13), TOOL (12), CISA, NSA, DOE, FBI, OPERATIONAL TECHNOLOGIES and OT as separate entities.
- Relationships carry source and target **titles**, a description and a weight - **no relationship type** and no canonical ids.
These findings drive the filtering and linking rules in Milestone 10.

## 4. Issues we faced and how each was solved
| # | Issue | Cause | Solution |
|---|---|---|---|
| 1 | The first build was called "GraphRAG-style" and was not Microsoft's tool | I replaced the package with my own implementation although the roadmap says "Microsoft GraphRAG indexing"; the reason (disk, no embeddings API, call volume) was real but the call was mine | Added the official run in its own venv (decision 0012); kept the own pipeline as a baseline; renamed the wording in docs (`rename_graphrag_wording.py`) |
| 2 | Relationship records failed your canonical `Relationship` model | I put `description` and `weight` at top level; the model forbids extra fields | Moved them into `properties`; the unit test against the real model caught it before delivery |
| 3 | Valid relationships would have been dropped | The quote-matching tokenizer glued full stops to words (`ransomware.` is not `ransomware`) | Tokenizer now allows `.` and `-` only inside a token; test added |
| 4 | Groq HTTP 413 "Request too large" on one window | A request is limited in size and counts the reply budget too; table-heavy text has many more tokens than words. My code also cut the error to 120 characters, hiding the limit | On 413 the window is split in half (up to 3 levels) and retried; finished work stays cached; errors print up to 400 characters |
| 5 | A rate-limit or size failure left the index incomplete | No resume path | Disk cache for every LLM answer, a hard call budget, a stop after 3 failures in a row; re-running the same command resumes |
| 6 | `graphrag`, `pandas`, `tiktoken` "not found" | The commands ran in the system Python, not in `.venv-graphrag` (the prompt had no venv prefix) | Preflight prints which Python it runs in; run guide shows how to confirm `sys.prefix`; `python -m graphrag` works without PATH |
| 7 | The preflight reported "0 input files" although they existed | GraphRAG's config loader changes the working directory, so relative paths broke afterwards | All paths are made absolute before the loader runs |
| 8 | GraphRAG needs embeddings and Groq has no embeddings API | - | Local OpenAI-compatible server around bge-small; tested with the openai SDK and LiteLLM, including the base64 format the SDK requests by default |
| 9 | Disk space (3.1 GB free, 1.3 GB venv) | GraphRAG pulls about 100 packages (spaCy, LanceDB, LiteLLM, cloud SDKs) | Separate venv, `--no-cache-dir`, preflight disk check; Neo4j goes to hosted Aura so no local database files |
| 10 | My cost estimate was wrong | I read the progress bar "188 / 188" as 188 LLM calls; the cache shows 44 | Corrected after measuring; the cache folder count is now the way to estimate: five advisories should be roughly five times 44 calls |
| 11 | Entity quality | GraphRAG's default prompt keeps generic words and the advisory's own authors | Starter filter rules in `config/graphrag_export_rules.json` for Milestone 10; to be reviewed against real output |

## 5. What we verified and what is still open
Verified on your machine: the full pilot run, the real schema, text-unit provenance (8 of 8), the cache-based call count. Verified here with fakes: config loading in GraphRAG's own loader, the embeddings
server protocol, the export and sync logic.
Open: only one advisory has been through the official pipeline; Groq daily limits were never read from the console; entity quality needs a review pass; GraphRAG relationships have no type.

## 6. Lessons
Check the roadmap before choosing a design; measure before estimating cost; keep every expensive step cached and resumable; test against the real schema (your canonical models) and not an assumed one; keep a separate environment for a heavy package.
