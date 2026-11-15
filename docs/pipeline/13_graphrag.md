# 13 - Milestone 9: GraphRAG indexing (own extraction pipeline) - what changed and why

## 0. First: what your Milestone 8.1 numbers mean
| Result | Meaning |
|---|---|
| All 7 BM25 misses are category C ("indexed but out-ranked") | No data problem and no tokenizer problem. The IDs are in the text and in the index; other chunks scored higher. Four of the six technique misses are ICS-matrix ids (`T0801`, `T0815`, `T0836`, `T0858`) sitting in long table chunks. My working guess, not yet proven: the generic words in the question template ("ATT&CK", "technique", "advisory") out-score one rare id inside a long table chunk. |
| `hybrid:3` and `hybrid:5` are still far below `bm25` on technique questions | The 3x keyword weight helped CVE questions (0.425 -> 0.775 top-1) but not enough for techniques. The embedding list still adds near-random chunks that also appear in the keyword list for generic words. |
| `hybrid_ids:3` = 1.0 for CVEs, 0.975 for techniques | This is the default mode, and it works. Remember the probes were built from the same fields it looks up, so treat it as "the lookup does what it should", not as a real-world accuracy. |
| The one missing 0.025 at top-1 for techniques | Reading the code to explain it, I found a real bug: a chunk listing two sub-techniques of the same parent (for example T1090.002 and T1090.003) received the "related" bonus twice, equal to an exact match. Fixed in `rag/hybrid.py`, with a regression test that fails on the old code. It is a likely, not proven, cause of that one miss. |

Verdict: good to move on. Not built, noted for later: giving keyword search only the identifier words when a question names an id.

## 1. What Milestone 9 is, as a detective agency
Milestones 7 and 8 gave you a clerk who finds the right paragraph. Some questions need an analyst instead:
"which attack patterns recur across these advisories?" no single paragraph answers that. GraphRAG works like this:
1. The analyst **reads** a few reports and pins every person, tool and vulnerability on a wall (entities), with strings between those that interact (relationships).
2. She notices **clusters** on the wall (communities).
3. She writes one short **briefing per cluster** (community reports).
4. When asked a broad question she **reads the briefings**, not the raw files (global search).

## 2. Decision: our own lightweight version (decision 0011)
Installing the official `graphrag` package would add about 100 packages (spaCy, LanceDB, LiteLLM, PyArrow, Azure and AWS SDKs ...), needs an embeddings service Groq does not offer, and makes hundreds of LLM calls. So `graphrag_engine/` implements the same method with one tiny new dependency (`networkx`). Differences, openly: Louvain communities instead of hierarchical Leiden; global search only (no local search); our own prompts. The official package remains available as a comparison in Milestone 17.

## 3. The pipeline
```
advisory_chunks.jsonl --select 5 advisories--> windows of ~1,400 words (~7 per advisory)
  --LLM (cached, paced, budgeted)--> entities + relationships  --grounding checks-->
  merge + link to canonical ids --> graph --Louvain--> communities --LLM--> community reports
  question --> BM25 picks top reports --> each answers alone (map) --> combined answer with [C000] citations (reduce)
```
- **Selection.** Advisories with the most distinct CVE/technique ids per chunk, 5-80 chunks long. Or choose with `--pick aa20-302a,...`.
- **Windows.** Packing chunks cuts calls roughly eightfold versus one call per chunk, which matters for free-tier limits.
- **Grounding (the anti-hallucination step).** An entity is kept only if its name literally occurs in the text. A relationship is kept only if both ends are kept entities and at least 80% of its supporting quote's words occur in the text. Everything dropped is counted in `run_summary.json`.
- **Evidence.** Every record has type `llm_extracted_candidate` (the type reserved for this milestone in Milestone 5), with the chunk id, the cache file and the source URL.
- **Linking.** CVE and ATT&CK ids reuse canonical ids (`Vulnerability:CVE-2024-3400`, `AttackTechnique:T1059.001`). A name is linked to a canonical entity only when exactly one compatible entity matches; ambiguous names stay candidates. Candidate ids look like `Malware:cand-trickbot`. Nothing is written into the canonical graph (that is Milestone 10).
- **Cache and budget.** Every LLM answer is stored on disk. A re-run costs nothing for finished work; a rate-limit stop is resumed by running the same command again. `--max-calls` (default 120) caps new calls per run; three failures in a row stop the run.

## 4. Files
| Path | Role |
|---|---|
| `graphrag_engine/indexing/select.py` | choose the advisory subset |
| `.../extract.py` | windows, prompt, JSON parsing, grounding validation |
| `.../llm_cache.py` | disk cache, pacing, call budget, token count |
| `.../resolve.py` | merge duplicates, type conflicts, canonical linking, evidence records |
| `.../communities.py` | graph, Louvain communities, stable ids C000, C001 ... |
| `.../reports.py` | community reports with citation checking |
| `.../run_index.py` | the command-line runner (`--dry-run`, `--pick`, `--skip-reports` ...) |
| `graphrag_engine/retrieval/global_search.py` | map-reduce answers from community reports |
| `scripts/check_graphrag_output.py` | about 20 checks on the output, including schema validation with the canonical models |
| `scripts/apply_milestone_9_docs.py` | change report with real numbers, CHANGELOG, PROJECT_STATUS |
| `tests/unit/test_graphrag_engine.py` | 31 tests with a rule-based fake LLM |

## 5. Changes in this package outside the new folder
- `rag/hybrid.py`: related-bonus double-count fix; `tests/unit/test_hybrid.py` +1 regression test.
- `requirements.txt`: `networkx`.
- Bugs the new tests caught before delivery: relationship records carried fields your canonical `Relationship` model forbids (moved into `properties`); the quote tokenizer glued full stops onto words (it would have wrongly dropped valid relationships).

## 6. Honest limits
- Built and tested against a rule-based fake LLM and synthetic chunks. The real Groq model has not seen these prompts: extraction quality, JSON compliance of gpt-oss-20b and the free-tier limits are unverified. That is why the first real step is `--dry-run`, then a small run.
- Five advisories give a small graph; community structure may be coarse. Louvain is one level, not Microsoft's hierarchy.
- Linking to canonical names is exact-slug matching; spelling variants will stay candidates.
- No local search and no Neo4j yet (Milestone 10).

## 7. Milestone 9.1 - the first real run (5 advisories, gpt-oss-20b)
What the numbers showed:
- **19 of 20 windows extracted.** Grounding dropped little: 18 entities not found in the text, 23 relationships with an unknown endpoint, 1 bad type. The model rarely invented things.
- **220 entities, 101 linked to canonical ids, 165 relationships, 62 communities, 12 reported.** The 12 is the `--max-communities` cap (largest first), not a failure.
- **One window failed with HTTP 413 ("Request too large").** Groq limits the size of a single request, and the request counts the reply budget (`--max-tokens`, 3500) as well as the text. Table-heavy windows have far more tokens than words. The first version hid the limit by cutting the error message to 120 characters, and a re-run would have failed the same way.
- **Five of the twelve reports are about one CVE and its affected product versions** (Accellion, Sitecore, Oracle, FortiOS, Exchange). Those communities are stars of `Vulnerability AFFECTS Software` and help little with broad questions. Not changed yet; candidate fix: fold product-version entities into their product, or rank communities by how many different entity types they hold.
- Two windows returned zero entities (`aa22-117a_w05`, `aa24-317a_w03`). They are probably reference or boilerplate text, but they are worth a look.

What changed:
- `run_index.py`: on HTTP 413 a window is halved (between chunks, or inside a single long chunk) and retried, up to three levels. Windows that already succeeded stay cached, so only the failed one costs calls. Errors now print up to 400 characters.
- Entity evidence is taken from the window's own chunk list, so it also works for split windows.
- A run where nothing could be extracted now stops instead of writing an empty graph; a run with some failed windows prints a warning, and `apply_milestone_9_docs.py` still refuses until none fail.
- Counts replies that ended at the token limit (`truncated_replies`) and warns.
- Tests: 36 in `test_graphrag_engine.py` (5 new), including 413 splitting, an unsplittable 413 and the truncation count.

