# Change report - Milestones 5 to 11 (catch-up of the project documentation)

Date: 2026-11-18  |  Repository: NamrahDurrani/CyberIntelGraph  |  Working directory: C:\CyberIntelGraph

**Why this report exists.** `README.md`, `PROJECT_STATUS.md`, `CHANGELOG.md` and the roadmap still described the project
as it stood at Milestone 4. This report records what Milestones 5-11 added, using only evidence that exists: your run
outputs, the milestone explanation files (M8, M9), commit hashes you reported, and (for Milestone 11) code that is
built and unit-tested but **not yet run against Aura**. Each item says where its numbers come from.

## Summary
| # | Milestone | Status | Key result | Evidence |
|---|---|---|---|---|
| 4 | Raw data audit | passed (0 FAIL) on 2026-11-10 | five sources audited and committed | your run, 2026-11-10 |
| 5 | Canonical model | done | 6,207 entities, 26,777 relationships; commit 3cd7374 | your run, 2026-11-10 |
| 5.1 | KEV CWE links | done | HAS_WEAKNESS 171 -> 1,755; 169 tests OK; commit 7da783b | your run, 2026-11-10 |
| 6 | Docling chunking | done | 2,734 chunks from 53 advisories; commits 0d8affc, 44c8cdf | your run, 2026-11-12 |
| 7 | Naive RAG | done | dense retrieval + Groq answers; index check found 1 FAIL / 1 WARN (both explained in M8) | M8 explanation file |
| 8 / 8.1 | Hybrid retrieval | done | `hybrid_ids` top-1: 1.0 CVE, 0.975 technique (probes built from the fields it looks up) | M9 explanation file |
| 9 / 9.1 | Own lightweight GraphRAG | done | 19 of 20 windows extracted on the first real run; 220 entities, 101 canonical links, 165 relationships | M9 explanation file |
| 9b | Official Microsoft GraphRAG pilot | pilot done | advisory aa22-103a: 8 text units, 106 entities, 81 relationships, 8 communities | your report, 2026-11-16 |
| 10 | Canonical + GraphRAG into Neo4j Aura | **verified 2026-11-17** | 6,313 nodes, 28,616 relationships, second sync created nothing | your run output |
| 11 | Cypher retrieval | **built, awaiting live check** | 34 offline unit tests pass | this delivery |

## Milestone 5 - canonical model (and 5.1)
- One standard shape for every entity, merged across sources (a CVE from NVD, KEV and advisories is one node).
- First build on real data: 6,207 entities and 26,777 relationships, all canonical checks passed (after a patch: the KEV ransomware field is a boolean).
- 5.1 made the KEV `cwes` field feed `HAS_WEAKNESS`: 171 -> 1,755 edges; 479 sub-technique parents intact.
- Evidence types are part of the model: structured record, directly stated, LLM-extracted candidate, human-reviewed, inferred. `llm_extracted_candidate` was reserved for Milestone 9.

## Milestone 6 - document processing
- Docling-based HTML chunking of the advisories: 2,734 chunks from 53 advisories (2,711 unique texts; 23 chunks are identical to another).
- Constraint met along the way: the raw advisories are 61 HTML files and the C: drive was nearly full, which is why the parser choice was reviewed before installing PyTorch.

## Milestone 7 - naive RAG
- Embedding index over the chunks, question -> top-k chunks -> answer from Groq `openai/gpt-oss-20b`; `rag/ask.py`, `scripts/check_rag_index.py`, 20 unit tests.
- Baseline weakness measured: technique-id questions found the right advisory 2.5% of the time at top-1, and CVE-2024-3400 returned five unrelated advisories.

## Milestone 8 - hybrid retrieval (8.1 results)
- Added: `rag/bm25.py` (identifier-preserving tokenizer), `rag/hybrid.py` (modes `dense`, `bm25`, `hybrid`, `hybrid_ids`; Reciprocal Rank Fusion plus an identifier bonus), `rag/compare.py`, `--mode` in `rag/ask.py` (default `hybrid_ids`), `config/hybrid_eval_questions.json`, `scripts/apply_milestone_8_docs.py`, 23 new tests.
- Fixed: tie-breaking in `VectorIndex.search` (identical chunks); a formula error that produced the "2,194 near-identical vectors" warning.
- 8.1: all 7 BM25 misses are "indexed but out-ranked"; fixed a related-bonus double count in `rag/hybrid.py` (+1 regression test). Not built: keyword search restricted to the identifier words.

## Milestone 9 - GraphRAG
- Own lightweight implementation (decision 0011): `graphrag_engine/indexing/*`, `graphrag_engine/retrieval/global_search.py`, `scripts/check_graphrag_output.py`, `scripts/apply_milestone_9_docs.py`, 36 tests; dependency `networkx`; Louvain communities; global search only.
- 9.1 first real run (5 advisories): 19/20 windows, grounding dropped 18 entities / 23 relationships / 1 bad type; 220 entities, 165 relationships, 62 communities (12 reported by cap); one HTTP 413 window led to automatic halving and retry; five of twelve reports were single-CVE product stars (not changed).
- 9b: Microsoft GraphRAG pilot in a separate `.venv-graphrag` with a local embeddings server (`scripts/serve_local_embeddings.py`).

## Milestone 10 - Neo4j Aura (verified 2026-11-17)
- `graphrag_engine/synchronization/sync_neo4j.py` (`--check-connection`, `--verify-twice`), `scripts/check_neo4j_graph.py`, `scripts/apply_milestone_10_docs.py`, `docs/CHANGE_REPORT_2026-11-17_M10_neo4j_sync.md`.
- First sync created 6,313 nodes (6,207 canonical, 90 candidates, 8 text units, 8 communities) and 28,616 relationships; second sync created 0 (IDEMPOTENT: PASS).
- `check_neo4j_graph.py`: ALL CHECKS PASSED (3 uniqueness constraints, counts per type, no duplicate ids, every candidate is `origin=graphrag` with evidence type `llm_extracted_candidate`, no canonical node labelled Candidate, no canonical relationship touches a candidate, every candidate linked to a text unit).
- Canonical relationships: USES 18,975 | AFFECTS 2,408 | HAS_WEAKNESS 1,755 | MITIGATES 1,477 | MENTIONS 1,184 | CHILD_OF 1,176 | PART_OF_TACTIC 881 | SUBTECHNIQUE_OF 479 | CONDUCTS 26 (total 28,361) + RELATED_TO 54 + links EXTRACTED_FROM 135, PART_OF 8, IN_COMMUNITY 58.

## Milestone 11 - Cypher retrieval (this delivery)
Added (see `docs/pipeline/15_neo4j_cypher_retrieval.md` for the explanation):
- `neo4j_engine/connection/client.py`, `schema/{introspect,mapping,indexes}.py`, `queries/cypher.py`, `repositories/{evidence,graph_repository}.py`, `cli.py`
- `scripts/check_neo4j_retrieval.py`, `scripts/apply_milestone_11_docs.py`, `tests/unit/test_neo4j_retrieval.py` (34 tests)
- Dependency: `neo4j` driver (already installed for Milestone 10); `python-dotenv` optional.
Behaviour: read-only; parameterised; property names discovered from the live graph; results classed documented / inferred / candidate.
Tests performed: 34 unit tests pass offline with a fake client; the live-check script was exercised against a simulated client only. A bug found by the tests before delivery: the index writer opened a session before validating its statements (now validates first).
Not yet done: the live check on Aura (`scripts\check_neo4j_retrieval.py`), applying the two indexes, committing.

## Documentation changed in this delivery
`README.md` (status, milestone table, M10/M11 sections), `PROJECT_STATUS.md` (rewritten), `CHANGELOG.md` (new top entries), `docs/pipeline/00_milestone_roadmap.md` (status line per milestone), `requirements.txt`, `.env.example` (secrets removed - see below).

## Open items and discrepancies
1. **Secrets in `.env.example`.** The copy inside the zip contained what look like real values (NVD key, Groq key, a Neo4j password). If that file was ever pushed to GitHub, treat those values as exposed: rotate the Groq and NVD keys and reset the Aura password, then keep only placeholders in `.env.example` (done in this delivery). Rotating matters more than deleting: Git history keeps old versions.
2. `CyberIntelGraph_Project_Report.md`/PDF (18 Nov) still says Milestone 4 is "not signed off" and M5-M8 records are unavailable; your 2026-11-10 run shows the M4 audit passed. Update that report from this one.
3. Official GraphRAG searches (global, local, DRIFT, basic) and a multi-advisory official run are not yet demonstrated.
4. Zip snapshot: the uploaded zip contains no Milestone 5-10 code (`neo4j_engine/`, `graphrag_engine/`, `canonical/` hold only `.gitkeep`). Keep your PC's working copy as the source of truth; use this delivery as an overlay.
