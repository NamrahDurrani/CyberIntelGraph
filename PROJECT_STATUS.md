# Project Status

**Current milestone:** 11 - Cypher retrieval on Neo4j: built and unit-tested; live check on Aura pending
**Last updated:** 2026-11-18

## Completed
- [x] Milestone 1-3: environment, decisions, five collectors (KEV, NVD, ATT&CK, CWE, advisories)
- [x] Milestone 4: raw data audit passed (0 FAIL) on 2026-11-10
- [x] Milestone 5 / 5.1: canonical model - 6,207 entities, 28,361 relationships after the KEV CWE fix (HAS_WEAKNESS 171 -> 1,755)
- [x] Milestone 6: Docling chunking - 2,734 chunks from 53 advisories
- [x] Milestone 7: naive RAG baseline (Groq gpt-oss-20b)
- [x] Milestone 8 / 8.1: hybrid retrieval (BM25 + dense + identifier bonus); `hybrid_ids` top-1 1.0 CVE / 0.975 technique
- [x] Milestone 9 / 9.1: own lightweight GraphRAG; first real run on 5 advisories (19 of 20 windows)
- [x] Milestone 9b: official Microsoft GraphRAG pilot on advisory aa22-103a
- [x] Milestone 10: canonical + GraphRAG into Neo4j Aura - 6,313 nodes, 28,616 relationships, idempotent, `check_neo4j_graph.py` ALL CHECKS PASSED (2026-11-17)
- [x] Milestone 11 code: `neo4j_engine/` (read-only Cypher retrieval), CLI, live check script; 34 offline unit tests pass

## To do for Milestone 11 (on your PC)
- [ ] `python -m unittest tests.unit.test_neo4j_retrieval -v` -> `Ran 34 tests` and `OK`
- [ ] `python neo4j_engine\cli.py schema --write` (see which property names were resolved) then `schema --apply-indexes`
- [ ] `python scripts\check_neo4j_retrieval.py` prints `ALL CHECKS PASSED`
- [x] verified 2026-11-19 on the real Aura graph: 19 checks passed, 2 warning(s); example Kimsuky: {'documented': 130, 'inferred': 58, 'candidate': 0, 'total': 188} <!-- M11-VERIFIED -->
- [ ] Commit and push

## Working functionality
- Collectors, canonical build, chunking, RAG (`rag\ask.py --mode hybrid_ids`), GraphRAG indexing and global search, Neo4j sync (`graphrag_engine\synchronization\sync_neo4j.py`)
- Retrieval over the graph: `python neo4j_engine\cli.py actor-techniques "APT29"` (after the live check)

## Pending
- Milestone 12: MongoDB persistence | 13: LangGraph supervisor | 14: evidence verification | 15: FastAPI | 16: frontend | 17: evaluation | 18: integration and deployment
- Official Microsoft GraphRAG: Basic / Local / Global / DRIFT searches and a multi-advisory run are not yet demonstrated

## Known issues
- Rotate the Groq key, the NVD key and the Aura password if the old `.env.example` (which contained real-looking values) was ever pushed to GitHub
- The 18 Nov progress report (PDF/md) still lists Milestone 4 as not signed off; it passed on 2026-11-10
- Milestone 11 assumes edge directions only for USES (actor -> technique); the live check verifies it

## Next exact task
Run the Milestone 11 steps above, paste the output of `check_neo4j_retrieval.py` (and `schema`, if any field is reported as not found).

<!-- milestone-13 -->
## Milestone 13 - LangGraph supervisor and specialist agents
Implemented. Live verification on the project PC is still pending.

What exists: a supervisor that plans an investigation, four read-only specialist agents that run in parallel, structured
claims with evidence ids, and an answer that cites only existing evidence. Run: `python scripts/run_agent.py "<question>"`.

Known limits: no independent claim verification or live KEV/NVD check yet (Milestone 14); no MongoDB persistence or
FastAPI endpoints yet (Milestones 14 and 15); document retrieval needs RAG_RETRIEVER in .env; answer quality depends on the
LLM and on how many advisories GraphRAG has processed (pilot only).

<!-- milestone-14 -->
## Milestone 14 - Independent verification, live fallback, MongoDB persistence
Implemented. Live verification on the project PC (KEV/NVD, MongoDB) is still pending.

What exists: every answer is audited against its evidence; CVE questions get a live KEV / NVD check with provenance; investigations and
agent traces are saved to MongoDB.

Known limits: investigations are stored in their own collections (not the Milestone 12 validated reports / agent_traces repositories)
- to be unified in Milestone 15; verification is lexical / identifier based; on FAIL only the answer is rewritten, specialist agents are not
re-run; live fallback covers KEV and NVD only; FastAPI endpoints and report generation are Milestone 15.
