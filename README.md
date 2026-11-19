# CyberIntelGraph

Evidence-grounded, agentic **Cyber Threat Intelligence (CTI)** research system.

It collects intelligence from authoritative sources (NVD, CISA KEV, MITRE ATT&CK, CWE,
CISA advisories), builds one unified knowledge graph (Microsoft GraphRAG + Neo4j), and answers
research questions with citations, source URLs, dates and stated limitations - never with
unsupported claims.

> **Status:** Milestones 1-10 complete (Neo4j Aura sync verified 2026-11-17). Milestone 11 (Cypher retrieval) is built and unit-tested; live check pending. See `PROJECT_STATUS.md` and `docs/CHANGE_REPORT_2026-11-18_M5-M11.md`.

## Start here (read in this order)
1. `docs/GETTING_STARTED.md`  - install Python 3.12, create the virtual environment, verify
2. `docs/GITHUB_GUIDE.md`     - turn this folder into a GitHub repository
3. `docs/pipeline/00_milestone_roadmap.md` - the 18 milestones, one by one, with run commands
4. `docs/architecture/folder_guide.md` - what every folder is for

## Quick start (Windows PowerShell)
```powershell
cd C:\CyberIntelGraph
.\scripts\setup_env.ps1          # creates .venv with Python 3.12
.\.venv\Scripts\Activate.ps1     # activate it
.\scripts\verify_structure.ps1   # checks every folder exists
Copy-Item .env.example .env      # then fill in keys later, when a milestone needs them
.\scripts\git_init.ps1           # local Git repo + first commit
```

## Technology stack
Python 3.12 | FastAPI | Pydantic | Docling | Microsoft GraphRAG | Neo4j | MongoDB |
LangGraph | BGE-M3 embeddings | hosted LLM API | Next.js + TypeScript | DeepEval

## Golden rules
- Work **one milestone at a time**; do not jump ahead.
- **Raw data in `data/raw/` is never modified.** Normalized copies go in `data/processed/`.
- Never invent records, citations or test results.
- Install only the packages the current milestone needs.
- Never commit `.env`, `.venv` or large datasets (already in `.gitignore`).
- After every change update `CHANGELOG.md` and `PROJECT_STATUS.md`.

## Collectors (Milestone 3)
| Source | Status | Run |
|---|---|---|
| CISA KEV | validated on the real feed | `python ingestion\collectors\cisa_kev\collector.py` |
| NVD | validated on the real API (150 CVEs) | `python ingestion\collectors\nvd\collector.py` |
| MITRE ATT&CK | validated on your PC (release 20.0) | `python ingestion\collectors\mitre_attack\collector.py` |
| CWE | validated on your PC (v5.0); category fix delivered, re-run to confirm | `python ingestion\collectors\cwe\collector.py` |
| CISA advisories | validated on your PC (46 documents); date fix and `--discover` delivered | `python ingestion\collectors\advisories\collector.py --discover https://www.cisa.gov/news-events/cybersecurity-advisories --discover-pages 5` |

Details: `docs/pipeline/03_cisa_kev_collector.md`, `04_nvd_collector.md`, `05_mitre_attack_collector.md`, `06_cwe_collector.md`, `07_advisories_collector.md`.
Check results with `python scripts\check_kev_output.py`, `check_nvd_output.py`, `check_attack_output.py`, `check_cwe_output.py` and `check_advisories_output.py`.
Milestone 3 gate (all five at once): `python scripts\check_all_outputs.py`.
Run unit tests: `python -m unittest discover -s tests\unit -v`.

## Milestone 4: raw data audit
One command audits all five sources together (raw integrity, freshness, targets, cross-source checks, field inventory, Git hygiene, check scripts, documentation):
`python ingestion\validation\audit_raw_data.py --write-doc`. Details: `docs/pipeline/08_raw_data_audit.md`. Optional: `.\scripts\protect_raw_data.ps1` makes raw files read-only.

## Milestones 5-10 in one table
| # | What | Entry point / command | Result |
|---|---|---|---|
| 5 | Canonical model | canonical build | 6,207 entities; 28,361 relationships after 5.1 |
| 6 | Docling chunking | chunking step | 2,734 chunks from 53 advisories |
| 7-8 | RAG and hybrid retrieval | `python rag\ask.py --mode hybrid_ids "..."`, `python rag\compare.py` | `hybrid_ids` top-1 1.0 (CVE) / 0.975 (technique) |
| 9 | Own lightweight GraphRAG | `python graphrag_engine\indexing\run_index.py --dry-run` | 220 entities, 165 relationships on 5 advisories |
| 9b | Official Microsoft GraphRAG pilot | separate `.venv-graphrag` | 106 entities, 81 relationships, 8 communities (aa22-103a) |
| 10 | Neo4j Aura sync | `python graphrag_engine\synchronization\sync_neo4j.py --verify-twice`, `python scripts\check_neo4j_graph.py` | 6,313 nodes, 28,616 relationships, idempotent |

## Milestone 11: Cypher retrieval (read-only)
```powershell
python -m unittest tests.unit.test_neo4j_retrieval -v      # offline tests
python neo4j_engine\cli.py schema --write --apply-indexes   # discover real property names, add name indexes
python neo4j_engine\cli.py actor-techniques "APT29"         # techniques marked documented / inferred / candidate
python scripts\check_neo4j_retrieval.py                     # live gate
python scripts\apply_milestone_11_docs.py                   # records the real results in the docs
```
verified 2026-11-19 on the real Aura graph: 19 checks passed, 2 warning(s); example Kimsuky: {'documented': 130, 'inferred': 58, 'candidate': 0, 'total': 188} <!-- M11-VERIFIED -->
Explanation: `docs/pipeline/15_neo4j_cypher_retrieval.md`. Credentials live in `.env` (see `.env.example`); never commit real keys.
