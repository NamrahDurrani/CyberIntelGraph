# Milestone Roadmap (18 milestones)

Rule: finish and **test** one milestone before starting the next. At the end of each one:
update `CHANGELOG.md` + `PROJECT_STATUS.md`, then `git add . ; git commit -m "Milestone N: ..." ; git push`.

Always run commands from the project folder with the venv active (`(.venv)` in the prompt). Type `cig` to get there from any terminal (see `docs/PROJECT_LOCATION.md`).

Package rule: install ONLY what the current milestone lists, then record it in `requirements.txt`
(`python -m pip freeze` is too noisy - add the top-level package names by hand).

---

## Milestone 1 - Environment and project structure  (this zip)
**Goal:** Python 3.12 venv, folder tree, docs, Git.
**Do:** follow `docs/GETTING_STARTED.md`, then `docs/GITHUB_GUIDE.md`.
**Done when:** `verify_structure.ps1` prints `STRUCTURE OK`, venv shows Python 3.12, first commit pushed.

## Milestone 2 - Data source selection and dataset scope
**Goal:** decide exactly what to download first (small and focused).
**Analogy:** packing a carry-on bag, not moving house. Start with ransomware, initial access, exploited vulnerabilities, malware and techniques.
**Targets:** NVD 150-200 CVEs | KEV 50-75 | ATT&CK relevant subset | CWE relevant categories | CISA advisories 50-75.
**Do:** write the scope in `docs/decisions/0002-initial-dataset-scope.md` (copy `docs/decisions/TEMPLATE.md`) and create one data-dictionary page per source from `docs/data_dictionary/TEMPLATE.md`.
**Packages:** none.
**Done when:** scope and the 5 data-dictionary pages exist.

## Milestone 3 - Individual collectors (one source at a time)
**Order:** CISA KEV -> NVD -> MITRE ATT&CK -> CWE -> CISA advisories. Wait for the previous one to pass validation.
**Folder:** `ingestion/collectors/<source>/collector.py`
**Packages:** `python -m pip install requests python-dotenv` (advisories also need `beautifulsoup4`).
**Each collector must:** fetch from the official source, handle HTTP errors/timeouts/rate limits, validate, keep source metadata (`source_name, source_url, source_record_id, retrieved_at, published_at, last_modified_at, original_format, raw_file_reference, collection_method`), save raw data untouched, log success/failure.
**Why an API/JSON catalog instead of scraping?** Scraping HTML is like copying a menu by photographing it - fragile. APIs hand you the data in a stable, structured form.
**Run (example):** `python ingestion\collectors\cisa_kev\collector.py`
**Done when:** raw file exists in `data/raw/<source>/`, record count and required fields validated, no duplicates.

## Milestone 4 - Raw data validation and storage
**Goal:** prove the whole raw data layer is complete, untouched, fresh, consistent across sources, documented and kept out of Git.
**Analogy:** the surveyor's visit before an architect designs the house.
**Built:** `ingestion/validation/audit_raw_data.py` (one command for all five sources), `config/dataset_targets.json`, `scripts/protect_raw_data.ps1` (optional read-only protection), generated `docs/data_dictionary/RAW_DATA_AUDIT.md`. Details: `docs/pipeline/08_raw_data_audit.md`, decision 0005.
**Run:** `python ingestion\validation\audit_raw_data.py --write-doc`
**Packages:** none.
**Done when:** the audit prints no FAIL on your PC, the advisories reach their target (or the shortfall is explained), the generated audit document is committed, and the data dictionary pages are no longer marked "not verified".

## Milestone 5 - Canonical schemas and normalization
**Goal:** one official shape for every entity so duplicates merge (CVE-2024-3400 from NVD + KEV + advisories = ONE Vulnerability node with several evidence records).
**Folders:** `canonical/schemas`, `canonical/entities`, `canonical/relationships`, `canonical/provenance`, `ingestion/normalization`.
**Packages:** `python -m pip install pydantic`
**Entities:** ThreatActor, Campaign, Malware, AttackTechnique, AttackTactic, Vulnerability, Software, Weakness, Organization, IntelligenceReport, Evidence, Community (optional).
**Provenance fields on every claim:** evidence ID, source URL/name, publication date, retrieval date, document + chunk ID, page/section, supporting text, extraction method, model + version, validation status, evidence type.
**Evidence types:** directly stated | structured authoritative record | LLM-extracted candidate | human-reviewed | inferred. An LLM-extracted relationship is **never** "verified" just because a model produced it.
**Done when:** normalized files in `data/processed/` pass schema validation and CVE IDs are unique.

## Milestone 6 - Document processing and chunking (Docling)
**Goal:** turn PDF/DOCX/HTML advisories into clean, chunked text with page/section references.
**Folders:** `ingestion/document_processing`, `ingestion/chunking`, `data/documents`, `data/chunks`.
**Packages (large - check disk first):** `python -m pip install docling tiktoken` (check `Get-PSDrive D` before; set `$env:PIP_CACHE_DIR="D:\pip_cache"`).
**Docling is for PDF/DOCX only.** Structured JSON/XML/STIX use ordinary parsers.
**Done when:** every document has a stable `document_id`; every chunk has a stable `chunk_id`, page/section, and tables are preserved.

## Milestone 7 - Naive RAG baseline
**Goal:** the simplest retrieval (embed chunks, find nearest) so later methods have something to beat.
**Folders:** `graphrag_engine/retrieval` (or a new `baselines/` decision recorded in `docs/decisions`).
**Packages:** an embedding client for your hosted BGE-M3-compatible endpoint plus a lightweight vector index (decide in an ADR; do not download local LLMs).
**Done when:** you can ask a question and get top-K chunks with source URLs.

## Milestone 8 - Hybrid RAG (vector + keyword)
**Packages:** `python -m pip install rank-bm25`
**Idea:** vector search finds meaning ("sounds like"), keyword search finds exact strings (CVE IDs). Merge both.
**Done when:** CVE-ID queries hit exactly and conceptual queries still work.

## Milestone 9 - Microsoft GraphRAG indexing
**Goal:** run GraphRAG on selected normalized documents; get entities, relationships, communities, community reports.
**Before installing:** check the GraphRAG version and whether it supports Python 3.12; if it conflicts, put it in its own venv and record that in `docs/decisions/`.
**Folders:** `graphrag_engine/indexing`, `data/graphrag_outputs`.
**Why community detection?** It groups related entities (like neighbourhoods on a map) so "global" questions can be answered from short community summaries.
**Cost warning:** indexing calls the LLM many times. Start with 5-10 documents.
**Done when:** output files exist and you have **inspected the real output schema** (do not assume column names).

## Milestone 10 - GraphRAG output inspection and Neo4j synchronization
**Folders:** `graphrag_engine/export`, `graphrag_engine/synchronization`.
**Packages:** `python -m pip install neo4j`
**Neo4j hosting:** the free hosted Aura tier avoids using local disk; Docker/Desktop also work.
**Rules:** map to canonical types, validate relationship endpoints, keep TextUnit references, use `MERGE` (repeatable/idempotent), batch writes, log counts. One direction only: GraphRAG/canonical -> Neo4j. No two disconnected graphs.
**Done when:** running the sync twice produces the same node/relationship counts.

## Milestone 11 - Neo4j schema and Cypher retrieval
**Folders:** `neo4j_engine/schema`, `queries`, `repositories`.
**Do:** constraints + indexes, then query functions: entity lookup, one-hop, multi-hop, evidence lookup, provenance, temporal.
**Done when:** "techniques for threat actor X" returns techniques **with evidence**, marking documented vs inferred.

## Milestone 12 - MongoDB application persistence
**Folder:** `database/mongodb`, `database/repositories`.
**Collections:** users, conversations, messages, research_jobs, reports, document_metadata, feedback, agent_traces.
**Packages:** the official PyMongo async API (check current docs). **No SQLite.** Do not duplicate the graph in MongoDB.
**Done when:** a test conversation and report round-trip.

## Milestone 13 - LangGraph supervisor and research tools
**Folders:** `agent/graph`, `nodes`, `tools`, `prompts`, `state`.
**Packages:** `python -m pip install langgraph`
**Start with ONE supervisor agent.** Tools: search_graphrag_basic/local/global/drift, search_neo4j, get_cve_details, check_kev_status, get_cwe_details, search_attack_techniques, retrieve_evidence, verify_claims, generate_report.
**Safety:** research only - no exploits, no scanning, no destructive actions.
**Done when:** the agent picks the right tool for 10 sample questions.

## Milestone 14 - Evidence verification and live intelligence fallback
**Rules:** judge sufficiency (relevance, recency, completeness, conflicts, authority), not just "zero results". An API error is reported as a limitation, **never** as "CVE does not exist". NVD alone does not prove exploitation - use KEV.
**Done when:** a stale/missing-evidence question triggers live retrieval and results are source-attributed.

## Milestone 15 - Report generation and FastAPI integration
**Packages:** `python -m pip install fastapi uvicorn pydantic-settings`
**Create now:** `backend/main.py` (only now, with real content).
**Endpoints:** POST /api/chat, POST /api/research, GET /api/research/{id}, GET /api/reports/{id}, GET /api/graph/entity/{id}, GET /api/graph/neighborhood/{id}, GET /api/sources/{id}, GET /api/health, GET /api/analytics.
**Run:** `python -m uvicorn backend.main:app --reload` then open http://127.0.0.1:8000/docs
**Done when:** a research request returns a cited report with dates and limitations.

## Milestone 16 - Frontend (Next.js + TypeScript)
**Prereq:** Node.js LTS (`node --version`). Delete `frontend\.gitkeep`, then `cd frontend` and run `npx create-next-app@latest .`.
**Pages:** Dashboard, Research Chat, History, Report Viewer, Graph Explorer, Vulnerability Explorer, Source/Evidence Viewer, Analytics.
**Done when:** every page uses real backend data (no decorative mock dashboards).

## Milestone 17 - Evaluation and benchmarking
**Packages:** `python -m pip install deepeval`
**Compare:** A naive RAG | B hybrid RAG | C GraphRAG | D Neo4j | E combined agentic.
**Dataset:** 30-50 manually reviewed questions in `evaluation/datasets/`.
**Metrics:** entity/relationship P/R/F1, entity-resolution accuracy, Precision@K, Recall@K, MRR, answer correctness/completeness, faithfulness, citation correctness, evidence coverage, tool-selection accuracy, task completion, latency, tokens, cost.
**Never claim one method is better without measured results.**

## Milestone 18 - Integration testing, security review, deployment
**Packages:** `python -m pip install pytest`
**Run:** `python -m pytest tests -q`
**Before going public:** authentication, authorization, rate limiting, tenant isolation, secrets review, dependency review.
