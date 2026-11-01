# Folder Guide - what each folder is for and when you fill it

| Folder | Purpose | Filled in |
|---|---|---|
| `backend/api/routes` | FastAPI route modules | M15 |
| `backend/api/dependencies` | Shared FastAPI dependencies (db, auth) | M15 |
| `backend/schemas` | Request/response Pydantic models | M15 |
| `backend/services` | Business logic called by routes | M15 |
| `backend/middleware` | Logging, rate limiting, auth | M15/M18 |
| `backend/core` | Config, logging, constants | M3+ |
| `config` | YAML/JSON settings (e.g. GraphRAG settings) | M3/M9 |
| `ingestion/collectors/nvd` | NVD API collector | M3 |
| `ingestion/collectors/cisa_kev` | CISA KEV JSON collector (first one built) | M3 |
| `ingestion/collectors/mitre_attack` | ATT&CK STIX collector | M3 |
| `ingestion/collectors/cwe` | CWE XML collector | M3 |
| `ingestion/collectors/advisories` | CISA advisories (RSS + BeautifulSoup + Docling) | M3/M6 |
| `ingestion/document_processing` | Docling pipeline | M6 |
| `ingestion/chunking` | Token-aware chunking, stable chunk IDs | M6 |
| `ingestion/normalization` | Raw -> canonical converters | M5 |
| `ingestion/validation` | Count/field/duplicate checks | M4 |
| `canonical/schemas` | Pydantic models for every entity | M5 |
| `canonical/entities` | Entity-specific logic (ID normalization, merging) | M5 |
| `canonical/relationships` | Allowed relationship types and rules | M5 |
| `canonical/provenance` | Evidence and provenance models | M5 |
| `graphrag_engine/indexing` | GraphRAG index runs | M9 |
| `graphrag_engine/retrieval` | Basic/Local/Global/DRIFT search wrappers (and RAG baselines) | M7-M9 |
| `graphrag_engine/export` | Read GraphRAG outputs | M10 |
| `graphrag_engine/synchronization` | Write to Neo4j with MERGE | M10 |
| `neo4j_engine/connection` | Driver/session setup | M10 |
| `neo4j_engine/schema` | Constraints and indexes | M11 |
| `neo4j_engine/queries` | Cypher query files/functions | M11 |
| `neo4j_engine/repositories` | Python access layer | M11 |
| `database/mongodb` | Mongo connection | M12 |
| `database/repositories` | Collection access classes | M12 |
| `agent/graph` | LangGraph workflow definition | M13 |
| `agent/nodes` | Planner, retriever, verifier, reporter nodes | M13/M14 |
| `agent/tools` | The tool functions | M13/M14 |
| `agent/prompts` | Prompt templates | M13 |
| `agent/state` | Shared agent state schema | M13 |
| `evaluation/datasets` | 30-50 reviewed questions | M17 |
| `evaluation/metrics` | Metric code | M17 |
| `evaluation/experiments` | Experiment configs (models, prompts) | M17 |
| `evaluation/reports` | Results | M17 |
| `data/raw/*` | Original downloads - never edited | M3 |
| `data/processed` | Normalized data | M5 |
| `data/documents` | Parsed documents | M6 |
| `data/chunks` | Chunked text | M6 |
| `data/graphrag_outputs` | GraphRAG index artifacts | M9 |
| `outputs/reports` | Generated reports | M15 |
| `outputs/exports` | Exports | M10+ |
| `outputs/analytics` | Analytics output | M17 |
| `tests/unit`, `integration`, `evaluation` | pytest suites | every milestone |
| `logs` | Run logs (ignored by Git) | M3+ |
| `frontend` | Next.js app | M16 |
| `scripts` | Helper scripts (setup, verify, git) | M1+ |
| `docs/architecture` | Diagrams and design notes | ongoing |
| `docs/data_dictionary` | One page per data source | M2+ |
| `docs/pipeline` | Pipeline guides and the milestone roadmap | ongoing |
| `docs/decisions` | Architecture decision records | ongoing |

`.gitkeep` files only exist so Git tracks empty folders. Delete one when you add a real file to that folder (optional).
