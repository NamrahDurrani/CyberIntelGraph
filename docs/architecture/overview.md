# Architecture Overview

```
Official sources (NVD, CISA KEV, MITRE ATT&CK, CWE, CISA advisories)
        |  collectors (ingestion/collectors)
        v
data/raw  (never modified)  --validation-->  normalization  -->  data/processed (canonical)
        |                                                            |
        | PDF/DOCX/HTML                                              |
        v                                                            |
Docling + chunking  -->  data/documents, data/chunks                 |
        |                                                            |
        v                                                            v
Microsoft GraphRAG indexing  --export/sync (MERGE, idempotent)-->  Neo4j (canonical graph + evidence)
 (entities, relationships,                                           |
  communities, reports)                                              |
        \_____________________  LangGraph supervisor  ______________/
                                   |  tools: GraphRAG search, Cypher, live NVD/KEV/CWE/ATT&CK
                                   v
                  sufficiency check -> live retrieval -> claim verification
                                   v
                      cited report (FastAPI)  -->  MongoDB (jobs, chats, reports)
                                   v
                           Next.js frontend
```

## Who does what (analogy: a detective agency)
| Component | Role | Analogy |
|---|---|---|
| Collectors | Fetch official data | Couriers bringing in original documents |
| data/raw | Untouched originals | Evidence locker |
| Normalization | Same shape for all sources | Filing clerk using one form for every case |
| Docling + chunking | Read reports, split into passages | Photocopying key pages with page numbers |
| GraphRAG | Extract entities/relations, find communities, write community reports | Analysts pinning notes on a corkboard and grouping them |
| Neo4j | Permanent canonical graph, exact Cypher queries | The official case-file database |
| MongoDB | Chats, jobs, reports | The front-desk logbook |
| LangGraph agent | Plans, picks tools, verifies | The lead detective |
| Live tools | Re-check current facts | Phoning the source to confirm |

## Why both GraphRAG and Neo4j?
GraphRAG is great at *discovering* structure in text and summarizing communities. Neo4j is great at
*exact, repeatable* traversal and keeps provenance. Importing entities into Neo4j does **not** carry over
GraphRAG community reports or embeddings, so we keep both and connect them through shared IDs.

## Evidence rules (non-negotiable)
- Every relationship keeps provenance (source URL, dates, document/chunk ID, supporting text, method, validation status).
- Co-occurrence in a document is **not** a relationship.
- LLM-extracted candidates stay "candidate" until reviewed.
- NVD does not prove exploitation in the wild; CISA KEV does.
- An API failure is a limitation, not a finding.
