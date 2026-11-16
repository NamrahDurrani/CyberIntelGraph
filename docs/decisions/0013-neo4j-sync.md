# Decision 0013 - Neo4j synchronization design (Milestone 10)

Status: accepted - 2026-11-16

1. Two steps in two environments: `export_graphrag.py` (reads parquet; runs in `.venv-graphrag`) writes a validated JSON; `sync_neo4j.py` (needs only the `neo4j` driver; runs in the main venv) writes to Neo4j. No pandas in the main environment.
2. Hosted AuraDB Free (200,000 nodes / 400,000 relationships per Neo4j's documentation) so no database files use local disk.
3. One graph: canonical nodes first, then GraphRAG nodes. GraphRAG facts about an existing canonical node go into `gr_*` properties and never overwrite canonical ones. GraphRAG-only entities are `:Candidate` nodes with ids `<Type>:cand-<name>`.
4. Relationship types and node labels cannot be Cypher parameters: they are validated against strict patterns and the queries are grouped per label and per type.
5. Only MERGE, keyed by `entity_id`, `text_unit_id`, `community_key` and `rel_id`; uniqueness constraints on the three node keys only (the full schema is Milestone 11). Nothing is deleted.
6. Noise rules live in `config/graphrag_export_rules.json` (starter rules from one advisory) and every skip is counted.
7. GraphRAG relationships have no type in the real output, so they are written as `RELATED_TO` with evidence type `llm_extracted_candidate`.
8. `--verify-twice` implements the roadmap's done-criterion (the second pass must create nothing).
