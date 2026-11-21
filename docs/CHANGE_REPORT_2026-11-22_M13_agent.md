# Change report - Milestone 13 (2026-11-22)

## Milestone 13 - LangGraph supervisor and specialist agents (2026-11-22)
- Added `cti_agent/`: a supervisor plans the investigation and runs specialist agents in parallel
  (threat_actor, vulnerability, attack, evidence). `collect` merges and de-duplicates their evidence, `review`
  retries only failed / no-match tasks (bounded), then assess -> generate -> citation check -> finalize.
- Typed contracts (Pydantic): ResearchTask, AgentResult, Claim. A documented / inferred / candidate claim must cite evidence.
- Evidence statuses: confirmed_authoritative, reported_in_document, inferred, llm_candidate, not_found, unable_to_verify.
  Claim statuses: documented, inferred, candidate, unsupported, not_found, unverified.
- Read-only Neo4j access; schema discovered from the real graph; GraphRAG candidates never promoted to facts;
  tool failures are unable_to_verify, never not_found.
- Budgets: retries, parallel tasks, time, tool calls. LangGraph checkpointing with pause / resume (memory; mongo optional).
- Hook points (`pre_assess`, `post_generate`, `post_finalize`) so Milestone 14 plugs in without editing these files.
- Each investigation is saved to outputs/investigations/.
- Scripts: run_agent.py, check_agent.py, probe_graph_schema.py, probe_rag_api.py.
- Status: Implemented. Live verification on the project PC is still pending.

## Files added
- cti_agent/ (config, evidence, schemas, nlp, supervisor, nodes, graph, state, hooks, checkpoint, store, trace, schema_map,
  neo4j_client, llm, deps, testing, agents/, tools/)
- scripts/run_agent.py, check_agent.py, probe_graph_schema.py, probe_rag_api.py, apply_milestone_13_docs.py, _bootstrap.py
- tests/unit/test_agent_basics.py, test_agent_graph.py, test_agent_agents.py
- docs/milestones/M13_langgraph_agent.md, docs/data_dictionary/AGENT_STATE_AND_EVIDENCE.md
- requirements-agent.txt
