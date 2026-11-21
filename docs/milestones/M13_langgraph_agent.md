# Milestone 13 - LangGraph supervisor and specialist research agents

## The idea in one picture
Think of a research manager with four analysts.
The manager (supervisor) reads the question and decides **who is needed**. The analysts work **at the same
time**, each in their own area, each with a small set of **read-only tools**. They never talk to each other;
they hand their notes back to the manager, who merges them, retries only the analyst who failed, and gives the
merged, numbered **exhibits** (E1, E2, ...) to a writer. Every sentence in the answer must point to an exhibit.

| Analyst (agent) | Job | Does NOT do |
|---|---|---|
| `threat_actor` | actors, groups, malware, tools, campaigns, aliases | technique mapping, CVE links |
| `vulnerability` | CVE / CWE records, affected software, KEV fields stored in the graph, advisories mentioning the CVE | claim that an actor exploited a CVE |
| `attack` | ATT&CK techniques, tactics, mitigations, who uses a technique | invent technique ids |
| `evidence` | document passages (deduplicated) and GraphRAG candidates | summarise; promote candidates |

The **verification agent** and **live fallback** are Milestone 14. This milestone only checks that every
citation points to evidence that exists.

## Workflow (`cti_agent/graph.py`)
```
START -> plan (supervisor)
      -> run_agent x N          (parallel, one per task)
      -> collect                (merge, renumber evidence, de-duplicate, link entities)
      -> review                 (failed / no-match task? retry that task only, bounded)
           '-> run_agent ... -> collect -> review
      -> gate -> [pre_assess hooks] -> assess -> generate -> check_citations
      -> [post_generate hooks] -> finalize -> [post_finalize hooks] -> END
```
`[hooks]` are extension points. Milestone 14 plugs in there without editing any Milestone 13 file.

## Status vocabulary
Evidence: `confirmed_authoritative`, `reported_in_document`, `inferred`, `llm_candidate`, `not_found`, `unable_to_verify`.
Claims: `documented`, `inferred`, `candidate`, `unsupported`, `not_found`, `unverified`.
A documented, inferred or candidate claim **must** cite evidence; the schema rejects it otherwise.
A tool failure is `unverified` / `unable_to_verify`, never `not_found`.

## Limits and safety
- Neo4j is only read (read transactions); queries are parameterised; no generated Cypher is ever executed.
- Retries: `AGENT_MAX_RETRIES` (default 1) per task. Parallel tasks: `AGENT_MAX_PARALLEL` (4).
  Time budget: `AGENT_MAX_DURATION_SECONDS` (120). Tool calls per agent: `AGENT_MAX_TOOL_CALLS` (60).
- Checkpointing: `AGENT_CHECKPOINT=memory` (default), `none`, or `mongo` (needs `langgraph-checkpoint-mongodb`;
  falls back to memory and says so). Memory checkpoints let you pause and resume within one Python process.
- Retrieved text is only ever used as evidence to quote; it is never run as an instruction or a tool call.
- Each investigation is saved as JSON in `outputs/investigations/` (git-ignored).

## How to run
`python scripts\run_agent.py "Which techniques does APT29 use?"` (add `--json` for the full record, `--no-llm` for evidence only).
`python scripts\check_agent.py` (offline) and `python scripts\check_agent.py --live` (real Neo4j + Groq).

## Connecting things the agent could not inspect
- **Property names in Neo4j:** `python scripts\probe_graph_schema.py` discovers them; the agent uses what it finds.
- **Your hybrid retriever (Milestones 7-8):** `python scripts\probe_rag_api.py`, then set `RAG_RETRIEVER=module:function` in `.env`.
  Until then the evidence agent reports "no document retriever configured" and the agent searches the graph only.

## Not in this milestone
Independent claim verification, contradiction detection, live KEV/NVD fallback, MongoDB persistence (Milestone 14);
FastAPI endpoints and report generation (Milestone 15).
