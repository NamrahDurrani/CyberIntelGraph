# Agent state, evidence and claims (Milestone 13)

## Evidence statuses
| Status | Meaning | Example |
|---|---|---|
| `confirmed_authoritative` | canonical KEV / NVD / ATT&CK / CWE data in the graph | "APT29 -[USES]-> T1059" |
| `reported_in_document` | stated in an advisory or passage, or "a report mentions this entity" | CISA advisory passage |
| `inferred` | derived from a path of two or more graph steps | Actor -> Software -> Weakness |
| `llm_candidate` | extracted by GraphRAG with an LLM; NOT confirmed | "Volt Typhoon" candidate node |
| `not_found` | searched, nothing found; not proof of absence | unknown name |
| `unable_to_verify` | a tool failed or data was unavailable | Neo4j timeout |

## Claim (structured, one fact)
`claim_id`, `text`, `subject`, `predicate`, `object`, `evidence_ids`, `status`
(documented / inferred / candidate / unsupported / not_found / unverified), `explanation`, `agent`.

## Agent result (what each specialist returns)
`agent_name`, `task_id`, `status` (ok / no_results / failed), `summary`, `entities`, `claims`, `evidence`
(agent-local ids, renumbered globally by `collect`), `unresolved`, `limitations`, `errors`, `tool_calls`
(tool, ok, rows, ms), `duration_ms`, `attempt`.

## Investigation record (`outputs/investigations/*.json`)
`investigation_id`, `thread_id`, `question`, `workflow_status` (completed / partial / no_results), `created_at`,
`finished_at`, `intent`, `scope`, `plan`, `selected_agents`, `answer`, `entities`, `unresolved`, `claims`, `evidence`,
`evidence_counts`, `citations_used`, `invalid_citations`, `agents`, `limitations`, `warnings`, `errors`,
`verification` and `fresh` (Milestone 14), `trace`.

## Rules
1. The graph is only read. 2. A GraphRAG candidate is never shown as a confirmed fact.
3. A failed tool is `unable_to_verify`, never `not_found`. 4. The answer may cite only existing evidence ids.
5. If nothing is found, the answer says so without calling the LLM. 6. No credentials are written to traces.
