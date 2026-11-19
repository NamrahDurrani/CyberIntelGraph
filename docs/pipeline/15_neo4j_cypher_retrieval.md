# 15 - Milestone 11: Cypher retrieval on Neo4j - what it is, how it works, what changed

## 0. Where Milestone 11 sits
```
 sources --> canonical model --> chunks --> RAG / hybrid (M7-M8) --\
 (KEV, NVD, ATT&CK,   (M5)        (M6)                              \
  CWE, advisories)                                                    +--> AGENT (M13) --> API (M15) --> web app
                              GraphRAG (M9) --> NEO4J AURA (M10) --> CYPHER RETRIEVAL (M11)
                                                  stores the graph      asks it exact questions
```
M10 **stored** the knowledge (6,313 nodes, 28,616 relationships). M11 **asks** it questions in a way the
later agent can rely on: every answer says where it came from and whether it is documented, inferred or
only an LLM-extracted candidate.

## 1. The analogy (continuing the library from Milestones 8 and 9)
| Milestone | Person in the building | Good at |
|---|---|---|
| 7 | clerk | finds paragraphs about a topic (meaning) |
| 8 | catalog desk | finds exact identifiers (CVE-2024-3400) |
| 9 | analyst | summarises clusters of related reports |
| 10 | filing room | stores every record and its links, labelled by origin |
| **11** | **records officer** | answers "who uses what, connected how?" exactly, **and stamps every answer with its evidence status** |

The records officer follows strict rules: she never writes in the files (read-only), never lets a visitor's
words become instructions (parameters), never answers beyond a limit, and never presents a rumour (candidate)
as a record (documented).

## 2. Cypher in ten minutes
Cypher draws the pattern you want in ASCII art; Neo4j finds every place the pattern occurs.
```
(a:ThreatActor)-[r:USES]->(t:AttackTechnique)
 ^ node  ^label    ^ relationship  ^ direction   ^ another node
```
| Clause | Meaning | Example |
|---|---|---|
| `MATCH` | the pattern to find | `MATCH (a:Entity)-[r:USES]->(t:AttackTechnique)` |
| `WHERE` | filter the matches | `WHERE a.entity_id IN $ids` |
| `RETURN` | what to hand back | `RETURN properties(t), properties(r)` |
| `$name` | a parameter - a value sent *separately* from the query text | `$ids`, `$q`, `$limit` |
| `LIMIT` | cap the rows | `LIMIT $limit` |
| `shortestPath` | fewest hops between two nodes | `shortestPath((a)-[*..4]-(b))` |

Why parameters? A query is code; a user's text is data. If the text were pasted into the query,
`x'}) DETACH DELETE (n) //` would become code. Sent as `$q`, it stays an inert string. Unit test
`test_find_entities_parameterises_user_text` proves it.

SQL comparison: "techniques used by a group" needs two JOINs through a link table in SQL; in Cypher the
relationship **is** stored, so the pattern above is one line and multi-hop is just a longer pattern.

## 3. The graph as Milestone 10 built it
```
 IntelligenceReport --MENTIONS--> (any Entity)
 ThreatActor --CONDUCTS--> Campaign --USES--> AttackTechnique --PART_OF_TACTIC--> AttackTactic
 ThreatActor/Malware/Tool --USES--> AttackTechnique --SUBTECHNIQUE_OF--> AttackTechnique
 Mitigation --MITIGATES--> AttackTechnique
 Vulnerability --AFFECTS--> Software ;  Vulnerability --HAS_WEAKNESS--> Weakness --CHILD_OF--> Weakness
 candidate (LLM) nodes --RELATED_TO / EXTRACTED_FROM--> TextUnit --PART_OF--> Community
```
Every node carries the label `Entity` plus its type; GraphRAG candidates also carry `Candidate`
(M10's check "no canonical node was labelled Candidate" enforces the split).
Relationship counts from your M10 run: USES 18,975 | AFFECTS 2,408 | HAS_WEAKNESS 1,755 | MITIGATES 1,477 |
MENTIONS 1,184 | CHILD_OF 1,176 | PART_OF_TACTIC 881 | SUBTECHNIQUE_OF 479 | CONDUCTS 26 | RELATED_TO 54 (candidates).
*Edge directions other than USES are treated as unknown in M11 and matched undirected; only
actor -USES-> technique is assumed directed, and the live check verifies that assumption.*

## 4. How a question flows (example: "techniques for APT29")
```
 "APT29" --> resolve_entity ---------------> ONE ThreatActor id (or: ambiguous / not found - never a guess)
                |
                +--> 4 read-only queries, each with $ids and $limit
                |      direct        (a)-[:USES]->(t)                       -> documented
                |      via_campaign  (a)-[:CONDUCTS]-(c)-[:USES]->(t)       -> inferred
                |      via_software  (a)-[:USES]->(malware|tool)-[:USES]->(t)-> inferred
                |      candidate     (a)-[:RELATED_TO]-(t)  (GraphRAG)      -> candidate
                +--> merge by technique id, keep every path, take the best class
                +--> 1 batch query: advisories (IntelligenceReport) that MENTION the techniques
                v
 { actor, techniques:[{id, name, claim_class, paths:[...], reports:[...]}], counts, notes }
```

## 5. Why the code discovers property names instead of assuming them (the "how" and the "why")
**Why:** the M10 exporter chose the property names; M11 was written without being able to see them, and
guessing a name in Cypher does not fail - it silently returns nothing (`n.nmae` is just `null`).
**How:** `schema/introspect.py` asks Neo4j (`db.labels()`, `db.schema.nodeTypeProperties()`, `SHOW INDEXES` ...);
`schema/mapping.py::GraphMap` maps each logical field (id, name, aliases, origin, evidence type, date ...) to the
first real property from a candidate list. Unresolved optional fields are left out of results and reported;
an unresolved `id` or `name` stops the check with a clear message. Property types matter too: the alias clause
is only generated if `aliases` is a list, and the date comparison is a string compare or `datetime()` depending
on the stored type. Whatever is placed in query text (labels, relationship types, property names) is checked
against a whitelist and an identifier pattern and backtick-quoted.

## 6. Documented vs inferred vs candidate
Two questions are kept apart: *what does the stored record say about itself* (`evidence_status`) and *how did
we reach the claim* (`derivation`).
| claim_class | When | Example |
|---|---|---|
| **documented** | one canonical edge: actor -USES-> technique | ATT&CK says the group uses T1059.001 |
| **inferred** | two canonical edges chained | actor -CONDUCTS-> campaign -USES-> technique |
| **candidate** | a GraphRAG/LLM edge (origin `graphrag`, evidence type llm/candidate/inferred) | an advisory sentence suggests a link |
Rules: a candidate is never upgraded; if a technique is both documented and candidate, it is documented and
flagged `also_reported_as_candidate`; a stored record with no recognisable evidence field is `unclassified`
(shown, not silently promoted). The live check asserts that nothing is "documented" without a direct canonical edge.

## 7. What was built
| Path | Role |
|---|---|
| `neo4j_engine/connection/client.py` | settings from `.env`, read-only client (READ transactions, 30 s timeout, write-keyword guard, CA-bundle support, index-only schema writer) |
| `neo4j_engine/schema/introspect.py` | reads labels, relationship types, property names/types, counts, indexes, constraints |
| `neo4j_engine/schema/mapping.py` | `GraphMap`: logical field -> real property; identifier/label/relationship whitelists |
| `neo4j_engine/schema/indexes.py` | range + text index on `Entity.name` (`IF NOT EXISTS`, applied only with `--apply-indexes`) |
| `neo4j_engine/queries/cypher.py` | the Cypher builders (all parameterised) |
| `neo4j_engine/repositories/evidence.py` | documented / inferred / candidate rules |
| `neo4j_engine/repositories/graph_repository.py` | `find_entities`, `resolve_entity`, `get_entity`, `neighbors`, `techniques_for_actor`, `find_path`, `provenance`, `candidate_evidence`, `changed_since` |
| `neo4j_engine/cli.py` | command line for all of the above |
| `scripts/check_neo4j_retrieval.py` | live check (cross-checks every result against an independent Cypher count) |
| `scripts/apply_milestone_11_docs.py` | writes the change report with the real numbers; refuses unless the check passed |
| `tests/unit/test_neo4j_retrieval.py` | 34 tests with a fake client |

## 8. The query catalogue
| Function | Question it answers | Notes |
|---|---|---|
| `find_entities(text)` | "what is T1059.001 / apt29?" | ranks exact id > exact name > alias > prefix > contains |
| `resolve_entity(ref)` | name or id -> exactly one entity | raises `AmbiguousEntity` rather than guessing |
| `get_entity(id)` | the node plus its degree per relationship type | |
| `neighbors(id, rel_types)` | one hop | candidates excluded by default |
| `techniques_for_actor(actor)` | the Done-when query of the roadmap | see section 4 |
| `find_path(a, b, max_hops<=5)` | multi hop | `shortestPath`; candidates excluded by default |
| `provenance(id)` | where does this come from? | text units, communities, advisories that mention it |
| `candidate_evidence(id)` | GraphRAG relationships with their source text | |
| `changed_since(date)` | temporal | needs a date property; otherwise says so |

## 9. Safety built in
READ transactions + write-keyword refusal (every generated query is tested against it) | parameters only |
label / relationship / property whitelists | `LIMIT` on everything (max 1,000) | hops capped at 5 |
timeouts | `ReadOnlyViolation`, `AmbiguousEntity`, `EntityNotFound`, `CapabilityUnavailable` are explicit
errors, never empty "success".

## 10. Run order (PowerShell, from C:\CyberIntelGraph, venv with the neo4j driver active)
```powershell
python -m unittest tests.unit.test_neo4j_retrieval -v          # offline, expect: Ran 34 tests ... OK
python neo4j_engine\cli.py schema --write                      # what is really in Aura; shows resolved fields
python neo4j_engine\cli.py schema --apply-indexes              # creates the 2 name indexes (idempotent)
python neo4j_engine\cli.py find "T1059.001"
python neo4j_engine\cli.py actor-techniques "APT29"
python neo4j_engine\cli.py path APT29 T1059.001
python scripts\check_neo4j_retrieval.py                        # the gate
python scripts\apply_milestone_11_docs.py                      # only after the gate passes
```
If the connection fails with a database error, set `NEO4J_DATABASE=neo4j` in `.env` (Aura Free databases are
normally named `neo4j`; the credentials file lists the instance id instead, which your M10 sync did not use).

## 11. Honest limits
- Written and unit-tested **without access to your Aura database** (the development environment cannot reach it).
  The 34 tests use a fake client; the live check has been exercised only against a simulated one.
  Real results come from your machine.
- Property names are discovered, not known; if `schema` shows a field under an unexpected name, add it to the
  candidate lists in `schema/mapping.py`.
- Direction of CONDUCTS, MENTIONS, EXTRACTED_FROM, IN_COMMUNITY is matched undirected because it was not visible.
- How canonical ATT&CK edges store their evidence (property names) is not known; they are classed `structured`
  or `unclassified` from `origin` / evidence-type if present. Nothing is guessed beyond that.
- `via_software` counts only Malware and Tool nodes; group-uses-software-uses-technique is a weaker, derived claim.
- No LLM is involved in M11; text-to-Cypher is deliberately not built (it would need its own validation milestone).
- The official GraphRAG searches (global / local / DRIFT / basic) are still not demonstrated; M11 does not change that.

## 12. Exam-style summary
- **M11 in one sentence:** parameterised, read-only Cypher functions that return graph answers with an evidence class.
- **Why introspect?** Wrong property names fail silently in Cypher.
- **Why parameters?** They keep user text from becoming query code.
- **Documented vs inferred vs candidate?** One canonical edge vs chained canonical edges vs LLM-extracted edge.
- **Why undirected for some edges?** Directions were not visible; USES direction is verified by the live check.
- **Neo4j vs GraphRAG vs RAG?** Neo4j = exact stored facts; GraphRAG = discovered structure and summaries; RAG = passages.
- **Done when (roadmap):** "techniques for threat actor X" returns techniques with evidence, marked documented vs inferred.
