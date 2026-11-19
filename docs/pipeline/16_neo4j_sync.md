# 16 - Milestone 10: GraphRAG output -> Neo4j (guide)

## 1. The idea, as a map room
So far your project has two filing cabinets: the **canonical** files (printed facts from KEV, NVD, ATT&CK, CWE) and GraphRAG's **parquet** files (what the analyst found in the advisories).
Milestone 10 builds one **wall map** in Neo4j. The printed facts go up first. GraphRAG's discoveries go up as **pencil notes** (label `Candidate`) unless they are the same thing as a printed fact, in which case
they are attached to the printed node. Every pencil note has a string back to the **source paragraph** (a `TextUnit`, and through it your own chunk ids). One direction only: files -> Neo4j.

## 2. What gets written
| In Neo4j | Meaning |
|---|---|
| `(:Entity:<Type> {entity_id, name, entity_type, origin})` | canonical entities (`origin: canonical`) and GraphRAG candidates (`origin: graphrag`, extra label `:Candidate`) |
| `gr_*` properties on a canonical node | what GraphRAG added (description, text units, frequency); canonical properties are never overwritten |
| `(a)-[:USES {rel_id, evidence_type, ...}]->(b)` | canonical relationships, each with its evidence |
| `(a)-[:RELATED_TO {weight, description, text_unit_ids, chunk_ids}]->(b)` | GraphRAG relationships (the real output has no relationship type) |
| `(:TextUnit {text_unit_id, text, chunk_ids})` | GraphRAG's chunks; `(:Entity)-[:EXTRACTED_FROM]->(:TextUnit)` and `(:TextUnit)-[:PART_OF]->(:IntelligenceReport)` |
| `(:Community {community_key, level, title, summary, rank})` | communities and their reports; `(:Entity)-[:IN_COMMUNITY]->(:Community)` |

## 3. Rules applied (from the roadmap and from what your real output showed)
- **Map to canonical types.** THREAT_ACTOR -> ThreatActor, MALWARE -> Malware ... Only SECTOR has no canonical type; it is kept and marked `canonical_type: false`.
- **Link or create a candidate.** CVE ids and ATT&CK ids reuse canonical ids. A name is linked only if exactly one compatible canonical entity has it; ambiguous names stay candidates (`<Type>:cand-<name>`).
- **Filter noise** with `config/graphrag_export_rules.json` (starter rules from the pilot): advisory authors (CISA, NSA, FBI, DOE ...) are dropped; alias merges (OT -> OPERATIONAL TECHNOLOGIES); **generic titles** (TOOL, APT ACTORS, MITIGATIONS ...) are *scoped*: each becomes one candidate node per advisory (`ThreatActor:cand-apt-actors-<advisory>`, `generic: true`) instead of being deleted. Reason: in the first real export, dropping them removed 48 of 81 relationships, because they were the graph's hubs. Set `"generic_mode": "drop"` in the rules to delete them instead. Every skip is counted with its reason (`endpoint_generic_title`, `endpoint_advisory_author`, `endpoint_unknown_title`, ...). Review and extend the file.
- **Validate relationship endpoints** before writing; invalid or dangling items are counted and dropped.
- **MERGE only**, in batches of 500, with uniqueness constraints on `entity_id`, `text_unit_id`, `community_key`. Nothing is ever deleted.
- **Idempotent**: `--verify-twice` runs the sync twice and fails unless the second pass creates nothing and the counts match (the roadmap's done-criterion).

## 4. Set up a free Neo4j Aura database (hosted, no local disk)
1. Create an account at neo4j.com (Aura console) and create an **AuraDB Free** instance. Neo4j's documentation lists the free tier at 200,000 nodes and 400,000 relationships, one database; check the current limits when you create it.
2. **Download the credentials file immediately.** The password is shown once.
3. Wait until the instance shows as running (it can take a few minutes).
4. Add to `C:\CyberIntelGraph\.env` (this file is git-ignored; confirm with `git check-ignore .env`):
```
NEO4J_URI=neo4j+s://<your-instance-id>.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=<password from the credentials file>
```
`NEO4J_USER` is accepted as an alternative to `NEO4J_USERNAME` (the repo's `.env.example` uses that name). `NEO4J_DATABASE` is optional; leave it out to use the default database. Do not paste the password into a chat.
Optional TLS settings (only if the connection fails with "Unable to retrieve routing information" or a certificate error): `NEO4J_TLS=certifi` trusts Python's certifi CA bundle instead of the Windows certificate store, `NEO4J_CA_BUNDLE=C:\path\root.pem` trusts your organisation's root certificate. The default (`auto`) tries the Windows store first and then certifi by itself.

## 5. Run it (two environments)
```powershell
cd C:\CyberIntelGraph

# A. export (graphrag venv - it has pandas/pyarrow)
.\.venv-graphrag\Scripts\Activate.ps1
python graphrag_engine\export\export_graphrag.py        # parquet -> data\graphrag_outputs\export\graphrag_graph.json, prints the report
deactivate

# B. sync (main venv)
.\.venv\Scripts\Activate.ps1
python -m pip install neo4j                              # small, pure Python
python graphrag_engine\synchronization\sync_neo4j.py --dry-run          # the plan, no connection
python graphrag_engine\synchronization\sync_neo4j.py --check-connection # proves the credentials, shows current counts
python graphrag_engine\synchronization\sync_neo4j.py --verify-twice     # writes, then proves it is repeatable
```
Read the export report before syncing: how many entities were skipped and why, how many nodes are linked or candidates, how many text units mapped, and whether the warning about report links appears.

## 6. Look at the result (Neo4j Query or Browser)
```cypher
MATCH (n:Entity) RETURN n.origin AS origin, count(*) AS nodes;
MATCH (n:Candidate) RETURN n.name, n.entity_type, n.gr_degree ORDER BY n.gr_degree DESC LIMIT 10;
MATCH (a)-[r:RELATED_TO]->(b) RETURN a.name, r.weight, b.name ORDER BY r.weight DESC LIMIT 10;
MATCH (e:Entity)-[:EXTRACTED_FROM]->(t:TextUnit) RETURN e.name, t.chunk_ids, left(t.text, 160) LIMIT 5;
MATCH (c:Community) RETURN c.level, c.title, c.rank ORDER BY c.rank DESC;
```

## 7. If something fails
| Symptom | Likely cause and fix |
|---|---|
| `missing NEO4J_URI ...` | The three variables are not in `.env` or the environment |
| Authentication error | Wrong password; the Aura password is only shown once, reset it in the console if lost |
| `Unable to retrieve routing information` or `SSLCertVerificationError`, although the port is reachable | The Windows certificate store on that machine could not verify Aura's certificate (on one machine Python reported "self-signed certificate in certificate chain" with the system store, while certifi's bundle verified the same server). `connect()` now retries with certifi automatically; add `NEO4J_TLS=certifi` to `.env` to skip the first attempt. If a company proxy inspects HTTPS, point `NEO4J_CA_BUNDLE` at its root certificate |
| Cannot connect / ServiceUnavailable | The instance is still starting or was paused when idle (free instances can be paused; check Aura's current policy); a corporate network may block the connection |
| `[warn] no text unit could be linked to a canonical IntelligenceReport` | The chunk `report_id` and the canonical report id differ; the warning prints one example of each; send them to me |
| `IDEMPOTENT: FAIL` | Something creates a new node or relationship on every pass; send the printed counts |
| `unsafe label / relationship type refused` | A type or label in the data is not a plain identifier; Cypher cannot parameterise them, so it is refused on purpose |

## 8. Scope
Not in this milestone (Milestone 11): the full constraint and index set, query functions, evidence and provenance queries. Not done: typing GraphRAG relationships (the output has no type), reviewing filter rules on more advisories.
Verified here only with an in-memory emulation of MERGE and a fake driver; the first run against real Aura is the true test.
