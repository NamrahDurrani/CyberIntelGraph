# Change report - Milestone 10: canonical graph and GraphRAG candidates in Neo4j

## Result (from the independent database check, `neo4j_check_20261117T095313Z.json`)
| Item | Value |
|---|---|
| Nodes in Neo4j | 6,313 |
| Relationships in Neo4j | 28,616 |
| Canonical nodes by type | AttackTactic 15 · AttackTechnique 706 · Campaign 57 · IntelligenceReport 53 · Malware 747 · Mitigation 44 · Software 1,117 · ThreatActor 178 · Tool 95 · Vulnerability 1,780 · Weakness 1,415 |
| GraphRAG candidate nodes | 90 |
| Text units / communities | 8 / 8 |
| Relationships by type | AFFECTS 2,408 · CHILD_OF 1,176 · CONDUCTS 26 · EXTRACTED_FROM 135 · HAS_WEAKNESS 1,755 · IN_COMMUNITY 58 · MENTIONS 1,184 · MITIGATES 1,477 · PART_OF 8 · PART_OF_TACTIC 881 · RELATED_TO 54 · SUBTECHNIQUE_OF 479 · USES 18,975 |
| Vulnerabilities with a weakness link | 1,596 |
| Independent checks passed | 16 of 16 |
| Repeatability (`--verify-twice`) | PASS (second pass created nothing; confirmed by the operator) |

Warnings: none

## GraphRAG export (pilot advisory)
{
 "communities": 8,
 "entities_in": 106,
 "entities_skipped": {
  "advisory_author": 4
 },
 "entity_community_links": 58,
 "entity_text_unit_dangling": 0,
 "entity_text_unit_links": 135,
 "generic_nodes_scoped_to_advisory": 3,
 "nodes_ambiguous": 0,
 "nodes_candidate_only": 90,
 "nodes_in_canonical_graph": 10,
 "nodes_linked_to_canonical_id": 10,
 "nodes_noncanonical_type": 9,
 "nodes_out": 100,
 "nodes_without_relationships": 59,
 "relationships_in": 81,
 "relationships_invalid": 0,
 "relationships_out": 54,
 "relationships_skipped": {
  "endpoint_advisory_author": 27
 },
 "text_units": {
  "mapped": 8
 },
 "text_units_linked_to_report": 8
}

## Rules that keep printed facts and pencil notes apart
- Candidates carry labels `:Entity:Candidate`, `origin: graphrag`, evidence type `llm_extracted_candidate`.
- GraphRAG relationships are the separate type `RELATED_TO`; no canonical relationship touches a candidate.
- GraphRAG facts on an existing canonical node live in `gr_*` properties and never overwrite canonical properties.
- Every text unit maps back to our chunk ids; every candidate is linked to its text unit.

## Not done
Milestone 11 (indexes, Cypher retrieval functions); typing GraphRAG relationships; more than one advisory;
the official GraphRAG search methods and evidence validation (Milestones 9.5-9.6 in the migration plan).
