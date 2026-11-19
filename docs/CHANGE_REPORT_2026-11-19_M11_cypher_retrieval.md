# Change report - Milestone 11: Cypher retrieval (live results, 2026-11-19)

Source: `outputs/reports/neo4j_retrieval_20261119T071326Z.json`  |  Result: **ALL CHECKS PASSED**

## Checks
| Status | Check | Detail |
|---|---|---|
| PASS | connected and schema read | 17 labels, 13 relationship types |
| PASS | expected labels exist |  |
| PASS | expected relationship types exist |  |
| PASS | id and name properties resolved | id=entity_id, name=name |
| WARN | optional fields | not present: ['node.date', 'rel.source_url', 'community.id'] |
| PASS | graph size matches the Milestone 10 sync |  |
| PASS | Milestone 11 indexes exist |  |
| PASS | exact id lookup T1059.001 ranks the canonical technique first | got AttackTechnique:T1059.001, expected AttackTechnique:T1059.001 |
| PASS | get_entity returns degree by relationship type | {"USES": 237, "MENTIONS": 21, "MITIGATES": 5, "PART_OF_TACTIC": 1, "SUBTECHNIQUE_OF": 1} |
| PASS | techniques_for_actor documented count equals an independent Cypher count | Kimsuky: function 130 vs Cypher 130 |
| PASS | every technique has a valid claim class | {'documented': 130, 'inferred': 58, 'candidate': 0, 'total': 188} |
| PASS | nothing is 'documented' without a direct canonical edge | [] |
| PASS | candidate-class techniques have no documented path | [] |
| PASS | USES direction is actor -> technique | directed 130, undirected 130 |
| PASS | neighbors count equals the degree total | neighbors 149, degree 149 |
| PASS | shortest path actor -> its technique is 1 hop | 1 |
| PASS | candidate provenance reaches a text unit | AttackTechnique:cand-backup-restore-files: 1 text unit(s), status candidate |
| PASS | canonical entity provenance lists the advisories that mention it | AttackTechnique:T1016: 9 report(s) |
| WARN | temporal query works | no date property on entities; temporal retrieval reports itself unavailable |
| PASS | write queries are refused by the client |  |
| PASS | slowest query under 10 s | 1.0248 s: MATCH (a:Entity)-[r:`USES`]->(t:AttackTechnique) WHERE a.`entity_id` I |

## Resolved graph fields
```json
{
  "node": {
    "id": "entity_id",
    "name": "name",
    "aliases": "aliases",
    "description": "description",
    "origin": "origin",
    "evidence_type": "evidence_types",
    "source_url": "url",
    "date": null
  },
  "rel": {
    "id": "rel_id",
    "origin": "origin",
    "evidence_type": "evidence_type",
    "description": "description",
    "source_url": null
  },
  "textunit": {
    "id": "text_unit_id",
    "text": "text",
    "chunk_ids": "chunk_ids"
  },
  "community": {
    "id": null,
    "title": "title",
    "summary": "summary",
    "level": "level"
  },
  "from_introspection": true,
  "unresolved": [
    "node.date",
    "rel.source_url",
    "community.id"
  ]
}
```

## Example
`Kimsuky` (`ThreatActor:G0094`): {'documented': 130, 'inferred': 58, 'candidate': 0, 'total': 188}

Queries run: 31; slowest: 1.0248 s.

## Warnings to review
- optional fields: not present: ['node.date', 'rel.source_url', 'community.id']
- temporal query works: no date property on entities; temporal retrieval reports itself unavailable
