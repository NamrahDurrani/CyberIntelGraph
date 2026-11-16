# Change report - Milestone 9b: official Microsoft GraphRAG run

GraphRAG 3.3.0 in `.venv-graphrag`, chat model Groq openai/gpt-oss-20b, local bge-small embeddings, settings in
`graphrag_engine/indexing/ms/settings.yaml`, output in `data/graphrag_outputs/output` (not committed).
The real schema is recorded in `docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md`.

## Result of the run
- documents 1 | text units 8 | entities 106 | relationships 81 | communities 8 | community reports 8
- cached LLM/embedding responses on disk: 53  by folder: {'community_reporting': 8, 'extract_graph': 8, 'summarize_descriptions': 28, 'text_embedding': 9}
- entity types: ATTACK_TECHNIQUE=51, SOFTWARE=15, MITIGATION=12, SECTOR=10, ORGANIZATION=9, MALWARE=3, VULNERABILITY=2, TOOL=2, THREAT_ACTOR=1, CAMPAIGN=1
- top 10 entities by degree: APT ACTORS [THREAT_ACTOR] deg 13; TOOL [TOOL] deg 12; CISA [ORGANIZATION] deg 9; NSA [ORGANIZATION] deg 8; OPERATIONAL TECHNOLOGIES [SECTOR] deg 8; DOE [ORGANIZATION] deg 7; FBI [ORGANIZATION] deg 7; ICS/SCADA [SECTOR] deg 7; MITIGATIONS [MITIGATION] deg 6; OT [SECTOR] deg 6
- entities whose title contains a CVE id: 1; an ATT&CK id: 0
- relationship columns: ['id', 'human_readable_id', 'source', 'target', 'description', 'weight', 'combined_degree', 'text_unit_ids'] (no relationship-type column unless listed)
- relationship weight: min 6.0, median 8.0, max 25.0
- communities per level: level 0: 5, level 1: 3
- community report titles (by rank): APT Actors and Chernovite's Pipedream in Industrial Control Systems (rank 8.5); INCONTROLLER and Mandiant Analysis Community (rank 8.5); Industrial Control Systems Threat Landscape (rank 8.5); CISA‑DOE‑NSA‑FBI OT Security Community (rank 8.5); APT Actors and Industrial Control System Threat Landscape (rank 8.5); APT Tool Targeting Schneider and OMRON PLCs (rank 8.5); Industrial Control Systems & OT Security Community (rank 8.5); OPC UA and OT Security Community (rank 8.5)

## What Milestone 10 must handle (read from the real output)
- Entity `type` values come from the prompt's list, upper-cased (for example THREAT_ACTOR); there are no canonical ids.
- Relationships carry source and target TITLES, a description and a weight, but no relationship type.
- Every entity, relationship and text unit keeps `text_unit_ids`; text units map back to our chunk ids through `input_manifest.json`.
