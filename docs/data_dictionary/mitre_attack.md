# Data source: MITRE ATT&CK (Enterprise, STIX 2.1)

| Item | Value |
|---|---|
| Source name | MITRE ATT&CK, Enterprise domain |
| Official repository | https://github.com/mitre-attack/attack-stix-data |
| Index (used to pick the release) | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json |
| File downloaded | One versioned bundle, e.g. `enterprise-attack/enterprise-attack-20.0.json` (about 55 MB) |
| Collection method | HTTP GET of the official files (no git clone, no scraping). Mobile and ICS domains are not downloaded. |
| Data format | STIX 2.1 JSON bundle: `{"type": "bundle", "id": ..., "objects": [...]}` |
| Identifiers | STIX id (`attack-pattern--<uuid>`) and ATT&CK id from the `mitre-attack` external reference (`T1566`, `G0007`, `S0002`, ...) |
| Collector | `ingestion/collectors/mitre_attack/collector.py` |
| Raw location | `data/raw/mitre_attack/enterprise-attack-<version>__<time>.json`, `index__<time>.json`, `.meta.json` sidecars |
| Processed location | `data/processed/attack_objects_normalized.json`, `attack_relationships_normalized.json` |
| Release profiled during development | Enterprise ATT&CK **20.0** (index modified 2026-10-13): 26,690 STIX objects |
| Collection date on your PC | **fill in after your first run** |
| Verified on your PC? | **NO - fill in after your first run.** (The structure below was verified on the real v20.0 file in the development environment.) |
| License / usage terms | Read the ATT&CK terms of use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) and paste the exact wording here. |

## Release choice
`index.json` lists every release. The collector takes the **highest version** of "Enterprise ATT&CK" (numeric order, so 19.2 < 20.0),
downloads that versioned file and records the version in every record (`attack_version`). A released version never changes,
so a verified copy on disk is not downloaded again. Pin one with `--version 20.0`.

## Objects in the v20.0 bundle (all types)
`relationship` 21,819 | `x-mitre-analytic` 1,770 | `attack-pattern` 867 | `malware` 750 | `x-mitre-detection-strategy` 705 |
`course-of-action` 268 | `intrusion-set` 193 | `x-mitre-data-component` 109 | `tool` 95 | `campaign` 57 | `x-mitre-data-source` 38 |
`x-mitre-tactic` 15 | `x-mitre-collection` 1 | `x-mitre-matrix` 1 | `identity` 1 | `marking-definition` 1.

## What is kept (normalized)
Only **active** objects (not `revoked`, not `x_mitre_deprecated`) of these types. Counts for v20.0:

| STIX type | Meaning | ATT&CK id | Kept (v20.0) |
|---|---|---|---|
| `attack-pattern` | technique / sub-technique | `T1234`, `T1234.001` | 706 (479 sub-techniques) |
| `x-mitre-tactic` | tactic | `TA0001` | 15 |
| `intrusion-set` | group (threat actor) | `G0001` | 178 |
| `malware` | malware | `S0001` | 747 |
| `tool` | tool | `S0002` | 95 |
| `campaign` | campaign | `C0001` | 57 |
| `course-of-action` | mitigation | `M1001` | 44 |

Excluded from the normalized files but still in the raw file: 403 revoked/deprecated objects, and the detection content types
(`x-mitre-analytic`, `x-mitre-detection-strategy`, `x-mitre-data-source`, `x-mitre-data-component`).

## Relationships kept (20,957 in v20.0), STIX direction preserved
| Source -> relationship -> target | Count |
|---|---:|
| malware uses attack-pattern | 10,739 |
| intrusion-set uses attack-pattern | 4,815 |
| course-of-action mitigates attack-pattern | 1,477 |
| campaign uses attack-pattern | 1,213 |
| tool uses attack-pattern | 869 |
| intrusion-set uses malware | 691 |
| attack-pattern subtechnique-of attack-pattern | 479 |
| intrusion-set uses tool | 475 |
| campaign uses malware | 92 |
| campaign uses tool | 81 |
| campaign attributed-to intrusion-set | 26 |

Excluded: `revoked-by` pointers (157), `detects` relationships (703, detection content out of scope), relationships touching a
revoked/deprecated object (2). Milestone 5 maps these to canonical relationships, for example reversing
`campaign attributed-to intrusion-set` into `ThreatActor -CONDUCTS-> Campaign`.

## Normalized object fields
Common: `record_id` (`attack:<id>`), `stix_id`, `stix_type`, `attack_id`, `name`, `description`, `attack_url`, `created`, `modified`,
`object_version`, `domains`, `aliases` (from `aliases` or `x_mitre_aliases`), `platforms`, `external_references` (the citations: source name, id, url, text).
Technique: `is_subtechnique`, `tactics` (tactic shortnames), `parent_attack_id`. Tactic: `shortname`. Malware: `is_family`. Campaign: `first_seen`, `last_seen`.
Provenance on every record: `source_name`, `source_url`, `source_record_id`, `retrieved_at`, `published_at` (= created), `last_modified_at` (= modified),
`original_format` (`stix-2.1-json`), `raw_file_reference`, `collection_method`, `attack_version`, `evidence_type` (`structured_authoritative_record`).

## Things worth knowing
- **Tactic names changed.** In v20.0 the tactic shortnames include `stealth` and `defense-impairment`; older ATT&CK versions (and many articles and models' memory)
  use `defense-evasion`. Questions about "Defense Evasion" need the version in mind. Always read tactics from the data.
- Techniques link to tactics through `kill_chain_phases`, not through relationships. Sub-techniques link to parents through `subtechnique-of`.
- The same real-world actor can appear under several names; ATT&CK `aliases` are kept, matching to advisory text is a Milestone 5 task.
- ATT&CK records what has been publicly reported and curated. A missing link is not proof that something never happened.

## Known limitations
- Enterprise domain only (no Mobile or ICS).
- Detection content (analytics, detection strategies, data sources) is not normalized yet.
- Counts above are for release 20.0. A newer release will differ; pin `--version 20.0` to reproduce them.
