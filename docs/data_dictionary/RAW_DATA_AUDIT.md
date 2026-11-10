# Raw Data Audit (generated)

*Generated 2026-11-10T08:31:55+00:00 by `ingestion/validation/audit_raw_data.py`. Do not edit by hand: run the audit again.*

**Result:** 0 FAIL, 1 WARN, 11 INFO

## 1. Raw files per source

| Source | Recorded downloads | Verified (SHA-256) | Missing | Changed | Orphans | Bytes | Newest download | Age (days) |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| CISA KEV | 1 | 1 | 0 | 0 | 0 | 1,826,755 | 2026-11-01T08:40:33.249909+00:00 | 9.0 |
| NVD | 150 | 150 | 0 | 0 | 0 | 1,366,326 | 2026-11-01T13:29:05.795216+00:00 | 8.8 |
| MITRE ATT&CK | 2 | 2 | 0 | 0 | 0 | 55,304,178 | 2026-11-02T08:38:03.027607+00:00 | 8.0 |
| CWE | 1 | 1 | 0 | 0 | 0 | 2,119,263 | 2026-11-03T09:18:34.582117+00:00 | 7.0 |
| CISA advisories | 61 | 61 | 0 | 0 | 0 | 7,749,440 | 2026-11-10T08:27:04.903700+00:00 | 0.0 |

## 2. Processed data

| Source | Numbers (re-read from disk) | Source's own version / date |
|---|---|---|
| CISA KEV | records 1,766, initial_subset_records 75 | 2026.10.30 / 2026-10-30T17:02:45.3665Z |
| NVD | records 150 | - / 2026-10-26T20:10:00.160 |
| MITRE ATT&CK | objects 1,842, relationships 20,957 | 20.0 / - |
| CWE | records 1,415, weaknesses 984, categories 0, other_entries 431, views 62, initial_subset_records 254 | 5.0 / 2026-10-28 |
| CISA advisories | documents 53, words 269,719 | - / 2026-10-20 |

## 3. Dataset targets

| Source | Metric | Target | Actual | Status |
|---|---|---|---:|---|
| NVD | records | 150-200 | 150 | MET |
| CISA KEV | initial_subset_records | 50-75 | 75 | MET |
| MITRE ATT&CK | objects | 1+ | 1842 | MET |
| CWE | initial_subset_records | 1+ | 254 | MET |
| CISA advisories | documents | 50-75 | 53 | MET |

Targets are initial targets, not permanent limits (see the master prompt and decision records 0002-0004).

## 4. Cross-source checks

- **nvd_in_kev**: `{"matched": 150, "total": 150}`
- **kev_subset_in_nvd**: `{"matched": 75, "total": 75}`
- **nvd_cwe_in_catalog**: `{"matched": 51, "total": 51, "missing": []}`
- **kev_cwe_in_catalog**: `{"matched": 198, "total": 198, "missing": []}`
- **advisory_cwe_in_catalog**: `{"matched": 41, "total": 41, "missing": []}`
- **advisory_cves**: `{"total": 175, "in_kev": 161, "in_nvd_set": 36, "in_neither": 14, "not_in_kev_examples": ["CVE-2020-15368", "CVE-2021-31206", "CVE-2021-33768", "CVE-2021-34470", "CVE-2021-45105", "CVE-2022-22972", "CVE-2022-22973", "CVE-2023-3466", "CVE-2023-3467", "CVE-2023-4967"]}`
- **advisory_attack_ids**: `{"total": 335, "known": 279, "ics_matrix": ["T0801", "T0803", "T0804", "T0807", "T0809", "T0812", "T0813", "T0814", "T0815", "T0816", "T0821", "T0826", "T0827", "T0828", "T0831", "T0832", "T0834", "T0836", "T0837", "T0842"], "ics_matrix_count": 39, "unknown": ["T1047.001", "T1070.001", "T1101.001", "T1101.003", "T1451", "T1532", "T1562", "T1562.001", "T1562.004", "T1562.009", "T1562.010", "T1574.002", "T1604", "T1627", "T1627.001"], "unknown_count": 17}`
- **nvd_cisa_dates**: `{"compared": 150, "records_without_field": 0, "added_mismatch": [], "due_mismatch": []}`

## 5. Field inventory (what really occurs in the raw data)

For each source: fields we **use**, fields that occur but are **ignored** (with how often), and fields we expect but never saw.

### CISA KEV

1766 records.
**Envelope**
- used (5): catalogVersion, count, dateReleased, title, vulnerabilities
- ignored: none
**Record fields**
- used (11): cveID, cwes, dateAdded, dueDate, knownRansomwareCampaignUse, notes, product, requiredAction, shortDescription, vendorProject, vulnerabilityName
- ignored: forensicTriage (1766)

**Fields we read that occur nowhere in this source:** none

### NVD

150 CVE records; CVSS metric versions seen: {'cvssMetricV31': 150, 'ssvcV203': 150, 'cvssMetricV2': 20, 'cvssMetricV40': 12, 'cvssMetricV30': 12}.
**cve object**
- used (14): cisaActionDue, cisaExploitAdd, cisaRequiredAction, cisaVulnerabilityName, configurations, descriptions, id, lastModified, metrics, published, references, sourceIdentifier, vulnStatus, weaknesses
- ignored: cveTags (150), affected (150)

**Fields we read that occur nowhere in this source:** none

### CISA advisories

53 documents; non-empty fields: {'release_date': 19, 'last_revised': 34, 'alert_code': 53, 'advisory_type': 53, 'archived': 20, 'published_at': 53, 'attachments': 53, 'mentioned_cve_ids': 33, 'mentioned_attack_ids': 43, 'mentioned_cwe_ids': 9}; dates derived from alert codes: 34.

**Fields we read that occur nowhere in this source:** none

### MITRE ATT&CK

Release 20.0.
**campaign**
- used (14): aliases, created, description, external_references, first_seen, id, last_seen, modified, name, revoked, type, x_mitre_deprecated, x_mitre_domains, x_mitre_version
- ignored: spec_version (57), created_by_ref (57), object_marking_refs (57), x_mitre_first_seen_citation (57), x_mitre_last_seen_citation (57), x_mitre_modified_by_ref (57), x_mitre_attack_spec_version (57), x_mitre_contributors (16)
**course-of-action**
- used (11): created, description, external_references, id, modified, name, revoked, type, x_mitre_deprecated, x_mitre_domains, x_mitre_version
- ignored: spec_version (44), created_by_ref (44), object_marking_refs (44), x_mitre_modified_by_ref (44), x_mitre_attack_spec_version (44)
**intrusion-set**
- used (12): aliases, created, description, external_references, id, modified, name, revoked, type, x_mitre_deprecated, x_mitre_domains, x_mitre_version
- ignored: spec_version (178), created_by_ref (178), object_marking_refs (178), x_mitre_modified_by_ref (178), x_mitre_attack_spec_version (178), x_mitre_contributors (100)
**malware**
- used (14): created, description, external_references, id, is_family, modified, name, revoked, type, x_mitre_aliases, x_mitre_deprecated, x_mitre_domains, x_mitre_platforms, x_mitre_version
- ignored: spec_version (747), created_by_ref (747), object_marking_refs (747), x_mitre_modified_by_ref (747), x_mitre_attack_spec_version (747), x_mitre_contributors (170)
**tool**
- used (13): created, description, external_references, id, modified, name, revoked, type, x_mitre_aliases, x_mitre_deprecated, x_mitre_domains, x_mitre_platforms, x_mitre_version
- ignored: spec_version (95), created_by_ref (95), object_marking_refs (95), x_mitre_modified_by_ref (95), x_mitre_attack_spec_version (95), x_mitre_contributors (27)
**attack-pattern**
- used (14): created, description, external_references, id, kill_chain_phases, modified, name, revoked, type, x_mitre_deprecated, x_mitre_domains, x_mitre_is_subtechnique, x_mitre_platforms, x_mitre_version
- ignored: spec_version (706), created_by_ref (706), object_marking_refs (706), x_mitre_attack_spec_version (706), x_mitre_modified_by_ref (706), x_mitre_contributors (440), x_mitre_remote_support (55), x_mitre_impact_type (33)
**x-mitre-tactic**
- used (12): created, description, external_references, id, modified, name, revoked, type, x_mitre_deprecated, x_mitre_domains, x_mitre_shortname, x_mitre_version
- ignored: spec_version (15), created_by_ref (15), object_marking_refs (15), x_mitre_modified_by_ref (15), x_mitre_attack_spec_version (15)

**Fields we read that occur nowhere in this source:** none

### CWE

**Weakness: attributes**
- used (5): Abstraction, ID, Name, Status, Structure
- ignored: Diagram (89)
**Weakness: child elements**
- used (8): Applicable_Platforms, Content_History, Description, Extended_Description, Mapping_Notes, Related_Attack_Patterns, Related_Weaknesses, Taxonomy_Mappings
- ignored: Modes_Of_Introduction (956), Common_Consequences (954), Weakness_Ordinalities (942), Potential_Mitigations (692), References (629), Detection_Methods (605), Demonstrative_Examples (604), Observed_Examples (596), Notes (377), Likelihood_Of_Exploit (184), Background_Details (177), Alternate_Terms (129), Functional_Areas (119), Affected_Resources (115), Dimensions (107), Technical_Nuance (53)
**Grouping: attributes**
- used (3): ID, Name, Status
- ignored: none
**Grouping: child elements**
- used (5): Content_History, Mapping_Notes, Relationships, Summary, Taxonomy_Mappings
- ignored: References (268), Notes (69)
**View: attributes**
- used (3): ID, Name, Status
- ignored: Type (62)
**View: child elements**
- used (3): Content_History, Mapping_Notes, Objective
- ignored: Members (43), Audience (42), References (38), Notes (26), Filter (17)

**Fields we read that occur nowhere in this source:** none

## 6. Check scripts (Milestone 3 gate)

- CISA KEV: **PASS**
- NVD: **PASS**
- MITRE ATT&CK: **PASS**
- CWE: **PASS**
- CISA advisories: **PASS**

## 7. Storage hygiene

- Git repository: True
- Tracked files from data/outputs/logs/.env: 0
- .env ignored by Git: True

## 8. Findings

| Severity | Area | Finding |
|---|---|---|
| WARN | Cross-source | 17 ATT&CK-style id(s) in advisory text are neither active Enterprise techniques nor ICS ids (retired, Mobile, or not really ATT&CK ids): ['T1047.001', 'T1070.001', 'T1101.001', 'T1101.003', 'T1451', 'T1532'] |
| INFO | CISA KEV | 1 raw file(s) verified against their SHA-256 (1,826,755 bytes) |
| INFO | CISA advisories | 61 raw file(s) verified against their SHA-256 (7,749,440 bytes) |
| INFO | CWE | 1 raw file(s) verified against their SHA-256 (2,119,263 bytes) |
| INFO | Cross-source | 150/150 NVD records are also in KEV (the default NVD set is built from KEV) |
| INFO | Cross-source | advisories mention 175 distinct CVEs: 161 in KEV, 36 in our NVD set, 14 in neither |
| INFO | Cross-source | 39 technique id(s) in advisory text belong to the ATT&CK for ICS matrix (T08xx), which is not collected (decision 0003, Enterprise only): ['T0801', 'T0803', 'T0804', 'T0807', 'T0809', 'T0812'] |
| INFO | Cross-source | NVD's embedded CISA 'exploit added' dates agree with KEV for all 150 compared records |
| INFO | MITRE ATT&CK | 2 raw file(s) verified against their SHA-256 (55,304,178 bytes) |
| INFO | NVD | 150 raw file(s) verified against their SHA-256 (1,366,326 bytes) |
| INFO | Storage | no files from data/, outputs/, logs/, .env or .venv are tracked by Git (only .gitkeep placeholders) |
| INFO | Storage | 0/215 raw files are read-only. Optional protection: .\scripts\protect_raw_data.ps1 |
