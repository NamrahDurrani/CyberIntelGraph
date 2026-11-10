# Decision 0006 - Canonical model and stable identifiers (Milestone 5)

Status: accepted - 2026-11-10

## Context
Milestones 3-4 produced five independent, audited source datasets (KEV, NVD,
ATT&CK Enterprise, CWE, CISA advisories). Each names things differently
(KEV free-text vendors, NVD CPE slugs, ATT&CK STIX UUIDs). GraphRAG, Neo4j and
the agent need ONE identity per real-world thing, with provenance.

## Decisions
1. **Identity format:** `<EntityType>:<natural key>`, deterministic, so reruns
   never create duplicates (idempotent; maps directly to Neo4j `MERGE`).
   Vulnerability -> CVE id; Weakness -> CWE-n; AttackTechnique/Tactic/
   ThreatActor/Malware/Tool/Campaign/Mitigation -> ATT&CK id (T/TA/G/S/C/M);
   Software -> `vendorslug/productslug`; IntelligenceReport -> slug of advisory id/url.
2. **Software resolution:** vendor and product are lower-cased and stripped of
   non-alphanumerics, so KEV "Palo Alto Networks / PAN-OS" and NVD
   "paloaltonetworks / pan-os" become the same `Software:paloaltonetworks/panos`.
3. **Entities (12):** Vulnerability, Weakness, Software, AttackTactic,
   AttackTechnique, ThreatActor, Malware, Tool, Campaign, Mitigation,
   IntelligenceReport, Organization (defined; not populated - no source yet).
4. **Relationships (allow-list):** HAS_WEAKNESS, AFFECTS, CHILD_OF,
   PART_OF_TACTIC, SUBTECHNIQUE_OF, USES, MITIGATES, CONDUCTS, MENTIONS. Any
   (source type, relation, target type) not in `canonical/mappings.py::ALLOWED`
   is skipped and counted, never silently stored.
5. **Direction:** ATT&CK `Campaign --attributed-to--> Group` is stored as
   `ThreatActor --CONDUCTS--> Campaign`. Names/directions are mapped explicitly.
6. **Evidence:** every entity and relationship carries `Evidence` (source,
   record_ref, raw_file_reference, URL, retrieved_at, evidence_type) using the
   five evidence types. KEV/NVD/ATT&CK/CWE facts = `structured_authoritative`;
   advisory mentions = `stated_in_source`. `llm_extracted_candidate`,
   `human_reviewed`, `inferred` are reserved for Milestones 9+.
7. **Advisory-only CVEs** become `Vulnerability` stubs (`stub=true`) so
   MENTIONS edges never dangle; they are filled in if KEV/NVD later cover them.
8. **Unresolved references are kept, not dropped:** ATT&CK ids in advisory text
   that are not active Enterprise techniques go to `unresolved_references.json`
   with a reason (`ics_matrix_not_collected` for T08xx, otherwise
   `not_active_enterprise_technique`). This is the Milestone 4 WARN.
9. **NVD placeholders** (`NVD-CWE-noinfo`, `NVD-CWE-Other`) are not Weakness
   nodes; they are counted as skipped.
10. **CWE groupings** are kept as `Weakness` entities with
    `element_type='grouping'` (CWE v5.0 has no `Category` elements).

## Consequences
Canonical files live in `data/canonical/` (not tracked by Git; rebuildable).
Revoked/deprecated ATT&CK objects are absent because the Milestone 3 processed
file already excludes them.
