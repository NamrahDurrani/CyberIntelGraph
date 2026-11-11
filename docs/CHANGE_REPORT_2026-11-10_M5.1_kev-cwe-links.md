# Change report - 2026-11-10 - Milestone 5.1: read CWE ids from KEV

Correction to Milestone 5 (commit 3cd7374, left unchanged). Separate commit.

## Problem
The Milestone 5 builder created `HAS_WEAKNESS` links only from NVD records. KEV
records carry a `cwes` field that was ignored, so most KEV vulnerabilities had
no weakness link (171 edges in total).

## Change
- `canonical/build.py`: CWE linking moved into one shared `_link_weaknesses()`
  used by both `from_nvd` and `from_kev`; unresolved entries are de-duplicated;
  the build summary reports HAS_WEAKNESS provenance; metadata gets
  `builder_revision: "5.1"`.
- `canonical/mappings.py`: one alias, `kev_cwes`.
- `tests/unit/test_canonical_kev_cwes.py`: 11 new tests.
- Unchanged: entity ids, schema (models.py, ids.py), checker, collectors,
  raw and processed data.

## Rules
- A CWE reported by both KEV and NVD becomes ONE edge with two evidence records.
- Ids missing from the CWE catalog create no edge; they are logged once in
  `unresolved_references.json`.
- `NVD-CWE-noinfo` / `NVD-CWE-Other` and unparsable tokens create no edge and
  are counted in the build summary.

## Result (from the rebuilt data/canonical files)
| Item | Before (M5) | After (M5.1) |
|---|---|---|
| HAS_WEAKNESS edges | 171 | 1755 |
| of which KEV only / NVD only / both | n/a | 1584 / 37 / 134 |
| Vulnerabilities with a weakness link | n/a | 1596 |
| SUBTECHNIQUE_OF edges vs sub-technique entities | 479 / 479 | 479 / 479 |

Sub-techniques without a parent: 0.

Full totals: entities: 6,207 (Vulnerability 1,780; Weakness 1,415; Software 1,117; Malware 747; AttackTechnique 706; ThreatActor 178; Tool 95; Campaign 57; IntelligenceReport 53; Mitigation 44; AttackTactic 15) | relationships: 28,361 (USES 18,975; AFFECTS 2,408; HAS_WEAKNESS 1,755; MITIGATES 1,477; MENTIONS 1,184; CHILD_OF 1,176; PART_OF_TACTIC 881; SUBTECHNIQUE_OF 479; CONDUCTS 26) | unresolved: 77
