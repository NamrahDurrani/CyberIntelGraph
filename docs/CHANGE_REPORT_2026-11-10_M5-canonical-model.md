# Change report - 2026-11-10 - Milestone 5: canonical model

## Starting point
Milestones 1-4 complete (commit 805ffa6): five collectors, 145 unit tests OK,
raw data audit PASSED (0 FAIL, 1 WARN, 11 INFO).

## Added
- `canonical/` package (models, ids, mappings, build) - see docs/pipeline/09
- `scripts/inspect_processed_schema.py`, `scripts/check_canonical_output.py`
- `tests/unit/test_canonical.py` (12 tests)
- `docs/decisions/0006-canonical-model.md`, `docs/pipeline/09_canonical_model.md`
- `requirements.txt`: add `pydantic>=2`
- `.gitattributes` (line-ending normalisation; housekeeping from Milestone 4)

## Milestone 4 findings handled here
| Finding | Handling |
|---|---|
| 17 ATT&CK-style ids not active Enterprise/ICS | `unresolved_references.json` with reason |
| 39 ICS (T08xx) ids, matrix not collected | unresolved, reason `ics_matrix_not_collected` |
| 14 advisory CVEs in neither KEV nor NVD | `Vulnerability` stubs (`stub=true`) |
| NVD sample is 100% KEV | not changed; still a known limitation |

## Verification
Unit tests on synthetic fixtures: 12/12 OK. NOT yet run on the real data: run
inspect -> tests -> build -> check and record the counts below.

## Real-run results (fill in after running)
entities by type: ... | relationships by type: ... | unresolved: ... | check: ...
