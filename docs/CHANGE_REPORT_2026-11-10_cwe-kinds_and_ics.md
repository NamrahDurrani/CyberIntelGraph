# Change Report: follow-up after your audit run (2026-11-10)

## What your output proved
| Result | Meaning |
|---|---|
| Advisories: 53 documents, all checks passed | The discovery fix worked; target 50-75 met |
| 19 of 19 stated Release Dates equal the date derived from the alert code | The `AAyy-ddd` convention behind the 34 derived dates holds on every page where it can be tested |
| Audit: all five targets MET, NVD's embedded CISA dates agree with KEV (150/150), nothing tracked by Git, 211 raw files verified | The raw data layer is sound |
| CWE subset 246 -> 254 and the "ids not in the catalog" warning gone | The parser fix works: the 8 missing ids are found |

## The two remaining items
| Item | Cause | Change |
|---|---|---|
| **FAIL: "0 categories found"** | The entries are in the file but are **not named `Category`**. My check looked for that one name, so it failed although the data is complete | `check_cwe_output.py` now checks "entries besides weaknesses (any kind)" and prints the kind names. The collector warning becomes an informational note when other kinds exist. Covered by 2 new tests and an end-to-end run on a synthetic file shaped like yours |
| **WARN: 15 ATT&CK-style ids not active techniques** (T0801, T0803, T0804 ...) | Ids T0800-T0899 belong to the **ATT&CK for ICS** matrix; we collect Enterprise only (decision 0003). They are mentions without an ATT&CK record to link to | The audit classifies them as INFO ("ICS matrix, not collected") and keeps WARN for ids that are neither Enterprise nor ICS. Decision 0003 got an amendment with the open question |

## Files
Changed: `scripts/check_cwe_output.py`, `ingestion/collectors/cwe/collector.py`, `ingestion/validation/audit_raw_data.py`, `tests/unit/test_cwe_collector.py`, `tests/unit/test_audit_raw_data.py`,
`docs/data_dictionary/cwe.md`, `docs/decisions/0003-mitre-attack-scope.md`, `docs/pipeline/08_raw_data_audit.md`, `CHANGELOG.md`, `PROJECT_STATUS.md`.

## Tested
145 unit tests pass. End-to-end CWE collector + check on a synthetic file with a differently named grouping section: SUCCESS and `ALL CHECKS PASSED`.
Not tested here: your real CWE file (I cannot download it); the real kind name is printed by your next collector run.

## Open decision (for Milestone 5)
Do you want ICS ATT&CK in the project (industrial control system advisories cite it)? Adding it is one more run of the same collector against the ICS collection in `index.json`; the answer changes nothing until then.
