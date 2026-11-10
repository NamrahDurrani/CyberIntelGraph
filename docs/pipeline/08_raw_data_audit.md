# Pipeline step: raw data audit (Milestone 4)

Files: `ingestion/validation/audit_raw_data.py`, `config/dataset_targets.json`, `scripts/protect_raw_data.ps1`, `tests/unit/test_audit_raw_data.py`.

## In plain words
Milestone 3 gave us five filing cabinets. Milestone 4 is the **inspector's visit**: is every drawer complete, is every document still exactly as received, is the paperwork fresh,
do the cabinets agree with each other, and has anything confidential leaked out of the building? Only then do we start building on top.
(Analogy: before an architect designs a house, a surveyor confirms the ground is solid.)

## What the audit does
| # | Check | Severity if it goes wrong |
|---|---|---|
| 1 | Every recorded raw file exists and matches its SHA-256 and size; orphans (on disk, recorded nowhere); identical duplicates | missing / changed = **FAIL**; orphans = WARN |
| 2 | Freshness: age of the newest download (default limit 30 days) and each source's own version or date | WARN |
| 3 | Processed data: record counts re-read from disk; a processed file missing while raw exists | missing = **FAIL** |
| 4 | Dataset targets from `config/dataset_targets.json` (NVD 150-200, KEV subset 50-75, advisories 50-75 ...) | below target = WARN |
| 5 | Cross-source: NVD vs KEV, CWE ids vs the catalog, advisory mentions vs KEV / NVD / ATT&CK / CWE, NVD's CISA dates vs KEV | disagreements = WARN |
| 6 | Field inventory: which raw fields occur, which we use, which we ignore, which we read but never see | read-but-never-seen = WARN |
| 7 | Storage: nothing from `data/`, `outputs/`, `logs/`, `.env` tracked by Git; `.env` ignored | **FAIL** |
| 8 | The five independent check scripts (the Milestone 3 gate) | any failing = **FAIL** |
| 9 | Data dictionary pages exist and are not still marked "not verified" | WARN |

## Run it
```powershell
cig                              # or: cd to your project folder
.\.venv\Scripts\Activate.ps1
python ingestion\validation\audit_raw_data.py --write-doc
```
Takes under a minute (it reads the 55 MB ATT&CK bundle once). Options: `--fast` skips the heavy field inventory, `--skip-checks` skips the five check scripts, `--max-age-days 7` for a stricter freshness limit.

**Outputs**
- Console summary (sources table, targets, findings).
- `outputs/reports/raw_data_audit_<time>.json` (ignored by Git).
- `docs/data_dictionary/RAW_DATA_AUDIT.md`: tracked by Git; contains the real field inventory for every source. Commit it.

**Exit code:** 0 when there is no FAIL. WARN findings are questions to answer, not errors.

## Optional: lock the raw files
```powershell
.\scripts\protect_raw_data.ps1            # raw files become read-only (manifest.jsonl stays writable)
.\scripts\protect_raw_data.ps1 -Unprotect # undo, for example before deleting a bad download
```
Collectors keep working: they only create new files. The audit tells you how many raw files are read-only.

## Reading the findings
| Finding | What to do |
|---|---|
| `target not met: advisories 50-75 (actual 46)` | Collect more: see the `--discover` section in `07_advisories_collector.md` |
| `N CWE id(s) used by NVD data are not in the CWE catalog` | After the CWE category fix this should be 0 or a few retired ids; list them in the next review |
| `technique id(s) in advisory text belong to the ATT&CK for ICS matrix` (INFO) | Ids T0800-T0899 are ICS techniques; we collect Enterprise only (decision 0003). Not a problem; a scope question for later |
| `ATT&CK-style id(s) ... are neither active Enterprise techniques nor ICS ids` (WARN) | Retired techniques, Mobile ids, or text that only looks like an id |
| `NVD record(s) carry a CISA exploit-added date that differs from KEV` | A real source conflict: keep both, flag it in the canonical layer (Milestone 5) |
| `fields our normalizer reads but that occur nowhere in the raw data` | A mapping may be dead or the source changed: tell me |
| `data dictionary ... still marked not verified` | Update that page after reviewing the audit |
| `[FAIL] ... tracked by Git` | `git rm --cached <file>` and fix `.gitignore` before committing again |
