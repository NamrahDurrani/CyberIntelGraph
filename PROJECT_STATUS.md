# Project Status

**Current milestone:** 3 - Collectors (KEV and NVD validated; ATT&CK built, to run; CWE and advisories next)

## Completed
- [x] Milestone 1: Python 3.12.10 venv, folder structure verified, pushed to GitHub
- [x] CISA KEV collector validated on the real feed (catalog 2026.10.30, 1766 records), committed d74e626
- [x] NVD collector validated on the real API with an API key (150/150 CVEs, all checks passed, 75/75 KEV subset covered)
- [x] MITRE ATT&CK collector written, 19 unit tests, run on the real v20.0 data in the development environment (1,842 objects, 20,957 relationships)
- [ ] NVD work committed and pushed (waiting for you to run the commit step)
- [ ] ATT&CK collector run on your PC and check script passed
- [ ] KEV, NVD, ATT&CK data dictionary pages confirmed against your real field lists
- [ ] ATT&CK work committed and pushed

## Working functionality
- `python ingestion\collectors\cisa_kev\collector.py` (confirmed on your PC)
- `python ingestion\collectors\nvd\collector.py` (confirmed on your PC)
- `python ingestion\collectors\mitre_attack\collector.py` (confirmed in the development environment, not yet on your PC)
- `python scripts\check_kev_output.py`, `check_nvd_output.py`, `check_attack_output.py`

## Pending
- CWE (XML) collector, CISA advisories collector (RSS + HTML)
- Milestone 4: raw data validation reports; Milestone 5: canonical schemas and cross-source deduplication

## Known issues
- None known

## Next exact task
Commit the NVD work, confirm the KEV/NVD field lists, then run the ATT&CK collector and its check script.
