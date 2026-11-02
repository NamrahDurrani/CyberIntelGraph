# Project Status

**Current milestone:** 3 - Collectors (CISA KEV done, NVD next to run)

## Completed
- [x] Milestone 1: Python 3.12.10 venv, folder structure verified, pushed to GitHub
- [x] CISA KEV collector validated on the real feed (catalog 2026.10.30, 1766 records, all checks passed), committed d74e626
- [x] NVD collector written, unit-tested (17 tests) and tested against a local mock server
- [ ] NVD API key obtained and stored in `.env` (recommended)
- [ ] NVD collector run on the REAL NVD API (`--limit 3` first, then the full 150) and validated
- [ ] KEV and NVD data dictionary pages confirmed against real data
- [ ] NVD work committed and pushed

## Working functionality
- `python ingestion\collectors\cisa_kev\collector.py` (confirmed on real feed)
- `python ingestion\collectors\nvd\collector.py` (not yet confirmed on the real API)
- `python scripts\check_kev_output.py`, `python scripts\check_nvd_output.py`

## Pending
- MITRE ATT&CK (STIX), CWE, CISA advisories collectors
- Milestone 4: raw data validation reports; Milestone 5: canonical schemas

## Known issues
- None known. Unconfirmed: real NVD field details (see docs/data_dictionary/nvd.md)

## Next exact task
Run `python ingestion\collectors\nvd\collector.py --limit 3`, then `python scripts\check_nvd_output.py`, and paste the output.
