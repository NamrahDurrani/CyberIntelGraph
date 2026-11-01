# Project Status

**Current milestone:** 3 - Collectors (CISA KEV first)

## Completed
- [x] Milestone 1: Python 3.12.10 venv, folder structure verified (STRUCTURE OK), pushed to GitHub (commit d41efb8)
- [x] CISA KEV collector written, unit-tested (13 tests) and tested against a local mock server
- [ ] CISA KEV collector run against the REAL CISA feed and validated on your PC
- [ ] KEV data dictionary page confirmed against real data (docs/data_dictionary/cisa_kev.md)
- [ ] KEV work committed and pushed

## Working functionality
- `python ingestion\collectors\cisa_kev\collector.py` (not yet confirmed on the real feed)
- `python scripts\check_kev_output.py`

## Pending
- NVD collector (next, after KEV is confirmed), then MITRE ATT&CK, CWE, CISA advisories
- Milestone 4: raw data validation reports; Milestone 5: canonical schemas

## Known issues
- None known. Unconfirmed: exact real-feed field list and warnings (see data dictionary)

## Next exact task
Run the KEV collector and both checks, paste the output, then commit and push.
