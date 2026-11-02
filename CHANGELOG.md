# Changelog

Record every meaningful change here (date, milestone, files added/changed, dependencies,
commands run, tests performed, known limitations).

## [Milestone 3 - NVD collector] - 2026-11-01
### Added
- `ingestion/collectors/nvd/collector.py` (CVE API 2.0, one request per CVE, rate limiting, retries, resume via manifest,
  raw save, validation, normalization, report, log; optional `NVD_API_KEY` from `.env`, sent as `apiKey` header)
- `tests/unit/test_nvd_collector.py` (17 tests, synthetic fixtures), `scripts/check_nvd_output.py`
- `docs/data_dictionary/nvd.md`, `docs/pipeline/04_nvd_collector.md`; decision 0002 extended (NVD default = 150 CVEs from KEV ordering)
### Dependencies
- None new (requests already installed)
### Tests performed
- 30 unit tests pass (13 KEV + 17 NVD)
- End to end against a LOCAL mock server: 503 retry, HTTP 404 reported as failure, 0-record answer reported separately,
  wrong-ID answer rejected, invalid CVE input ignored, resume/reuse on second run, API key sent only as header and never
  written to logs/manifest/report, check script catches a changed raw file
- NOT yet run against the real NVD API (pending user run)
### Known limitations
- NVD field names confirmed from public documentation only; verify against the first real download
- Default NVD set contains only KEV-listed CVEs (see decision 0002)

## [Milestone 3 - CISA KEV collector] - 2026-11-01
### Verified on the user's PC (real CISA feed)
- Catalog version 2026.10.30, 1766 records, 0 rejected, 0 duplicates, 0 warnings; raw file 1,826,755 bytes
- 361 records with known ransomware campaign use; date_added range 2021-11-03 .. 2026-10-30
- 13 unit tests OK; check script ALL CHECKS PASSED; second run reused the unchanged raw file; committed d74e626 and pushed
### Added
- `ingestion/collectors/cisa_kev/collector.py`, `tests/unit/test_cisa_kev_collector.py`, `scripts/check_kev_output.py`
- `docs/data_dictionary/cisa_kev.md`, `docs/decisions/0002-initial-dataset-scope.md`, `docs/pipeline/03_cisa_kev_collector.md`
### Dependencies
- requests

## [Milestone 1 - environment and structure] - 2026-11-01
### Verified on the user's PC
- Python 3.12.10 virtual environment at C:\CyberIntelGraph\.venv; `verify_structure.ps1` printed STRUCTURE OK
- Project moved out of OneDrive to C:\CyberIntelGraph; first commit d41efb8 pushed to GitHub (NamrahDurrani/CyberIntelGraph)
- Execution-policy issue (unsigned downloaded scripts) resolved with Unblock-File

## [Milestone 1] - 2026-10-31
### Added
- Complete empty directory structure (61 leaf folders, each with a .gitkeep)
- README.md, CHANGELOG.md, PROJECT_STATUS.md, .env.example, .gitignore, requirements.txt
- Guides in docs/ (getting started, GitHub, milestone roadmap, architecture, data dictionary template, decisions)
- PowerShell helper scripts in scripts/ (setup_env, verify_structure, git_init)
### Dependencies
- None
### Known limitations
- No collectors or application code at that point
