# Changelog

Record every meaningful change here (date, milestone, files added/changed, dependencies,
commands run, tests performed, known limitations).

## [Milestone 3 - MITRE ATT&CK collector] - 2026-11-02
### Added
- `ingestion/collectors/mitre_attack/collector.py` (index.json -> latest Enterprise release -> one versioned STIX bundle;
  raw save with SHA-256, reuse of a verified release, validation, normalization of 7 object types and 4 relationship types)
- `tests/unit/test_mitre_attack_collector.py` (19 tests, synthetic fixtures), `scripts/check_attack_output.py` (15 checks)
- `docs/data_dictionary/mitre_attack.md`, `docs/pipeline/05_mitre_attack_collector.md`, `docs/decisions/0003-mitre-attack-scope.md`
### Dependencies
- None new
### Tests performed
- 49 unit tests pass (13 KEV + 17 NVD + 19 ATT&CK)
- Collector run end to end on the REAL official data in the development environment: Enterprise ATT&CK 20.0, 26,690 objects ->
  1,842 objects + 20,957 relationships, 0 errors, 0 warnings; second run reused the verified bundle; check script ALL CHECKS PASSED
- Tamper test: a modified raw bundle makes the collector refuse to run and the check script fail
- NOT yet run on the user's PC
### Known limitations
- Enterprise domain only; detection content (analytics, detection strategies, data sources) not normalized yet
- Counts are for release 20.0; later releases will differ (use --version 20.0)

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
- Verified on the user's PC with an API key: 150 requested, 150 downloaded, 0 failed, 150 normalized (150 with CVSS, CWE and affected products); check script ALL CHECKS PASSED; 75/75 KEV subset covered; NVD carried CISA fields on all 150 records
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
