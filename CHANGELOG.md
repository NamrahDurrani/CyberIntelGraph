# Changelog

Record every meaningful change here (date, milestone, files added/changed, dependencies,
commands run, tests performed, known limitations).

## [Milestone 3 - CISA KEV collector] - 2026-11-01
### Added
- `ingestion/collectors/cisa_kev/collector.py` (download, raw save, validation, normalization, subset, report, log)
- `tests/unit/test_cisa_kev_collector.py` (13 stdlib unittest tests using clearly synthetic fixtures)
- `scripts/check_kev_output.py` (independent output check, includes SHA-256 verification)
- `docs/data_dictionary/cisa_kev.md`, `docs/decisions/0002-initial-dataset-scope.md`, `docs/pipeline/03_cisa_kev_collector.md`
### Changed
- `README.md` (status, collectors table), `requirements.txt` (requests), project docs now use C:\CyberIntelGraph
### Dependencies
- requests
### Tests performed
- 13 unit tests pass; collector exercised end to end against a LOCAL mock server (retry after HTTP 503, 404, count mismatch,
  non-JSON body, same-second collision, unchanged-content reuse, tamper detection by check script)
- NOT yet run against the real CISA feed (pending user run)
### Known limitations
- Field list in the data dictionary must be confirmed against the first real download
- Subset rule (ransomware-linked first, newest first) is proposed in decision 0002 and awaits confirmation

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
