# Changelog

Record every meaningful change here (date, milestone, files added/changed, dependencies,
commands run, tests performed, known limitations).

## Milestone 5.1 - 2026-11-10 - KEV CWE ids now create HAS_WEAKNESS links
- Fixed: `cwes` on KEV records were ignored; HAS_WEAKNESS is now 1755 (was 171).
- Changed: `canonical/build.py` (shared `_link_weaknesses`), `canonical/mappings.py` (alias).
- Added: `tests/unit/test_canonical_kev_cwes.py`, `scripts/apply_milestone_5_1_docs.py`.
- Verified: 479 sub-techniques still have 479 parent links; entity ids and schema unchanged.
- Commit 3cd7374 (Milestone 5) intentionally left as is.

## [Audit results on the user's PC and two follow-up fixes] - 2026-11-10
### Verified on the user's PC (2026-11-09)
- Advisories: 53 documents (target 50-75 met), every one dated, 34 dates derived from alert codes and **19/19 stated Release Dates agree with the code-derived date**, 20 pages marked Archived, 175 distinct CVEs mentioned (161 in KEV, 36 in the NVD set, 14 in neither); all 14 advisory checks passed
- Audit: all five dataset targets MET; NVD's embedded CISA dates agree with KEV for all 150 records; nothing from data/outputs/logs/.env is tracked by Git; all raw files verified by SHA-256
- CWE: the parser fix works for the data (subset 246 -> 254, no more "ids not in the catalog"), but the CWE check still FAILED because it only recognized the element name `Category`
### Fixed
- `scripts/check_cwe_output.py`: asks "are there entries besides weaknesses (any kind)?" instead of looking for one element name; prints the kind names; the collector warning is informational when other kinds exist
- `ingestion/validation/audit_raw_data.py`: ATT&CK-style ids T0800-T0899 (ICS matrix, not collected) are classified as INFO instead of WARN; unknown ids stay WARN; CWE stats carry `other_entries`
### Tests performed
- 145 unit tests pass (+2); end-to-end test of the CWE collector and check on a synthetic file with a differently named grouping section: SUCCESS, check passes with the info line
### Known limitations
- The real name of the CWE grouping kind is not known to me yet; the collector prints it (`Other entry kinds`)
- ICS ATT&CK is not collected (decision 0003 amendment): scope question for Milestone 5

## [Location-independent tooling] - 2026-11-04
### Why
Commands were run from an old, empty OneDrive folder while the update had been extracted into C:\CyberIntelGraph (`Ran 0 tests`, `[Errno 2]`, `.venv ... not recognized`).
The code never depended on a fixed path; the instructions and the terminal did.
### Added
- `scripts/doctor.py` (project health and location check), `scripts/install_shortcut.ps1` (`cig`, `cig doctor`), `docs/PROJECT_LOCATION.md`,
  `tests/unit/test_doctor_and_guards.py` (14 tests), `docs/CHANGE_REPORT_2026-11-04_location-independence.md`
### Changed
- All five collectors: friendly message and exit code 2 when `requests` / `beautifulsoup4` is not available (global Python)
- README, GETTING_STARTED, GITHUB_GUIDE, pipeline pages, roadmap, PROJECT_GUIDE: no hard-coded project path (`cig`, `$project` variable)
### Tests performed
- 143 unit tests pass; doctor simulated for a OneDrive path with spaces and a terminal in another folder; collector guard simulated
- NOT tested here: the two PowerShell scripts (no PowerShell in the development environment)

## [Milestone 4 - raw data audit, and fixes found by the Milestone 3 gate run] - 2026-11-04
### Verified on the user's PC before these changes (2026-11-03)
- Milestone 3 gate: ALL FIVE SOURCES PASSED (KEV 9, NVD 7, ATT&CK 15, CWE 12, advisories 12 checks)
- CWE v5.0 (2026-10-28): 984 weaknesses, 62 views, **0 categories**; advisories: 46 documents, 18 with a Release Date label, RSS feed HTTP 403, 2 seed addresses HTTP 404
### Problems found in that output and fixed
- CWE: categories were missed (CWE lists several hundred; 8 ids used by NVD/KEV are categories) -> structure-agnostic parser, XML section report, unknown kinds kept, warning when none, check script now fails on 0 categories
- Advisories: 28 of 46 documents without a date (older pages show only Last Revised) -> date derived from the alert code (AAyy-ddd), always marked derived, cross-checked against pages that state the date; `archived` flag; `advisory_type`; metadata lines no longer repeated in the text
- Advisories: RSS feed refused (403, not bypassed) and only 46 documents (target 50-75) -> `--discover` / `--discover-pages` read advisory links from CISA listing pages; 6 candidates added to the seed list; the 2 dead seed addresses (aa21-265a, aa22-293a) removed
- Gate weakness: check scripts passed although CWE had 0 categories and half the advisories had no date -> new checks (categories exist; every document has a date; derived dates marked)
- Data dictionaries still said "not verified" -> updated with the real results
### Added (Milestone 4)
- `ingestion/validation/audit_raw_data.py`, `config/dataset_targets.json`, `scripts/protect_raw_data.ps1`, `tests/unit/test_audit_raw_data.py`
- `docs/pipeline/08_raw_data_audit.md`, `docs/decisions/0005-raw-data-audit-and-storage.md`, `docs/CHANGE_REPORT_2026-11-04_M3-fixes_and_M4.md`
- Generated by the audit: `docs/data_dictionary/RAW_DATA_AUDIT.md` (commit it)
### Changed
- `ingestion/collectors/cwe/collector.py`, `ingestion/collectors/advisories/collector.py`, `scripts/check_cwe_output.py`, `scripts/check_advisories_output.py`,
  `config/advisory_seed_urls.txt`, all five data dictionary pages, `docs/pipeline/00_milestone_roadmap.md`, `06_cwe_collector.md`, `07_advisories_collector.md`,
  `docs/decisions/0004-cwe-and-advisories-scope.md`, README, PROJECT_STATUS, `docs/PROJECT_GUIDE.md`
### Dependencies
- None new
### Tests performed
- 129 unit tests pass (34 added: 3 CWE structure, 7 advisories dates/archive/discovery, 24 audit), also with DeprecationWarning treated as an error
- Integration run in the development environment: KEV, NVD, CWE and advisories collectors against local mock servers plus the REAL ATT&CK Enterprise 20.0 download (1,842 objects, 20,957 relationships), then the full audit (field inventory of the 55 MB bundle included)
- Bugs found by that testing and fixed: `--write-doc` crashed when docs/data_dictionary did not exist; per-type "expected but never seen" warnings were noise (now only source-wide gaps)
- NOT yet run against the real CWE download (category fix), the real CISA listing pages (--discover), or the audit on the user's PC
### Known limitations
- Listing-page discovery depends on CISA's page layout, which is not a documented API
- Date derived from an alert code is an inference (flagged); its agreement with stated dates is measured, not assumed

## [Milestone 3 - CWE and CISA advisories collectors] - 2026-11-03
### Added
- `ingestion/collectors/cwe/collector.py` (official `cwec_latest.xml.zip`: raw zip with SHA-256, XML read in memory, weaknesses / categories /
  views, counts of how many NVD and KEV records use each id, initial subset = referenced ids + ChildOf ancestors in view 1000)
- `ingestion/collectors/advisories/collector.py` (RSS feed + explicit URLs + seed list; robots.txt; polite delay; 403 reported and never bypassed;
  raw HTML + manifest + resume; BeautifulSoup text extraction; lexical CVE / ATT&CK / CWE mentions; status SUCCESS / PARTIAL / FAILED)
- `config/advisory_seed_urls.txt` (48 unverified candidate advisory addresses; failures are reported)
- `tests/unit/test_cwe_collector.py` (21 tests), `tests/unit/test_advisories_collector.py` (25 tests), synthetic fixtures only
- `scripts/check_cwe_output.py`, `scripts/check_advisories_output.py`, `scripts/check_all_outputs.py` (Milestone 3 gate)
- `docs/data_dictionary/cwe.md`, `advisories.md`; `docs/pipeline/06_cwe_collector.md`, `07_advisories_collector.md`; `docs/decisions/0004-cwe-and-advisories-scope.md`
### Dependencies
- beautifulsoup4 (advisories collector)
### Tests performed
- 95 unit tests pass in total (13 KEV + 17 NVD + 19 ATT&CK + 21 CWE + 25 advisories), also with DeprecationWarning treated as an error
- End to end against LOCAL mock servers only (the development environment cannot resolve cwe.mitre.org or cisa.gov):
  CWE: ok zip, reuse on second run, HTML instead of zip, HTTP 404, raw tamper detected by the check script.
  Advisories: feed + seed, flaky page (503 then 200), 404, robots.txt-disallowed path, PDF skipped, off-site redirect refused,
  feed 403 reported without bypass, explicit --url fallback, nothing usable -> clear error, resume/reuse on second run
- NOT yet run against the real CWE download or real CISA pages (pending user run)
### Known limitations
- Real CWE and CISA page structure confirmed from documentation and public copies only; field details to be confirmed on the first real run
- Advisory text extraction is heuristic; seed-list addresses are unverified candidates
- PDF / DOCX attachments are listed, not read (Milestone 6)

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
- Verified on the user's PC: check_attack_output.py ALL CHECKS PASSED (706 techniques incl. 479 sub-techniques, 15 tactics, 178 groups, 747 malware, 95 tools, 57 campaigns, 44 mitigations; 20,957 relationships)
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
