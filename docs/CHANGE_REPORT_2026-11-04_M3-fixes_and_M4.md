# Change Report: Milestone 3 fixes and Milestone 4 (2026-11-04)

This report lists **everything that changed** and why. It answers three questions:
1. Is Milestone 3 complete? 2. What problems did your real run reveal, and what was done about each? 3. What is Milestone 4 and what do you run?

---

## 1. Verdict

| Question | Answer |
|---|---|
| Did the Milestone 3 gate pass? | **Yes.** `check_all_outputs.py`: KEV 9, NVD 7, ATT&CK 15, CWE 12, advisories 12 checks passed. |
| Is Milestone 3 therefore complete? | **Not yet.** Your own output showed four problems the checks did not catch. All four are fixed in the code, tests and docs below, but the fixes need one **re-run on your PC** (CWE and advisories) to be confirmed. |
| Is Milestone 4 built? | **Yes**, and tested. It is complete when the audit prints no FAIL on your PC and its generated document is committed. |

**Analogy:** the gate was a driving test that passed. Reading your output was like looking at the car afterwards: it drove fine, but one headlight was out and the fuel gauge was missing. A passed test only proves what the test asked.

---

## 2. Problems found in your real output, and what changed

### Problem 1: CWE found 0 categories
| | |
|---|---|
| **Evidence** | Summary: `984 weaknesses, 0 categories, 62 views`. Warning: 8 referenced CWE ids not in the catalog: CWE-189, CWE-19, CWE-254, CWE-255, CWE-264 ... |
| **Why it is a bug** | Those ids are **categories**. CWE's own site lists several hundred categories (396 on the CWE 5.0 view page I read). Also 984 minus your 28 Deprecated = 956, which matches the site's active weakness count, so only the categories were missing. |
| **Root cause** | The parser looked for categories in one fixed place (`Categories/Category`). Whatever CWE 5.0 does differently, the parser did not find them. I cannot download cwe.mitre.org from my environment, so the exact layout is confirmed only by your re-run. |
| **Fix** | The parser now treats every element two levels below the root that has `ID` and `Name` as an entry, whatever the section is called. Unknown kinds are kept (not dropped). The summary prints an `XML sections` line showing what the file really contains. A warning appears when no categories are found. |
| **Why the gate missed it** | No check asked "are there categories?". `check_cwe_output.py` now **fails** when there are none. |
| **Status** | Fixed and unit-tested (3 new tests). **Confirm by re-running the CWE collector.** |

### Problem 2: 28 of 46 advisories had no publication date
| | |
|---|---|
| **Evidence** | `with release date label: 18/46`, `published_at source: none: 28`. Your sample page (DarkSide, AA21-131A) shows only `Last Revised July 08, 2021` and an `Archived Content` banner. |
| **Root cause** | Older (archived) pages do not state a Release Date. I had treated that as "no date". |
| **Fix** | Date priority is now: Release Date label, page meta tag, RSS pubDate, then a date **derived from the alert code**. CISA codes are `AAyy-ddd`: year and day of the year of first release (AA21-131A = 2021, day 131 = 2021-05-11). A derived date is always marked (`published_at_is_derived = true`, source text starts with `DERIVED`). `Last Revised` is **never** used as the publication date. |
| **Is the derived date trustworthy?** | It is an inference, so it is tested, not assumed: on every page that states a Release Date, the collector compares it with the code-derived date (`release_date_matches_alert_code`) and the check script prints how many agree. |
| **Also changed** | `archived` flag (archived advisories may be outdated); `advisory_type`; the metadata lines (labels, values, banner, type line) are stored as fields and no longer repeated inside the text (your printed sample began with `### Archived Content` and `Last Revised`, which would pollute chunking in Milestone 6). |
| **Why the gate missed it** | It only checked that dates present were valid. `check_advisories_output.py` now **fails** if any document has no date and if a derived date is not marked as derived. |
| **Status** | Fixed and unit-tested (7 new tests). Confirm by re-running. |

### Problem 3: the RSS feed refused the connection and only 46 documents were reached (target 50-75)
| | |
|---|---|
| **Evidence** | `RSS feed not used: HTTP 403 Forbidden`; `Normalized documents: 46`; status `PARTIAL`. |
| **Decision** | A refusal is **not bypassed**. The collector reported it and carried on with the seed list, which is the intended behaviour. |
| **Fix** | New options `--discover <CISA listing page>` and `--discover-pages N`: the collector reads advisory and analysis-report links from CISA's public listing pages (robots.txt checked, 2 s delay, listing pages saved raw). Six more seed candidates were added. Order of sources: your `--url`s, feed, discovered links, seed list. |
| **Status** | Fixed and tested against a mock listing server (3 pages, stops at the first page with nothing new). **Not yet run on CISA's real listing pages** (layout is not a documented API). The summary line `Links found on listings` tells you at once whether it worked. |

### Problem 4: two seed addresses returned HTTP 404
`aa21-265a` and `aa22-293a` were removed from `config/advisory_seed_urls.txt` (they were announced as unverified candidates). After that, the collector status can become SUCCESS instead of PARTIAL.

### Problem 5: data dictionaries still said "not verified"
All five pages now carry your real results (dates, counts, versions). KEV, NVD and ATT&CK say "collector and independent check: YES; field list: to be confirmed by running the Milestone 4 audit", because the audit lists the fields that really occur (it replaces the manual one-liners I asked you for earlier).

### What I noticed but did not change (information for later)
- 12 of the 167 CVEs mentioned in your 46 advisories are not in KEV (155 are). That is normal (advisories also cover older and vendor-specific CVEs) and is useful material for the canonical model.
- The default NVD set contains only KEV-listed CVEs (decision 0002). Questions about non-exploited vulnerabilities will need a few `--cve-id` additions before evaluation.

---

## 3. Milestone 4: raw data validation and storage

**What it is.** One command that inspects the whole raw data layer after the five collectors: complete, untouched, fresh, consistent across sources, documented, and not leaking into Git.
**Analogy:** the surveyor's visit before the architect designs the house.

```powershell
python ingestion\validation\audit_raw_data.py --write-doc
```

| # | Check | If it goes wrong |
|---|---|---|
| 1 | Every recorded raw file exists and matches its SHA-256 and size; orphan files; duplicate content | missing / changed = **FAIL** |
| 2 | Freshness (newest download older than 30 days) and each source's own version / date | WARN |
| 3 | Processed record counts re-read from disk | processed file missing = **FAIL** |
| 4 | Dataset targets from `config/dataset_targets.json` | below target = WARN |
| 5 | Cross-source: NVD vs KEV; CWE ids vs the CWE catalog; advisory mentions vs KEV / NVD / ATT&CK / CWE; NVD's embedded CISA dates vs KEV | WARN |
| 6 | Field inventory: fields that occur, fields we use, fields we ignore, fields we read that occur nowhere | read-but-never-seen = WARN |
| 7 | Git hygiene: nothing from `data/`, `outputs/`, `logs/`, `.env` tracked; `.env` ignored | **FAIL** |
| 8 | The five independent check scripts | any failing = **FAIL** |
| 9 | Data dictionary pages exist and are not marked "not verified" | WARN |

Outputs: console summary; `outputs/reports/raw_data_audit_<time>.json` (not in Git); `docs/data_dictionary/RAW_DATA_AUDIT.md` (in Git, **commit it**).
Exit code: 0 unless there is a FAIL. Options: `--fast`, `--skip-checks`, `--max-age-days N`, `--write-doc`.

Optional protection: `.\scripts\protect_raw_data.ps1` makes raw files read-only (`-Unprotect` undoes it; `manifest.jsonl` stays writable). Collectors keep working because they only create new files.

---

## 4. Files

### Added
| File | Purpose |
|---|---|
| `ingestion/validation/audit_raw_data.py` | The Milestone 4 audit |
| `config/dataset_targets.json` | Initial dataset targets from the master prompt (as data, not code) |
| `scripts/protect_raw_data.ps1` | Optional read-only protection for raw files |
| `tests/unit/test_audit_raw_data.py` | 24 tests for the audit |
| `docs/pipeline/08_raw_data_audit.md` | How to run and read the audit |
| `docs/decisions/0005-raw-data-audit-and-storage.md` | Why the audit works the way it does |
| `docs/CHANGE_REPORT_2026-11-04_M3-fixes_and_M4.md` | This report |
| `docs/data_dictionary/RAW_DATA_AUDIT.md` | **Generated by the audit** on your PC (not in the zip) |

### Changed
| File | What changed |
|---|---|
| `ingestion/collectors/cwe/collector.py` | Structure-agnostic parsing, section report, unknown kinds kept, no-categories warning |
| `ingestion/collectors/advisories/collector.py` | Derived dates (marked), `archived`, `advisory_type`, metadata stripped from text, `--discover` / `--discover-pages` |
| `scripts/check_cwe_output.py` | Fails when there are no categories |
| `scripts/check_advisories_output.py` | Fails on undated documents and unmarked derived dates; prints date-convention agreement and archived counts |
| `config/advisory_seed_urls.txt` | 2 dead addresses removed, 6 candidates added (52 total) |
| `tests/unit/test_cwe_collector.py`, `test_advisories_collector.py` | 10 new tests; one test updated to expect the designed warning |
| `docs/data_dictionary/{cisa_kev,nvd,mitre_attack,cwe,advisories}.md` | Real results written in; correction logs; new advisory fields |
| `docs/decisions/0004-cwe-and-advisories-scope.md` | Amendments for the four fixes |
| `docs/pipeline/00_milestone_roadmap.md`, `06_cwe_collector.md`, `07_advisories_collector.md` | Milestone 4 section; real expected output; `--discover`; dates and archived pages |
| `README.md`, `CHANGELOG.md`, `PROJECT_STATUS.md`, `docs/PROJECT_GUIDE.md` | Status, new commands, lessons learned |

### Removed
Two dead seed addresses (above). Nothing else.

---

## 5. How it was tested (and what was not)

| Where | What |
|---|---|
| Unit tests | **143 pass** (95 before, 48 added: 34 for the fixes and Milestone 4, 14 for the location tooling), also with deprecation warnings treated as errors |
| Integration, my environment | KEV, NVD, CWE and advisories collectors against local mock servers; **ATT&CK against the real official download** (Enterprise 20.0: 1,842 objects, 20,957 relationships); then the full audit including the field inventory of the 55 MB bundle |
| Bugs found by that testing and fixed before delivery | `--write-doc` crashed when `docs/data_dictionary` did not exist; per-type "expected but never seen" warnings were noise (now only fields missing from the whole source) |
| **Not tested** | The CWE category fix on the real CWE file; `--discover` on CISA's real listing pages; the audit on your PC. My environment cannot reach cwe.mitre.org or cisa.gov. These are your three confirmations. |

---

## 6. What you run

```powershell
$project = "C:\CyberIntelGraph"     # the folder that holds README.md; change it if your project is somewhere else
cd $project
.\.venv\Scripts\Activate.ps1
Expand-Archive -Path "$HOME\Downloads\milestone4_update_v2.zip" -DestinationPath $project -Force
Get-ChildItem -Recurse -File | Unblock-File
python -m unittest discover -s tests\unit                    # expect: Ran 143 tests ... OK

python ingestion\collectors\cwe\collector.py                 # categories must appear
python scripts\check_cwe_output.py
python ingestion\collectors\advisories\collector.py --discover https://www.cisa.gov/news-events/cybersecurity-advisories --discover-pages 5
python scripts\check_advisories_output.py

python ingestion\validation\audit_raw_data.py --write-doc    # Milestone 4
```

**Expected**
- Unit tests: `Ran 129 tests` and `OK`.
- CWE: `Categories` several hundred (not 0), an `XML sections` line, and the earlier "8 referenced ids not in the catalog" warning gone or reduced to a few retired ids; check script `ALL CHECKS PASSED`.
- Advisories: a `Links found on listings` number above 0, at least 50 normalized documents, `no date at all: 0`, `date derived from code` around 28 or more, Status `SUCCESS` (or `PARTIAL` with a short, explainable failure list); check script `ALL CHECKS PASSED`.
- Audit: no FAIL. WARN findings are questions to read, not errors. Expect to see, for example, ATT&CK-style ids in old advisory text that are not active techniques in release 20.0.

**If `Links found on listings` is 0:** CISA's listing layout differs from what the extractor expects. Paste me the advisories summary and I will adapt the extractor. Seed-list pages already on disk are reused, so nothing is lost.

Then commit:
```powershell
git add .
git status --short            # code and docs only: no .env, nothing from data\
git commit -m "Milestone 4: raw data audit; fixes for CWE categories and advisory dates and discovery"
git push
```

---

## 7. What is left

| Item | Owner |
|---|---|
| Re-run CWE and advisories and paste the summaries | you |
| Run the audit and paste the summary | you |
| Commit and push | you |
| Read the generated `RAW_DATA_AUDIT.md` field inventory and tell me about any field you want us to use that we currently ignore | you |
| Milestone 5: canonical schemas and cross-source deduplication (ATT&CK tool vs malware mapping decision comes first) | next |
