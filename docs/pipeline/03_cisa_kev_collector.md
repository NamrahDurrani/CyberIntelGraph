# Pipeline step: CISA KEV collector

Milestone 3 - first collector. Files: `ingestion/collectors/cisa_kev/collector.py`,
`tests/unit/test_cisa_kev_collector.py`, `scripts/check_kev_output.py`.

## The source in plain words
Think of the KEV catalog as a **library card catalog**: one cover sheet (the *envelope*: title, version,
release date, how many cards) followed by one card per vulnerability. CISA publishes the whole drawer as a single
JSON file, so we ask for it once with an HTTP GET. No scraping, no API key.

```
{ "title": "...", "catalogVersion": "...", "dateReleased": "...", "count": N,
  "vulnerabilities": [ { "cveID": "CVE-....", "vendorProject": "...", "product": "...",
                         "vulnerabilityName": "...", "dateAdded": "YYYY-MM-DD", "shortDescription": "...",
                         "requiredAction": "...", "dueDate": "YYYY-MM-DD",
                         "knownRansomwareCampaignUse": "Known|Unknown", "notes": "...", "cwes": [...] }, ... ] }
```
(Field list: `docs/data_dictionary/cisa_kev.md`. Confirm against the real file after your first run.)

## What the collector does, step by step
| # | Step | Why |
|---|---|---|
| 1 | GET the official URL; retry on timeout, 429, 5xx (waits 2s, 4s, 8s...) | Networks fail; 404/403 fail immediately with a clear message |
| 2 | Save the response bytes **unchanged** to `data/raw/cisa_kev/`, plus `.meta.json` (URL, time, HTTP info, SHA-256) | Evidence locker; never edited, never overwritten |
| 3 | If the same bytes were saved before, reuse that file instead of storing a duplicate | Avoid duplicate storage |
| 4 | Validate envelope (keys, `count` == real count) and every record (required fields, CVE format, date format, duplicates) | Catch bad data before it spreads |
| 5 | Write normalized copy `data/processed/cisa_kev_normalized.json` with provenance fields on every record | Separate from raw |
| 6 | Write `cisa_kev_initial_subset.json` (default 75, ransomware-linked first) | Controlled first dataset (decision 0002) |
| 7 | Write a validation report to `outputs/reports/` and a log to `logs/cisa_kev_collector.log` | Audit trail (both ignored by Git) |

Errors **reject** a record (missing cveID/vendor/product/name/dateAdded, bad CVE format, bad date, duplicate).
Warnings **keep** it (e.g. an empty `requiredAction`). Exit code is 0 on success, 1 on any error.

## Run it
```powershell
cd C:\CyberIntelGraph
.\.venv\Scripts\Activate.ps1
python -m pip install requests
python ingestion\collectors\cisa_kev\collector.py
```

**Expected output (numbers will be the real ones from CISA, not these):**
```
... | INFO | GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (attempt 1/4)
... | INFO | Saved raw catalog: data/raw/cisa_kev/kev_raw_<timestamp>.json (<bytes> bytes, sha256 ...)
... | INFO | Wrote normalized copy: data/processed/cisa_kev_normalized.json (<N> records)
... | INFO | Wrote initial subset: data/processed/cisa_kev_initial_subset.json (75 records)

=== CISA KEV collection summary ===
  Status                : SUCCESS
  Catalog version       : <version>
  Declared count        : <N>
  Records in file       : <N>
  Valid records         : <N>
  Rejected records      : 0
  Duplicate CVE IDs     : 0
  ...
  Errors                : 0
```

## Validate it
```powershell
python -m unittest discover -s tests\unit -v      # 13 logic tests, expect "OK"
python scripts\check_kev_output.py                # re-reads the files, expect "ALL CHECKS PASSED"
```
Run the collector a **second time**: the summary should say `(reused, unchanged)` next to the raw file when CISA has not updated the catalog.

## Options
```powershell
python ingestion\collectors\cisa_kev\collector.py --subset-size 50     # smaller subset (0 = none)
python ingestion\collectors\cisa_kev\collector.py --retries 6 --timeout 60
```

## If it fails
| Message | Meaning / fix |
|---|---|
| `No module named 'requests'` | venv not active or package missing: activate, then `python -m pip install requests` |
| `HTTP 403` / `HTTP 404 (not retryable)` | The server refused or the URL changed. Open the URL in a browser, then paste me the full output |
| `Giving up after 4 attempts` + `ConnectionError` | No internet, VPN or firewall. Check you can open the URL in a browser |
| `Response is not valid JSON` | Got an HTML page instead of JSON (the raw file is kept: open it to see what came back) |
| `Declared count (X) != records in file (Y)` | Catalog changed mid-download or format changed: re-run; if it repeats, paste me the output |
| Warnings about missing fields | Not fatal. Tell me the message and we will update the data dictionary |

## Next
After the real run is validated and committed: NVD collector (fetch the CVEs from the KEV subset first).
