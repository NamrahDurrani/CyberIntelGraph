# Pipeline step: NVD collector

Milestone 3 - second collector. Files: `ingestion/collectors/nvd/collector.py`,
`tests/unit/test_nvd_collector.py`, `scripts/check_nvd_output.py`. Prerequisite: the KEV collector has been run.

## In plain words
KEV tells us *which* vulnerabilities are being exploited. NVD is the **detailed case file** for each one: description, severity
scores, weakness type, affected products. Analogy: KEV is the "wanted list"; NVD is the dossier behind each name.
The same CVE ID appears in both, which later lets us merge them into one canonical Vulnerability.

## Which CVEs?
By default the collector reads `data/processed/cisa_kev_normalized.json` and takes the first **150** using the same ordering as the
KEV initial subset (ransomware-linked first, newest first). So the first 75 are exactly `cisa_kev_initial_subset.json`.
Add specific CVEs with `--cve-id` (for example `--cve-id CVE-2024-3400`). Use `--no-kev` to fetch only those.

## Steps
| # | Step | Why |
|---|---|---|
| 1 | One GET per CVE: `...cves/2.0?cveId=CVE-...`; retry on timeout, 403/429 (rate limit, waits 35 s), 5xx | NVD's firewall answers 403/429 if you go too fast |
| 2 | Pause between requests: 6.5 s without key, 0.7 s with key | Stay inside NVD's published limits |
| 3 | Save each response **unchanged** to `data/raw/nvd/<CVE>__<time>.json`, append a line to `manifest.jsonl` (file, time, status, SHA-256) | Evidence locker + resume point |
| 4 | Skip CVEs already downloaded (use `--refresh` to force) | An interrupted run just continues |
| 5 | Validate: envelope keys, `NVD_CVE` / `2.0`, exactly one record, returned ID == requested ID, required fields | Catch wrong or broken answers |
| 6 | Normalize everything with a successful download into `data/processed/nvd_normalized.json` | Separate from raw |
| 7 | Report in `outputs/reports/`, log in `logs/nvd_collector.log` | Audit trail |

Outcomes per CVE: **ok**, **no record** (HTTP 200 but 0 results: reported, never treated as "does not exist"), or **failed**
(request error or invalid response: raw response is kept when there is one). Exit code 0 only if nothing failed.

## Get an API key first (recommended, free, a few minutes)
1. Request one at https://nvd.nist.gov/developers/request-an-api-key (the key is emailed to you).
2. Open the `.env` file in the project folder (create it with `Copy-Item .env.example .env` if missing) and set `NVD_API_KEY=` to your key.
3. `.env` is ignored by Git. Never paste the key in chat or commit it. The collector never prints it.

## Run it
```powershell
cig                              # or: cd to your project folder
.\.venv\Scripts\Activate.ps1
python ingestion\collectors\nvd\collector.py --limit 3        # small first test (about 20 s without a key)
python scripts\check_nvd_output.py
python ingestion\collectors\nvd\collector.py                  # the real run: 150 CVEs
python scripts\check_nvd_output.py
```
**Expected (real numbers will differ):** one `saved (... bytes)` line per CVE, then a summary with `Status: SUCCESS`,
`CVEs requested: 150`, `Normalized records: 150` and coverage counts for CVSS / CWE / affected products.
Running it again prints `Reused (already on disk): 150` and downloads nothing.

## If it fails
| Message | Meaning / fix |
|---|---|
| `cisa_kev_normalized.json not found` | Run the KEV collector first |
| `HTTP 403` or `429` repeated, then `Giving up` | Rate limit. Wait a minute, run again (it resumes). Get an API key. |
| `HTTP 404 (not retryable)` | The API refused this request. It is reported as a failure, not as "CVE not found" |
| `NVD answered but returned 0 records` | Reported as NO RECORD; paste it to me, we decide what to do |
| `Ctrl+C` during a run | Safe. Progress is saved; run the same command to resume |
| `invalid response ... returned id ... != requested` | NVD answered with a different CVE; raw kept for inspection |

## Next
After NVD is validated and committed: MITRE ATT&CK (STIX), then CWE, then CISA advisories.
