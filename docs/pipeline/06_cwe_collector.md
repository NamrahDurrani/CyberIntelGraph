# Pipeline step: CWE collector

Milestone 3 - fourth collector. Files: `ingestion/collectors/cwe/collector.py`, `tests/unit/test_cwe_collector.py`, `scripts/check_cwe_output.py`.
Prerequisites: the NVD and KEV collectors have been run (so the collector can see which CWE ids we use).

## In plain words
NVD told us each vulnerability's **weakness type** as a code like `CWE-79`. CWE is the dictionary that explains those codes and shows how they are organized
(a family tree from broad "Pillars" down to specific "Variants"). Analogy: a CVE is one specific break-in; a CWE is the *kind* of lock weakness it exploited.

## Steps
| # | Step | Why |
|---|---|---|
| 1 | Download the official zip (about a couple of MB) with retries | The structured official download, not scraping |
| 2 | Save the zip **unchanged** + `.meta.json` (URL, time, SHA-256); reuse an identical zip | Evidence locker, no duplicates |
| 3 | Read the XML inside the zip in memory; refuse non-zip answers, missing XML or oversize archives | A blocked request often returns an HTML page instead of a zip |
| 4 | Parse and validate: root element, ids, names, duplicates, link targets | Catch broken data |
| 5 | Normalize weaknesses, categories, views; count how many of our NVD/KEV records use each id | Shows which weaknesses matter to us |
| 6 | Build the initial subset: referenced ids + ancestors (view 1000) | "Relevant weakness categories" |
| 7 | Report, log | Audit trail |

## Run it
```powershell
cig                              # or: cd to your project folder
.\.venv\Scripts\Activate.ps1
python ingestion\collectors\cwe\collector.py
python scripts\check_cwe_output.py
```
**Expected (CWE v5.0 as seen on a real run):** `Status: SUCCESS`, `Catalog: CWE v5.0 (2026-10-28)`, about 984 weaknesses (28 of them Deprecated), 62 views and **several hundred categories** (the first version of this collector wrongly found 0; see the correction log in `docs/data_dictionary/cwe.md`),
an `XML sections` line showing what the file contains,
`CWE ids used by NVD/KEV: N found of N` (a few missing ids are possible and are listed as warnings), an `Initial subset` count, and `Errors: 0`.
The check script ends with `ALL CHECKS PASSED`. A second run says `(reused, unchanged)`.

## If it fails
| Message | Meaning / fix |
|---|---|
| `downloaded file is not a zip archive` | The server answered with a page instead of the zip: open the URL in a browser; the raw file is kept for inspection |
| `HTTP 404 (not retryable)` | The download address changed: check https://cwe.mitre.org/data/downloads.html and paste me the output |
| `unexpected XML root element` | The format changed: paste me the output |
| Warnings `referenced CWE id(s) not in the catalog` | Not fatal. After the category fix the earlier 8 missing ids (CWE-189, 19, 254, 255, 264 ...) should disappear; any that remain are retired ids |
| `no Category entries found` warning, or `[FAIL] the catalog has categories (0)` | The parser missed a section. Copy the `XML sections` line to me; the collector keeps unknown entry kinds, so the data is in the raw zip |
| `[FAIL] raw zip SHA-256 ...` in the check | The raw file was changed after download: delete it and its `.meta.json` and run again |

## Next
CISA advisories (the last collector of Milestone 3), then Milestone 4 (combined raw-data audit).
