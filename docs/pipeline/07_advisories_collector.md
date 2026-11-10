# Pipeline step: CISA advisories collector

Milestone 3 - fifth and last collector. Files: `ingestion/collectors/advisories/collector.py`, `config/advisory_seed_urls.txt`,
`tests/unit/test_advisories_collector.py`, `scripts/check_advisories_output.py`.
New package: `beautifulsoup4`.

## In plain words
KEV, NVD, ATT&CK and CWE are tables of facts. Advisories are **stories**: how a named group broke in, which tools it used, which vulnerabilities it exploited, what to do about it.
Analogy: the first four sources are the police database; this one is the case report written by investigators. This is the text GraphRAG will read in Milestone 9 and that our RAG baselines will search.

## Steps
| # | Step | Why |
|---|---|---|
| 1 | Collect page addresses: your `--url`s, the RSS feed (newest first), then the seed list; only `www.cisa.gov`; at most `--limit` (75) | Reproducible, focused list |
| 2 | Check robots.txt; wait 2 s between pages; retry only timeouts, 429 and 5xx | Polite, rule-following |
| 3 | HTTP 403 is reported and **never bypassed**; other 4xx are failures; non-HTML (PDF) is skipped for Milestone 6; off-site redirects are refused | Safe and honest |
| 4 | Save each page **unchanged** + a line in `manifest.jsonl` (SHA-256); skip pages already downloaded (resume) | Evidence locker |
| 5 | Extract title, dates, alert code, clean text with headings, attachment links, and CVE / ATT&CK / CWE **mentions** | Ready for chunking |
| 6 | Flag very short pages, missing dates, hash mismatches | Quality gate |
| 7 | Report, log | Audit trail |

## Before the full run: a small test
The page layout is not a documented API, so test small first:
```powershell
cig                              # or: cd to your project folder
.\.venv\Scripts\Activate.ps1
python -m pip install beautifulsoup4
python ingestion\collectors\advisories\collector.py --limit 3
python scripts\check_advisories_output.py
```
**Expected:** `RSS feed: ok (N items)` (or a clear reason why it was not used), 3 pages saved, `Status: SUCCESS`,
normalized documents 3, mostly "with release date" and "with alert code" counts of 3, `very short: 0`, and `ALL CHECKS PASSED`.
Open one record to judge the extraction yourself:
```powershell
python -c "import json; d=json.load(open('data/processed/advisories_normalized.json',encoding='utf-8')); r=d['records'][0]; print(r['title'], r['alert_code'], r['release_date']); print(r['text'][:1200])"
```
If the text looks like the advisory (headings, bullets, no menu junk), run the full collection:
```powershell
python ingestion\collectors\advisories\collector.py
python scripts\check_advisories_output.py
```
Takes a few minutes (2 s per page). Re-running resumes: pages already on disk are reused.

## When the RSS feed refuses you (HTTP 403)
This happened on a real run. The collector reports it, never bypasses it, and carries on with the other URL sources. To collect more than the seed list holds, read advisory links from CISA's listing pages:
```powershell
python ingestion\collectors\advisories\collector.py --discover https://www.cisa.gov/news-events/cybersecurity-advisories --discover-pages 5
```
Listing pages are saved raw too; only links to Cybersecurity Advisories (`aaYY-NNNx`) and Analysis Reports (`arYY-NNNx`) are followed; robots.txt is checked; 2 seconds between requests.
Look at the line `Links found on listings`: if it is 0, the listing page layout differs from what the extractor expects; paste me the output.
Already downloaded pages are reused, so you can run it repeatedly.

## Dates and archived advisories
Older advisories carry the banner "Archived Content" and show only `Last Revised`. The publication date is then **derived from the alert code** (`AA21-131A` = year 2021, day 131 = 2021-05-11) and always marked `published_at_is_derived`.
On pages that do state a Release Date the collector compares it with the code-derived date (`release_date_matches_alert_code`); the check script prints how many agree. `archived` is stored as a flag.

## Status values
- **SUCCESS:** every page was downloaded and extracted.
- **PARTIAL:** some pages failed, were refused by robots.txt, or were skipped; the rest are fine. The list is printed. For seed-list entries a failure usually means a wrong address: delete the line.
- **FAILED:** nothing usable.

## If it fails
| Message | Meaning / fix |
|---|---|
| `RSS feed not used: HTTP 403 ... refused this request` | The feed refused this connection. Not bypassed. The collector continues with seed/`--url` pages. You can also open the feed in your browser and copy advisory addresses into a text file, then run with `--urls-file my_urls.txt --no-seed` |
| `FAILED ... HTTP 404` | Wrong address (common for seed entries): delete or fix the line |
| `very little text ... blocked, JavaScript-only or wrong page?` | Extraction found almost nothing: open the raw HTML file in `data\raw\advisories` and tell me; I will adapt the extractor |
| `No advisory URLs to collect` | Feed and seed gave nothing: pass pages with `--url https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a` |
| `SKIPPED (robots.txt)` | The site asks bots not to fetch that path; we respect it |
| `Ctrl+C` during a run | Safe: progress is saved, run again to resume |

## Next
Milestone 3 is complete when all five collectors are validated on your PC and committed. Then Milestone 4 (combined raw data audit) and Milestone 5 (canonical model).
