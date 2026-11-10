# Data source: CISA Cybersecurity Advisories

| Item | Value |
|---|---|
| Source name | CISA Cybersecurity Advisories (joint advisories, #StopRansomware, exploited-vulnerability and malware advisories) |
| Official listing | https://www.cisa.gov/news-events/cybersecurity-advisories |
| RSS feed (read first) | https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml (in-depth advisories on threat actors and campaigns). A broader feed, `.../all.xml`, also mixes alerts, ICS advisories and bulletins; we do not use it by default. |
| Page address pattern | `https://www.cisa.gov/news-events/cybersecurity-advisories/aaYY-DDDx` (for example `aa25-203a`) |
| Collection method | RSS (`xml.etree`) + page download (`requests`) + text extraction (`BeautifulSoup`, html.parser). robots.txt is checked; delay between requests; no bypassing of refusals. |
| Data format | HTML pages (documents linked from them may be PDF, STIX JSON/XML: listed only, handled in Milestone 6) |
| Identifier | `doc_id = cisa-advisory:<slug>`, slug = last part of the page address; `alert_code` (AA25-203A) when present |
| Collector | `ingestion/collectors/advisories/collector.py` |
| Raw location | `data/raw/advisories/<slug>__<UTC time>.html`, `feed__<time>.xml`, `manifest.jsonl` |
| Processed location | `data/processed/advisories_normalized.json` |
| Target size | 50-75 documents (initial target, not a permanent limit) |
| Collection date / count on your PC | 2026-11-03: 46 documents (2 seed addresses returned HTTP 404 and were removed; the RSS feed answered HTTP 403, so pages came from the seed list); 238,398 words; 255 attachment links listed |
| Verified on your PC? | **Collector and independent check: YES** (12 checks passed). Page labels seen on real pages: `Last Revised` and `Alert Code` on all, `Release Date` on 18 of 46 (older pages are marked `Archived Content` and show only `Last Revised`). Fixes made after this run are listed under *Corrections*. |
| License / usage terms | Read CISA's site policies (Privacy & Use) and paste the exact wording here. |

## Where the URLs come from (in this order, duplicates removed, at most `--limit`, default 75)
1. URLs you pass: `--url ...` or `--urls-file file.txt` (use these if the feed refuses your connection).
2. The RSS feed items, newest first.
3. `config/advisory_seed_urls.txt`: **candidate** advisory addresses built from CISA's published advisory codes. Not verified one by one; a wrong address shows up as a failure (for example HTTP 404) and can simply be deleted from the file.
Only `www.cisa.gov` pages are accepted; `cisa.gov` is rewritten to `www.cisa.gov`; query strings and fragments are dropped.

## Fields extracted per page
| Field | How it is found |
|---|---|
| `title` | `og:title` meta, else first `<h1>`, else `<title>` (the " \| CISA" suffix is removed); a page with no title is rejected |
| `release_date`, `last_revised`, `alert_code` | visible label lines "Release Date", "Last Revised", "Alert Code" followed by the value |
| `published_at` and `published_at_source` | Release Date label, else a date meta tag, else the RSS `pubDate` (the source is recorded); a warning if none exists |
| `text`, `sections[]`, `word_count` | main content only (`<main>`, `<article>` or `#main-content`; navigation, scripts, forms and, without `<main>`, header/footer are removed). Headings become `#` lines, list items `-`, table rows `\| a \| b \|`. |
| `attachments[]` | links to `.pdf .json .xml .csv .docx .xlsx .zip .txt` inside the content (address + link text) |
| `mentioned_cve_ids`, `mentioned_attack_ids`, `mentioned_cwe_ids` | regular-expression matches in the title and text. **Lexical mentions only, not relationships.** |
| `feed_title`, `feed_pub_date`, `feed_categories` | from the RSS item, when the page came from the feed |
| provenance | `source_name`, `source_url`, `source_record_id`, `retrieved_at`, `published_at`, `last_modified_at`, `original_format` (html), `raw_file_reference`, `raw_sha256`, `collection_method`, `evidence_type` (`stated_in_source`) |

## Quality flags
A page with fewer than 500 characters of text is flagged (blocked page, JavaScript-only content or wrong page). A page with no date, or whose raw file no longer matches its SHA-256, is reported.

## Known limitations
- Text extraction is heuristic: the HTML layout is not a documented API. The check script and the "very short" flag exist to catch pages where it fails.
- PDF/DOCX attachments (and the technical detail inside long advisories delivered as PDF) are not read until Milestone 6.
- The RSS feed lists only recent advisories, so older ones depend on the seed list or on `--url`.
- Some CISA feed requests have been reported as refused (HTTP 403) by third-party readers. We do not bypass that; the collector reports it and continues with the other URL sources.

## Fields added after the first real run (2026-11-03)
| Field | Meaning |
|---|---|
| `advisory_type` | the type line on the page (for example "Cybersecurity Advisory") |
| `archived` | true when the page carries the "Archived Content" banner (older advisories; may be outdated) |
| `release_date_from_alert_code` | date implied by the alert code `AAyy-ddd` (year, day of year): **derived, not stated** |
| `published_at_is_derived` | true when `published_at` came from the alert code. `published_at_source` then starts with `DERIVED` |
| `release_date_matches_alert_code` | true / false / null: does the stated Release Date agree with the code-derived date? (tests the convention; compare on the audit) |

Date priority for `published_at`: page `Release Date` label, page meta tag, RSS `pubDate`, **derived from the alert code**, otherwise none.
`last_revised` is never used as a publication date.
The metadata lines (labels and values, the Archived banner and the type line) are stored as fields and no longer repeated inside `text`.

## Corrections after the first real run
- 28 of 46 documents had no publication date (older pages show only `Last Revised`): fixed with the clearly marked derived date above.
- The RSS feed returned HTTP 403 (not bypassed): added `--discover` to read advisory links from CISA listing pages, plus 6 more seed candidates.
- Seed addresses `aa21-265a` and `aa22-293a` returned HTTP 404 and were removed from `config/advisory_seed_urls.txt`.
