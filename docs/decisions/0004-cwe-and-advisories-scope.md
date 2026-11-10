# 0004 - CWE and CISA advisories scope

- Date: 2026-11-03
- Status: accepted as implemented

## CWE
- **Source:** the official `cwec_latest.xml.zip`. The zip is stored untouched; the XML inside is read in memory.
- **Kept:** all weaknesses and categories (small, cheap, complete) plus views as a short list.
- **Initial subset ("relevant weakness categories"):** CWE ids referenced by our NVD or KEV records plus their ancestors via `ChildOf` in view 1000.
  Only the subset goes to GraphRAG/Neo4j first, keeping the graph focused; the full set stays available.
- **NVD placeholders** (`NVD-CWE-Other`, `NVD-CWE-noinfo`) are not CWE entries and are not mapped.
- **No invented entries:** referenced ids missing from the catalog are reported as warnings.

## CISA advisories
- **URL sources:** explicit `--url` / `--urls-file`, the official RSS feed, and an optional seed list of candidate addresses. Default cap 75 pages (target 50-75).
  The seed list exists because an RSS feed shows only recent items; its entries are unverified candidates and failures are reported, not hidden.
- **Politeness and rules:** robots.txt is checked and respected; 2 seconds between page requests; identifying User-Agent; retries only for 429/5xx.
  **HTTP 403 is never bypassed**: it is reported with guidance, and the collector continues with other sources.
- **Only www.cisa.gov** pages (including after redirects).
- **HTML only for now.** PDF and other attachments are listed but not downloaded; Docling handles them in Milestone 6.
- **Mentions are not relationships.** CVE / ATT&CK / CWE ids found in the text are stored as lexical mentions with an explicit note; any real relationship
  must be extracted with evidence (GraphRAG, Milestone 9) and reviewed.
- **Evidence type** is `stated_in_source` (the page says it); extracted claims will carry their own, lower evidence types.

## Consequences
- The first real run decides whether the extraction heuristics fit CISA's current page layout; the check script and quality flags make misfits visible.
- Milestone 6 can reuse the `text` and `sections` fields for chunking HTML advisories, and adds Docling for PDF/DOCX.

## Amendments after the first real run (2026-11-03)
- **CWE parsing is structure-agnostic.** The first parser found 0 categories in CWE v5.0 (the site lists several hundred, and NVD still references category ids such as CWE-189 and CWE-264).
  Entries are now every element two levels below the root with `ID` and `Name`; unknown kinds are kept; the XML sections seen are reported; the check script fails when there are no categories.
- **Advisory dates.** 28 of 46 advisories had no date because older pages show only "Last Revised". Priority is now: Release Date label, meta tag, RSS pubDate, then a date **derived from the alert code**
  (`AAyy-ddd` = year and day of the year of first release), always marked `published_at_is_derived`. `Last Revised` is never used as the publication date.
  The convention is tested against every page that has a Release Date label (`release_date_matches_alert_code`).
- **Discovery without the feed.** The CISA RSS feed answered HTTP 403 and is not bypassed. `--discover <listing page> --discover-pages N` reads advisory and analysis-report links from CISA listing pages (robots.txt respected).
  Two seed addresses that returned HTTP 404 were removed; six candidates were added.
- **Archived content** is flagged (`archived`), because archived advisories may be outdated and must be treated as such in freshness and conflict analysis.

