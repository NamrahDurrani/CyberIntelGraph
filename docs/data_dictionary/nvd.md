# Data source: NVD - National Vulnerability Database (CVE API 2.0)

| Item | Value |
|---|---|
| Source name | NVD CVE API 2.0 |
| Official documentation | https://nvd.nist.gov/developers/vulnerabilities |
| Endpoint (used) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN |
| Collection method | REST GET, one request per CVE ID (`requests`) |
| Data format | JSON envelope + `vulnerabilities[]` (each item has a `cve` object) |
| Identifier field | `cve.id` |
| Collector | `ingestion/collectors/nvd/collector.py` |
| Raw location | `data/raw/nvd/<CVE>__<UTC timestamp>.json` + `manifest.jsonl` |
| Processed location | `data/processed/nvd_normalized.json` |
| Rate limits (published by NVD) | 5 requests / 30 s without API key; 50 requests / 30 s with a free key. NVD suggests ~6 s between requests without a key. |
| API key | Free: https://nvd.nist.gov/developers/request-an-api-key . Sent in the `apiKey` HTTP header (case-sensitive). Put `NVD_API_KEY=...` in `.env` (never committed). |
| Collection date / records | **fill in after the first real run** |
| Verified against a real download? | **NO - update this page after the first real run** |
| License / usage terms | Read the NVD developer terms and paste the exact wording here. |

## What NVD does and does not tell you
NVD describes vulnerabilities (scores, weaknesses, affected products). **It does not establish that a
vulnerability is exploited in the wild.** Use the CISA KEV catalog for that. A record returned with 0 results, or an
API error, is **not** evidence that a CVE does not exist.

## Envelope fields
`resultsPerPage`, `startIndex`, `totalResults`, `format` (expected `NVD_CVE`), `version` (expected `2.0`),
`timestamp`, `vulnerabilities`. For a `cveId` query `totalResults` is 1 (record found) or 0 (nothing returned).

## CVE object -> normalized fields
| Raw (`cve.*`) | Normalized | Notes |
|---|---|---|
| `id` | `cve_id` | Must equal the requested ID, otherwise the response is rejected |
| `descriptions[]` (`lang`=`en`) | `description_en` | Warning if no English text |
| `vulnStatus` | `vuln_status` | e.g. Analyzed; `Rejected` CVEs are flagged in the report |
| `sourceIdentifier` | `source_identifier` | Who reported it |
| `published` / `lastModified` | `published_at` / `last_modified_at` | NVD timestamps, kept as given |
| `metrics.cvssMetricV40/V31/V30/V2[]` | `cvss_metrics_all`, `cvss_primary` | `cvss_primary` = newest CVSS version available (4.0 > 3.1 > 3.0 > 2.0), preferring a `Primary` entry. Nothing is dropped. CVSS v2 keeps severity on the metric item, not in `cvssData`. |
| `weaknesses[].description[]` | `weaknesses[]` (`cwe_id`, `source`, `type`) | Values like `CWE-79`; also `NVD-CWE-Other` / `NVD-CWE-noinfo`, which are NVD placeholders, not real CWE entries |
| `configurations[].nodes[].cpeMatch[]` (vulnerable = true) | `affected_products[]` | CPE string, vendor / product / version split out, version range fields, `matchCriteriaId`. "Running on" context entries (vulnerable = false) stay in the raw file only. |
| `references[]` | `references[]` | `url`, `source`, `tags` |
| keys starting `cisa...` (if NVD carries them) | `nvd_cisa_fields` | Cross-check only. KEV catalog stays authoritative. |

## Provenance on every normalized record
`record_id` (`nvd:<CVE>`), `source_name`, `source_url` (the exact request URL), `source_record_id`, `retrieved_at`,
`published_at`, `last_modified_at`, `original_format`, `raw_file_reference`, `collection_method`.

## Known limitations
- Field names above come from NVD's public documentation and client libraries. **Confirm them against your first real download** and correct this page.
- Vendor / product come from CPE strings and are not the same naming as KEV's free-text `vendorProject` / `product`; matching them is a Milestone 5 task.
- Some CVEs have no CVSS yet, no CWE or no configurations (recently published or awaiting analysis). The collector reports coverage counts instead of treating that as an error.
- One request per CVE is slow without an API key (about 6.5 s each, so 150 CVEs take roughly 16 minutes).
