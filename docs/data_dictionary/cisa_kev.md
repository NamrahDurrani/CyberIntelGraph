# Data source: CISA Known Exploited Vulnerabilities (KEV)

| Item | Value |
|---|---|
| Source name | CISA Known Exploited Vulnerabilities (KEV) catalog |
| Official catalog page | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| Machine-readable feed (used) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Collection method | HTTP GET of the official JSON catalog (`requests`), no scraping |
| Data format | One JSON file: a small envelope + a `vulnerabilities` array |
| Identifier field | `cveID` (one record per CVE) |
| Collector | `ingestion/collectors/cisa_kev/collector.py` |
| Raw location | `data/raw/cisa_kev/kev_raw_<UTC timestamp>.json` (+ `.meta.json` sidecar) |
| Processed location | `data/processed/cisa_kev_normalized.json`, `cisa_kev_initial_subset.json` |
| Collection date | **fill in after the first real run** |
| Catalog version / count at collection | **fill in after the first real run** |
| Verified against a real download? | **NO - update this page after the first real run** |
| License / usage terms | Public U.S. government data. Read the terms on the CISA site and paste the exact wording here. |

## What KEV means (important for this project)
KEV is CISA's list of vulnerabilities that **it has determined are exploited in the wild**.
NVD records do **not** establish that. So `check_kev_status` (Milestone 14) must use KEV for that claim.

## Envelope fields
| Field | Meaning |
|---|---|
| `title` | Catalog title (collector warns if missing, not fatal) |
| `catalogVersion` | Version string of this snapshot |
| `dateReleased` | When this snapshot was released |
| `count` | Number of vulnerabilities declared (collector checks it equals the real count) |
| `vulnerabilities` | The records |

## Record fields (raw name -> normalized name)
| Raw field | Normalized | Treated as | Meaning |
|---|---|---|---|
| `cveID` | `cve_id` | required | CVE identifier (upper-cased, format `CVE-YYYY-NNNN+` checked) |
| `vendorProject` | `vendor_project` | required | Vendor or project name (free text, not a controlled vocabulary) |
| `product` | `product` | required | Product name (free text) |
| `vulnerabilityName` | `vulnerability_name` | required | CISA's short name for the vulnerability |
| `dateAdded` | `date_added` (also `published_at`) | required | Date CISA added it to KEV (`YYYY-MM-DD`). **Not** the CVE publication date. |
| `shortDescription` | `short_description` | expected (warning if empty) | Short description |
| `requiredAction` | `required_action` | expected | Action CISA requires of federal agencies |
| `dueDate` | `due_date` | expected | Remediation due date |
| `knownRansomwareCampaignUse` | `known_ransomware_campaign_use_raw` + boolean `known_ransomware_campaign_use` | expected | `Known` -> true, `Unknown` -> false, anything else -> null + warning |
| `notes` | `notes` | optional | Extra notes / links |
| `cwes` | `cwes` (list) | optional | CWE IDs; a later addition to the feed, so absent on some entries/versions -> `[]` |

The collector tolerates unknown extra fields (they stay in the raw file; they are not copied to the normalized file).
**After the first real run**, compare this table with the actual keys in the raw file and correct it.

## Provenance fields added to every normalized record
`record_id` (`kev:<CVE>`), `source_name`, `source_url`, `source_record_id`, `retrieved_at`,
`published_at`, `last_modified_at` (always null: KEV has no per-record modified date),
`original_format`, `raw_file_reference`, `collection_method`.

## Known limitations
- The feed is one file with **all** entries, so the whole catalog is downloaded; the *initial subset* is a selection made afterwards (see decision 0002).
- Vendor/product names are inconsistent free text; matching to Software entities needs care in Milestone 5.
- KEV has no per-record modified date; use `catalogVersion` / `dateReleased` to judge freshness.
