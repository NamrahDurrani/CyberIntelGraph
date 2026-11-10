# Data source: CWE - Common Weakness Enumeration (MITRE)

| Item | Value |
|---|---|
| Source name | CWE (Common Weakness Enumeration), maintained by MITRE |
| Official downloads page | https://cwe.mitre.org/data/downloads.html |
| File downloaded | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip (a zip holding one `cwec_v<version>.xml` file) |
| Collection method | HTTP GET of the official zip; the XML inside is read in memory (nothing is extracted to disk) |
| Data format | XML, root element `Weakness_Catalog` with `Name`, `Version`, `Date` attributes. The XML namespace carries the schema version (`http://cwe.mitre.org/cwe-7` in the schemas I read); the collector ignores the namespace, so a schema bump does not break it. |
| Identifier | `ID` attribute (a number), written by the collector as `CWE-<number>` |
| Collector | `ingestion/collectors/cwe/collector.py` |
| Raw location | `data/raw/cwe/cwec_latest__<UTC time>.zip` + `.meta.json` sidecar |
| Processed location | `data/processed/cwe_normalized.json`, `data/processed/cwe_initial_subset.json` |
| Collection date / catalog version on your PC | 2026-11-03: CWE **v5.0** dated 2026-10-28, file `cwec_v5.0.xml` inside a 2,119,263-byte zip |
| Verified on your PC? | **Collector and independent check: YES.** First run: 984 weaknesses (956 active + 28 deprecated), 62 views, no entries named Category, and 8 CWE ids used by NVD/KEV (CWE-189, 19, 254, 255, 264 ...) missing. After the parser fix the subset grew from 246 to 254 records and the "ids not in the catalog" warning disappeared, so the 8 ids are found. They are **not** elements named `Category` in this file; their actual kind name is printed as `Other entry kinds` by the collector (see the correction log). |
| License / usage terms | Read https://cwe.mitre.org/about/termsofuse.html and paste the exact wording here. |

## Elements read from the XML
| XML element | Meaning | Normalized as |
|---|---|---|
| `Weaknesses/Weakness` | A weakness type (Pillar, Class, Base, Variant or Compound) | `element_type = "weakness"` |
| `Categories/Category` | A grouping of weaknesses | `element_type = "category"` |
| `Views/View` | A named way of organizing weaknesses (for example view 1000, Research Concepts) | separate `views` list |
| `External_References` | Citations | not normalized (stay in the raw zip) |

## Weakness / category fields
| Normalized field | From | Notes |
|---|---|---|
| `cwe_id`, `record_id` | `ID` | `CWE-79`, `cwe:CWE-79` |
| `name` | `Name` | required |
| `abstraction`, `structure` | `Abstraction`, `Structure` | weaknesses only (Pillar > Class > Base > Variant) |
| `status` | `Status` | Draft / Incomplete / Stable / Deprecated ...; **Deprecated ids can still appear in NVD records** |
| `description` | `Description` (weakness) or `Summary` (category) | nested XHTML flattened to plain text |
| `extended_description` | `Extended_Description` | same |
| `related_weaknesses[]` | `Related_Weaknesses/Related_Weakness` | `nature` (ChildOf, ParentOf, PeerOf, CanPrecede ...), `cwe_id`, `view_id`, `ordinal` |
| `members[]` | `Relationships/Has_Member` (categories) | `cwe_id`, `view_id` |
| `applicable_platforms[]` | `Applicable_Platforms/*` | `kind` (Language, Operating_System, Architecture, Technology), `name`, `class`, `prevalence` |
| `related_attack_patterns[]` | `Related_Attack_Patterns` | `CAPEC-<id>` |
| `taxonomy_mappings[]` | `Taxonomy_Mappings` | other taxonomies' entry id and name |
| `mapping_notes` | `Mapping_Notes` | `usage` (for example Allowed / Discouraged), `rationale`, `comments`: tells whether the id is appropriate for mapping vulnerabilities |
| `submission_date`, `last_modified` | `Content_History` | last_modified = latest `Modification_Date` |
| `definition_url` | built | `https://cwe.mitre.org/data/definitions/<number>.html` |
| `referenced_by_nvd_records`, `referenced_by_kev_records` | counted from our NVD and KEV files | how many of our records use this id |
| provenance | | `source_name`, `source_url`, `source_record_id`, `retrieved_at`, `published_at` (submission), `last_modified_at`, `original_format`, `raw_file_reference`, `collection_method`, `catalog_version`, `evidence_type` |

## Initial subset (`cwe_initial_subset.json`)
CWE ids that our NVD or KEV records reference, plus all their ancestors through `ChildOf` relationships in view 1000 (Research Concepts).
This is the "relevant weakness categories" from the master prompt. The full catalog is also kept (it is small).
NVD placeholders such as `NVD-CWE-Other` and `NVD-CWE-noinfo` are **not** CWE entries; the collector counts them and leaves them out.

## Things worth knowing
- NVD's CWE ids can be missing from the catalog (for example retired ids). The collector lists them as warnings; it never invents an entry.
- A weakness describes a *type* of flaw. A CVE is one specific instance. `Vulnerability -HAS_WEAKNESS-> Weakness` is built in Milestone 5.
- The hierarchy (`ChildOf`) differs per view. We use view 1000 for ancestors.

## Known limitations
- Only weaknesses, categories and views are normalized (no external references, no consequences, mitigations or detection text yet).
- XML is parsed with Python's built-in parser; the source is the official MITRE download over HTTPS.

## Correction log
- 2026-11-03: the first parser looked for categories only in a fixed `Categories/Category` path and found none in CWE v5.0.
  It now reads every element two levels below the root that has `ID` and `Name`, records what sections it saw (`XML sections` in the summary),
  keeps unknown entry kinds instead of dropping them, and warns / fails when no categories are found.
- 2026-11-10: on your PC the fix worked for the data (the 8 missing ids are found, subset 246 -> 254) but the check still failed, because it looked for the literal element name `Category`.
  The check now asks the real question: are there entries besides weaknesses (any kind)? The name of the kind in your file is shown by the collector (`Other entry kinds`) and by this command:
  `python -c "import json,collections as c; d=json.load(open('data/processed/cwe_normalized.json',encoding='utf-8')); print(c.Counter(r['element_type'] for r in d['records']))"`
