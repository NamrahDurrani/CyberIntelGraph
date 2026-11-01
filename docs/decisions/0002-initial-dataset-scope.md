# 0002 - Initial dataset scope

- Date: 2026-11-01
- Status: proposed (confirm or change; other sources will be added as their collectors are built)

## Context
The project starts with a small, focused dataset (ransomware, initial access, exploited vulnerabilities,
malware and techniques) instead of downloading everything. Targets from the master prompt:

| Source | Initial target |
|---|---:|
| NVD | 150-200 vulnerability records |
| CISA KEV | 50-75 entries |
| MITRE ATT&CK | relevant subset of STIX objects |
| CWE | relevant weakness categories |
| CISA advisories | 50-75 documents |

## Decision for CISA KEV (the first collector)
- The official KEV JSON is a **single file**, so the collector downloads it whole (~1.5 MB) and keeps it as the raw record.
- `cisa_kev_normalized.json` holds **all** valid records (faithful, small, cheap).
- `cisa_kev_initial_subset.json` holds the **first 75** by this rule: entries with
  `knownRansomwareCampaignUse = Known` first, then the rest; each group newest `dateAdded` first, ties broken by CVE ID.
  Rule is deterministic, so re-runs on the same catalog give the same subset.
- Change the size with `--subset-size N` (0 disables the subset).

## Consequences
- The NVD collector (Milestone 3, next) should fetch the CVEs listed in the KEV subset first, so the two sources overlap
  and we can test deduplication into one canonical Vulnerability entity.
- Selection is a convenience for keeping GraphRAG indexing cheap; it does not change what the raw record says.
