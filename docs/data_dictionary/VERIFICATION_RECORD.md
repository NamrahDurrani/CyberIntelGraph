# Verification and fresh-lookup records (Milestone 14)

## `verification` (inside every investigation record)
`outcome` (PASS / PARTIAL / FAIL / TOOL_ERROR), `tool_error`, `headline`, `answer_counts` (supported / partial / unsupported / uncited),
`answer_results` (per sentence: text, verdict, reasons, cited, basis, hint, overstated), `claim_checks` (structured claims with issues:
claim_id, issues, effective_status, critical), `claims_checked`, `claims_with_issues`, `contradictions` (type, detail),
`sufficiency` (dimensions: relevance / freshness / authority / completeness / consistency with level and note; sufficient; needs_live_check),
`needs_review`, `rewrites`.
Each claim also gains `verified_status` and `verification_issues`.

## `fresh`
`checked` (CVE ids, "recent_kev"), `kev_catalog_version`, `kev_retrieved_at`, `kev_stale`, `errors`, `discrepancies`, `notes`.
Fresh evidence kinds: `fresh_kev`, `fresh_nvd`, `fresh_kev_recent`, `freshness_check` (meta holds sha256 and retrieval time).

## Cache (`data/fresh_cache/`, git-ignored, never `data/raw/`)
`kev_live.json`, `nvd/CVE-*.json`: `{url, retrieved_at, sha256, payload}`.

## MongoDB
`investigation_runs` (unique `investigation_id`): question, status, scope, plan, answer, entities, claims, evidence (excerpts), counts,
citations, limitations, warnings, verification, fresh, `persisted_at`, `report_version`.
`investigation_traces` (unique `investigation_id + task_id + attempt`): agent, status, duration, tool calls, errors, limitations.
