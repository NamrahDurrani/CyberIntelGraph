# Change report - Milestone 14 (2026-11-22)

## Milestone 14 - Independent verification, live fallback, MongoDB persistence (2026-11-22)
- Added `cti_verification/`, attached to the Milestone 13 agent through hooks (no Milestone 13 file edited).
- Verification agent: checks structured claims, the written answer sentence by sentence, contradictions and sufficiency;
  outcomes PASS / PARTIAL / FAIL / TOOL_ERROR. Unsupported statements are marked [UNVERIFIED] / [CHECK]. Optional LLM judge can only downgrade.
- One corrective rewrite on FAIL (kept only if it verifies better). Specialist agents are not re-run by verification.
- Live fallback: CISA KEV and NVD for CVEs in the question or "latest KEV additions"; cache with URL, time and SHA-256 under data/fresh_cache/;
  stale cache only when the download fails and labelled stale; graph-vs-live comparison; a failed download is unable_to_verify, never not_found.
- MongoDB persistence into new collections investigation_runs and investigation_traces (idempotent); JSON copy always written first.
- Scripts: check_verification.py, check_mongodb_persistence.py, apply_milestone_14_docs.py.
- Status: Implemented. Live verification on the project PC (KEV/NVD, MongoDB) is still pending.

## Files added
- cti_verification/ (settings, fresh, claims, verifier, verification_agent, verify_node, nodes, persistence, hooks, testing)
- scripts/check_verification.py, check_mongodb_persistence.py, apply_milestone_14_docs.py
- tests/unit/test_verification_claims_and_verifier.py, test_verification_fresh_and_integration.py, test_verification_agent_and_persistence.py
- docs/milestones/M14_verification_and_live_fallback.md, docs/data_dictionary/VERIFICATION_RECORD.md
