r"""Adds the Milestone 14 entries to CHANGELOG.md, PROJECT_STATUS.md and README.md (append-only, safe to run twice)
and writes a dated change report.

  python scripts\apply_milestone_14_docs.py              (records "implemented, verification pending")
  python scripts\apply_milestone_14_docs.py --verified   (run ONLY after the live checks passed on your PC)
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import _bootstrap  # noqa: F401
from _bootstrap import ROOT

MARK = "<!-- milestone-14 -->"


def append_once(path: Path, text: str) -> str:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    if MARK in current:
        return "already present"
    path.write_text(current.rstrip() + "\n\n" + MARK + "\n" + text.strip() + "\n", encoding="utf-8")
    return "updated"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified", action="store_true")
    args = ap.parse_args()
    today = date.today().isoformat()
    state = (f"Verified on the project PC on {today} (offline checks, unit tests, live KEV/NVD check, MongoDB persistence check)."
             if args.verified else "Implemented. Live verification on the project PC (KEV/NVD, MongoDB) is still pending.")

    changelog = f"""## Milestone 14 - Independent verification, live fallback, MongoDB persistence ({today})
- Added `cti_verification/`, attached to the Milestone 13 agent through hooks (no Milestone 13 file edited).
- Verification agent: checks structured claims, the written answer sentence by sentence, contradictions and sufficiency;
  outcomes PASS / PARTIAL / FAIL / TOOL_ERROR. Unsupported statements are marked [UNVERIFIED] / [CHECK]. Optional LLM judge can only downgrade.
- One corrective rewrite on FAIL (kept only if it verifies better). Specialist agents are not re-run by verification.
- Live fallback: CISA KEV and NVD for CVEs in the question or "latest KEV additions"; cache with URL, time and SHA-256 under data/fresh_cache/;
  stale cache only when the download fails and labelled stale; graph-vs-live comparison; a failed download is unable_to_verify, never not_found.
- MongoDB persistence into new collections investigation_runs and investigation_traces (idempotent); JSON copy always written first.
- Scripts: check_verification.py, check_mongodb_persistence.py, apply_milestone_14_docs.py.
- Status: {state}"""

    status = f"""## Milestone 14 - Independent verification, live fallback, MongoDB persistence
{state}

What exists: every answer is audited against its evidence; CVE questions get a live KEV / NVD check with provenance; investigations and
agent traces are saved to MongoDB.

Known limits: investigations are stored in their own collections (not the Milestone 12 validated reports / agent_traces repositories)
- to be unified in Milestone 15; verification is lexical / identifier based; on FAIL only the answer is rewritten, specialist agents are not
re-run; live fallback covers KEV and NVD only; FastAPI endpoints and report generation are Milestone 15."""

    readme = """## Verification and live fallback (Milestone 14)
Offline check: `python scripts/check_verification.py`. Live KEV/NVD check: `python scripts/check_verification.py --live`.
MongoDB check: `python scripts/check_mongodb_persistence.py`. Details: docs/milestones/M14_verification_and_live_fallback.md"""

    report = f"""# Change report - Milestone 14 ({today})

{changelog}

## Files added
- cti_verification/ (settings, fresh, claims, verifier, verification_agent, verify_node, nodes, persistence, hooks, testing)
- scripts/check_verification.py, check_mongodb_persistence.py, apply_milestone_14_docs.py
- tests/unit/test_verification_claims_and_verifier.py, test_verification_fresh_and_integration.py, test_verification_agent_and_persistence.py
- docs/milestones/M14_verification_and_live_fallback.md, docs/data_dictionary/VERIFICATION_RECORD.md
"""
    out = {"CHANGELOG.md": append_once(ROOT / "CHANGELOG.md", changelog),
           "PROJECT_STATUS.md": append_once(ROOT / "PROJECT_STATUS.md", status),
           "README.md": append_once(ROOT / "README.md", readme)}
    report_path = ROOT / "docs" / f"CHANGE_REPORT_{today}_M14_verification.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    for name, result in out.items():
        print(f"{name}: {result}")
    print(f"{report_path.relative_to(ROOT)}: written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
