"""Verification Agent - deliberately independent of the specialist agents.

It never trusts an agent's own status or confidence. It re-checks, from the
underlying evidence records:
  1. structured claims   (evidence exists, status is justified, identifiers are real and present, sources/dates valid)
  2. the written answer  (sentence by sentence, see verifier.py)
  3. contradictions      (found vs not found, stored vs live data, conflicting live/graph values)
  4. sufficiency         (relevance, freshness, authority, completeness, consistency)
and returns one outcome:
  PASS        claims meet the evidence and validation requirements
  PARTIAL     some claims are supported; others are qualified ([CHECK] / [UNVERIFIED])
  FAIL        critical claims lack evidence or contain invalid references
  TOOL_ERROR  a source needed for verification could not be reached (this is NOT a failure of the claims,
              and NOT evidence that anything is missing)
Deterministic Python does the checking; an optional LLM judge may only downgrade.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cti_agent.evidence import EvidenceBook, EvidenceStatus as S
from cti_agent.llm import LLM

from .nodes import CVE_IN_TEXT, wants_fresh
from .verifier import (PARTIAL, SUPPORTED, UNCITED, UNSUPPORTED, VerificationReport, _haystack, _identifiers,
                       verify_answer)

PASS_, PARTIAL_, FAIL_, TOOL_ERROR_ = "PASS", "PARTIAL", "FAIL", "TOOL_ERROR"

STRICT = {
    "CVE": re.compile(r"^CVE-\d{4}-\d{4,7}$"),
    "ATT&CK technique": re.compile(r"^T\d{4}(?:\.\d{3})?$"),
    "CWE": re.compile(r"^CWE-\d{1,5}$"),
}
LOOSE = [("CVE", re.compile(r"\bCVE-[\w-]+", re.IGNORECASE)), ("CWE", re.compile(r"\bCWE-[\w-]+", re.IGNORECASE)),
         ("ATT&CK technique", re.compile(r"\bT\d{2,6}(?:\.\d+)?\b"))]
DATE_KEYS = ("date", "modified", "published", "released", "retrieved_at")
AUTHORITATIVE = {S.CONFIRMED_AUTHORITATIVE, S.REPORTED_IN_DOCUMENT}


@dataclass
class ClaimCheck:
    claim_id: str
    issues: list[str] = field(default_factory=list)
    effective_status: str = ""
    critical: bool = False


def _date_ok(value: Any) -> bool:
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value)))


def check_structured_claims(claims: list[dict[str, Any]], book: EvidenceBook) -> list[ClaimCheck]:
    checks: list[ClaimCheck] = []
    for c in claims:
        chk = ClaimCheck(c["claim_id"], effective_status=c["status"])
        evs = [book.get(i) for i in c.get("evidence_ids", [])]
        if c["status"] in ("documented", "inferred", "candidate") and not c.get("evidence_ids"):
            chk.issues.append("no evidence cited")
            chk.critical = True
        if any(e is None for e in evs):
            chk.issues.append("cites evidence that does not exist")
            chk.critical = True
        real = [e for e in evs if e is not None]
        if real:
            hay = _haystack(real)
            if c["status"] == "documented" and not any(e.status in AUTHORITATIVE for e in real):
                weakest = real[0].status
                chk.issues.append(f"marked documented, but the cited evidence is only '{weakest.value}'")
                chk.effective_status = "candidate" if weakest == S.LLM_CANDIDATE else "inferred" if weakest == S.INFERRED else "unverified"
            text = " ".join(str(x) for x in (c["subject"], c.get("object") or "", c["text"]))
            for label, loose in LOOSE:
                for token in dict.fromkeys(m.group(0).upper() for m in loose.finditer(text)):
                    strict = STRICT[label]
                    if not strict.match(token):
                        chk.issues.append(f"invalid {label} identifier format: {token}")
                        chk.critical = True
                    elif token.lower() not in hay:
                        chk.issues.append(f"{label} identifier {token} does not appear in the cited evidence")
                        chk.critical = True
            for e in real:
                if not e.source.strip():
                    chk.issues.append(f"evidence {e.id} has no source reference")
                for key, value in e.meta.items():
                    if any(k in key.lower() for k in DATE_KEYS) and value and not _date_ok(value):
                        chk.issues.append(f"evidence {e.id} has an unreadable date in '{key}': {value}")
        if chk.critical:
            chk.effective_status = "unsupported"
        checks.append(chk)
    return checks


def find_contradictions(claims: list[dict[str, Any]], book: EvidenceBook, fresh: dict[str, Any]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    groups: dict[tuple, set[str]] = {}
    for c in claims:
        groups.setdefault((str(c["subject"]).lower(), c["predicate"], str(c.get("object") or "").lower()), set()).add(c["status"])
    for (subj, pred, obj), statuses in groups.items():
        if "documented" in statuses and "not_found" in statuses:
            found.append({"type": "found_vs_not_found", "detail": f"'{subj} {pred} {obj}' is documented by one source and not found by another"})
    for d in fresh.get("discrepancies", []):
        found.append({"type": "stored_vs_live", "detail": d})
    stored = {cve for e in book.items if e.kind == "kev_in_graph" for cve in e.entities}
    for e in book.items:
        if e.kind == "fresh_kev" and e.status == S.NOT_FOUND:
            for cve in e.entities:
                if cve in stored or any(x.kind == "kev_in_graph" and cve in x.summary for x in book.items):
                    found.append({"type": "stored_vs_live",
                                  "detail": f"the stored record of {cve} has exploitation fields, but the live KEV catalog does not list it"})
    return found


def assess_sufficiency(question: str, book: EvidenceBook, fresh: dict[str, Any], unresolved: list[str],
                       agent_failures: int, contradictions: list[dict[str, str]]) -> dict[str, Any]:
    items = book.items
    content = [e for e in items if e.status not in (S.NOT_FOUND, S.UNABLE_TO_VERIFY)]
    auth = [e for e in items if e.status == S.CONFIRMED_AUTHORITATIVE]
    needs_live = bool(CVE_IN_TEXT.search(question)) or wants_fresh(question)
    live = [e for e in items if e.kind.startswith("fresh_") and e.status in (S.CONFIRMED_AUTHORITATIVE, S.NOT_FOUND)]
    dims: dict[str, dict[str, str]] = {}
    dims["relevance"] = {"level": "ok" if content else "fail", "note": f"{len(content)} evidence item(s) with content"}
    if needs_live and not live:
        dims["freshness"] = {"level": "warn", "note": "stored data only; no successful live check"}
    elif fresh.get("kev_stale"):
        dims["freshness"] = {"level": "warn", "note": "live source unreachable; cached copy used"}
    else:
        dims["freshness"] = {"level": "ok", "note": "live check done" if live else "no live check required"}
    dims["authority"] = {"level": "ok" if auth else ("warn" if content else "fail"),
                         "note": f"{len(auth)} of {len(items)} evidence items are from authoritative sources"}
    gaps = len(unresolved) + agent_failures
    dims["completeness"] = {"level": "warn" if gaps else "ok",
                            "note": f"{len(unresolved)} unresolved name(s), {agent_failures} failed agent task(s)"}
    dims["consistency"] = {"level": "fail" if contradictions else "ok", "note": f"{len(contradictions)} contradiction(s)"}
    sufficient = dims["relevance"]["level"] != "fail" and dims["consistency"]["level"] != "fail" and dims["authority"]["level"] != "fail"
    return {"dimensions": dims, "sufficient": sufficient, "needs_live_check": needs_live}


def run_verification(*, question: str, answer: str, claims: list[dict[str, Any]], evidence: list[dict[str, Any]],
                     fresh: dict[str, Any] | None, unresolved: list[str], agent_failures: int, llm: LLM | None,
                     use_llm_judge: bool, min_overlap: float) -> dict[str, Any]:
    fresh = fresh or {}
    book = EvidenceBook(evidence)
    checks = check_structured_claims(claims, book)
    contradictions = find_contradictions(claims, book, fresh)
    sufficiency = assess_sufficiency(question, book, fresh, unresolved, agent_failures, contradictions)

    notes: list[str] = []
    if fresh.get("discrepancies"):
        notes.append("Freshness: the graph may be outdated - " + "; ".join(fresh["discrepancies"][:3]))
    if fresh.get("kev_stale"):
        notes.append("The CISA KEV catalog used here is a cached copy because the live download failed.")
    if any(e.status == S.UNABLE_TO_VERIFY for e in book.items):
        notes.append("Some checks could not be completed (marked 'unable to verify'); absence of data is not proof of absence.")
    for c in contradictions:
        notes.append("Contradiction: " + c["detail"])

    report: VerificationReport = verify_answer(answer, book, llm=llm, use_llm_judge=use_llm_judge,
                                               min_overlap=min_overlap, extra_notes=notes)
    counts = report.counts
    total = sum(counts.values())
    bad = counts[UNSUPPORTED] + counts[UNCITED]
    integrity = [c for c in checks if c.critical]
    tool_error = bool(fresh.get("errors")) and sufficiency["needs_live_check"]

    if integrity or (total and bad * 2 >= total):
        outcome = FAIL_
    elif tool_error:
        outcome = TOOL_ERROR_
    elif report.needs_review or any(c.issues for c in checks) or contradictions:
        outcome = PARTIAL_
    else:
        outcome = PASS_

    headline = f"Verification {outcome}: " + report.headline.removeprefix("Verification: ")
    if outcome == TOOL_ERROR_:
        headline += " A live source could not be reached, so current status could not be verified."
    return {
        "outcome": outcome, "tool_error": tool_error, "headline": headline,
        "answer_counts": counts, "answer_results": [r.__dict__ for r in report.results],
        "claim_checks": [c.__dict__ for c in checks if c.issues],
        "claims_checked": len(checks), "claims_with_issues": sum(1 for c in checks if c.issues),
        "contradictions": contradictions, "sufficiency": sufficiency,
        "annotated_answer": report.answer.replace(report.headline, headline, 1), "needs_review": outcome != PASS_,
    }
