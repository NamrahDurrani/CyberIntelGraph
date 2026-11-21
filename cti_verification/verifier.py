"""Claim-by-claim verification of an answer against the evidence it cites.

Principle: the checks are deterministic (identifiers, names, numbers and wording
must be present in the cited evidence). An LLM judge is optional and can only
DOWNGRADE a verdict, never upgrade it: an LLM must not validate its own claims.

Verdicts
  supported    - cited evidence contains the claim's identifiers, names, numbers and wording
  partial      - some of it is present, or the claim sounds more certain than its evidence
  unsupported  - key identifiers/names are missing from the cited evidence, or wording barely overlaps
  uncited      - the claim cites nothing (it may still appear in other evidence; reported as a hint)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from cti_agent.evidence import EvidenceBook, EvidenceStatus
from cti_agent.llm import LLM, LLMUnavailable, NullLLM, extract_json
from cti_agent.nodes import ID_PATTERNS, STOPWORDS, heuristic_terms

from .claims import CITE, Claim, split_claims

SUPPORTED, PARTIAL, UNSUPPORTED, UNCITED = "supported", "partial", "unsupported", "uncited"
HEDGES = ("candidate", "unconfirmed", "not confirmed", "reportedly", "extracted", "possible", "possibly", "may ",
          "might", "appears", "suggests", "inferred", "indirect", "connected via", "linked via", "according to",
          "reported", "llm")
CERTAINTY = re.compile(r"\b(confirmed|verified|established|proven|definitely|known to)\b")
GENERIC = STOPWORDS | {"evidence", "listed", "shows", "shown", "include", "includes", "including", "following",
                       "based", "found", "status", "source", "total", "showing", "sample", "step", "steps"}
NUMBER = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?(?![\w])")


@dataclass
class ClaimResult:
    text: str
    verdict: str
    reasons: list[str] = field(default_factory=list)
    cited: list[str] = field(default_factory=list)
    basis: str = ""                       # strongest evidence status among the cited blocks
    hint: list[str] = field(default_factory=list)  # evidence ids that DO contain an uncited claim's entities
    overstated: bool = False


def _stem(word: str) -> str:
    w = word.lower()
    for suffix in ("ing", "ed", "es", "s"):
        if w.endswith(suffix) and len(w) - len(suffix) >= 4:
            return w[: -len(suffix)]
    return w


def _haystack(items: list) -> str:
    parts = []
    for ev in items:
        parts += [ev.summary, ev.text, ev.source, " ".join(ev.entities), " ".join(map(str, ev.meta.values()))]
    return " ".join(parts).lower()


def _identifiers(text: str) -> list[str]:
    found = []
    for pattern in ID_PATTERNS.values():
        found += [m.group(0).upper() for m in pattern.finditer(text)]
    return list(dict.fromkeys(found))


def _strip_ids(text: str) -> str:
    for pattern in ID_PATTERNS.values():
        text = pattern.sub(" ", text)
    return text


def _content_stems(text: str) -> set[str]:
    words = re.findall(r"[A-Za-z][A-Za-z0-9\-]{3,}", _strip_ids(text))
    return {_stem(w) for w in words if w.lower() not in GENERIC}


def _present(term: str, hay: str, hay_stems: set[str]) -> bool:
    t = term.lower()
    return t in hay or (len(t) > 3 and _stem(t) in hay_stems)


STRENGTH = [EvidenceStatus.CONFIRMED_AUTHORITATIVE, EvidenceStatus.REPORTED_IN_DOCUMENT, EvidenceStatus.INFERRED,
            EvidenceStatus.LLM_CANDIDATE, EvidenceStatus.UNABLE_TO_VERIFY, EvidenceStatus.NOT_FOUND]


def verify_claim(claim: Claim, book: EvidenceBook, min_overlap: float = 0.5) -> ClaimResult:
    cited = [book.get(i) for i in claim.cited]
    valid = [e for e in cited if e is not None]
    all_hay = _haystack(book.items)
    ids = _identifiers(claim.text)
    names = [t for t in heuristic_terms(claim.text, {}) if t.lower() not in GENERIC and len(t) > 2]

    if not valid:
        in_other = [e.id for e in book.items if any(i.lower() in _haystack([e]) for i in ids)
                    or any(n.lower() in _haystack([e]) for n in names)]
        reason = "no valid evidence citation" if not claim.cited else "cited evidence does not exist"
        return ClaimResult(claim.text, UNCITED, [reason], claim.cited, hint=in_other[:3])

    hay = _haystack(valid)
    hay_stems = {_stem(w) for w in re.findall(r"[a-z][a-z0-9\-]{3,}", hay)}
    reasons: list[str] = []
    basis = min((e.status for e in valid), key=STRENGTH.index).value

    missing_ids = [i for i in ids if i.lower() not in hay]
    missing_names = [n for n in names if not _present(n, hay, hay_stems)]
    claim_numbers = NUMBER.findall(_strip_ids(CITE.sub("", claim.text)))
    missing_numbers = [n for n in claim_numbers if n.replace(",", "") not in hay.replace(",", "")]
    stems = _content_stems(claim.text)
    overlap = (sum(1 for s in stems if s in hay_stems or s in hay) / len(stems)) if stems else 1.0

    if missing_ids:
        reasons.append("identifier(s) not in the cited evidence: " + ", ".join(missing_ids))
    if missing_names:
        reasons.append("name(s) not in the cited evidence: " + ", ".join(missing_names[:4]))
    if missing_numbers:
        reasons.append("number(s) not in the cited evidence: " + ", ".join(missing_numbers[:4]))
    if overlap < min_overlap:
        reasons.append(f"only {overlap:.0%} of the claim's wording appears in the cited evidence")

    if missing_ids or (overlap < min_overlap / 2):
        verdict = UNSUPPORTED
    elif missing_names or missing_numbers or overlap < min_overlap:
        verdict = PARTIAL
    else:
        verdict = SUPPORTED

    # sounding more certain than the evidence allows
    lowered = claim.text.lower()
    statuses = {e.status for e in valid}
    only_weak = statuses <= {EvidenceStatus.LLM_CANDIDATE, EvidenceStatus.INFERRED}
    overstated = False
    if only_weak and not any(h in lowered for h in HEDGES):
        overstated = True
        reasons.append("stated as fact, but the cited evidence is only a candidate / inferred connection")
    elif (CERTAINTY.search(lowered) and not any(h in lowered for h in HEDGES)
          and EvidenceStatus.CONFIRMED_AUTHORITATIVE not in statuses):
        overstated = True
        reasons.append("claims confirmation, but no cited evidence is from an authoritative source")
    if overstated and verdict == SUPPORTED:
        verdict = PARTIAL
    return ClaimResult(claim.text, verdict, reasons, claim.cited, basis, overstated=overstated)


LLM_JUDGE_SYSTEM = """You check whether EVIDENCE supports a CLAIM. Reply with JSON only:
{"verdict": "supported" | "partial" | "unsupported", "reason": "<one short sentence>"}
Use only the evidence text. If the evidence does not state the claim, answer unsupported."""


def llm_downgrade(result: ClaimResult, claim: Claim, book: EvidenceBook, llm: LLM) -> ClaimResult:
    """Optional second opinion. It may only make the verdict worse."""
    if isinstance(llm, NullLLM) or result.verdict != SUPPORTED:
        return result
    evidence = "\n\n".join(e.prompt_block() for e in (book.get(i) for i in claim.cited) if e)
    try:
        reply = extract_json(llm.complete(LLM_JUDGE_SYSTEM, f"CLAIM: {claim.text}\n\nEVIDENCE:\n{evidence}", max_tokens=300))
    except (LLMUnavailable, ValueError):
        return result
    verdict = str(reply.get("verdict", "")).lower()
    if verdict in (PARTIAL, UNSUPPORTED):
        result.verdict = verdict
        result.reasons.append(f"LLM judge: {reply.get('reason', verdict)}")
    return result


@dataclass
class VerificationReport:
    results: list[ClaimResult]
    counts: dict[str, int]
    headline: str
    needs_review: bool
    answer: str

    def to_dict(self) -> dict[str, Any]:
        return {"results": [asdict(r) for r in self.results], "counts": self.counts,
                "headline": self.headline, "needs_review": self.needs_review}


TAGS = {UNSUPPORTED: " [UNVERIFIED]", UNCITED: " [UNVERIFIED]", PARTIAL: " [CHECK]"}


def verify_answer(answer: str, book: EvidenceBook, *, llm: LLM | None = None, use_llm_judge: bool = False,
                  min_overlap: float = 0.5, extra_notes: list[str] | None = None) -> VerificationReport:
    claims = [c for c in split_claims(answer) if c.is_claim]
    results: list[ClaimResult] = []
    for claim in claims:
        res = verify_claim(claim, book, min_overlap)
        if use_llm_judge and llm is not None:
            res = llm_downgrade(res, claim, book, llm)
        results.append(res)

    counts = {SUPPORTED: 0, PARTIAL: 0, UNSUPPORTED: 0, UNCITED: 0}
    for r in results:
        counts[r.verdict] += 1
    total = len(results)
    if total == 0:
        headline = "Verification: the answer contains no factual claims to check."
    else:
        headline = (f"Verification: {total} claim(s) checked - {counts[SUPPORTED]} supported, {counts[PARTIAL]} partially "
                    f"supported, {counts[UNSUPPORTED] + counts[UNCITED]} unsupported or uncited.")
    needs_review = bool(counts[PARTIAL] or counts[UNSUPPORTED] or counts[UNCITED])

    annotated = answer
    for claim, res in sorted(zip(claims, results), key=lambda cr: cr[0].end, reverse=True):
        tag = TAGS.get(res.verdict)
        if tag:
            annotated = annotated[: claim.end] + tag + annotated[claim.end:]
    notes = [headline] + list(extra_notes or [])
    if needs_review:
        notes.append("[UNVERIFIED] = the cited evidence does not back this statement. "
                     "[CHECK] = only partly backed, or stated more strongly than the evidence allows.")
    annotated = annotated.rstrip() + "\n\n---\n" + "\n".join(notes)
    return VerificationReport(results, counts, headline, needs_review, annotated)
