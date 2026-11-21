"""Milestone 14 - claim splitting and claim-by-claim verification."""
from cti_agent.evidence import EvidenceBook, EvidenceStatus as S
from cti_agent.llm import LLMUnavailable
from cti_agent.testing import FakeLLM
from cti_verification.claims import split_claims
from cti_verification.verifier import (PARTIAL, SUPPORTED, UNCITED, UNSUPPORTED, verify_answer, verify_claim)


def book():
    b = EvidenceBook()
    b.add(S.CONFIRMED_AUTHORITATIVE, "graph_relations", "APT29 -[USES]-> AttackTechnique: 2 total",
          text="- Command and Scripting Interpreter (T1059)\n- Phishing (T1566.001)", entities=["G0016"])      # E1
    b.add(S.LLM_CANDIDATE, "graphrag_candidate", "GraphRAG candidate 'Volt Typhoon' (type: THREAT_ACTOR) - extracted by an LLM",
          text="source passage: Volt Typhoon used living off the land techniques.")                          # E2
    b.add(S.CONFIRMED_AUTHORITATIVE, "fresh_nvd", "NVD record for CVE-2024-3400: CVSS 10.0 CRITICAL",
          text="A command injection in GlobalProtect of PAN-OS.", entities=["CVE-2024-3400"])               # E3
    return b


def test_split_claims_citation_merging_and_ids_not_split():
    answer = ("APT29 uses T1059.001 and Phishing [E1]. It also uses T1566. [E1]\n"
              "- Volt Typhoon is a candidate actor [E2].\nLimitations: only a pilot.")
    claims = split_claims(answer)
    factual = [c for c in claims if c.is_claim]
    assert len(factual) == 3
    assert factual[0].text.startswith("APT29 uses T1059.001") and factual[0].cited == ["E1"]
    assert factual[1].cited == ["E1"]                       # bare "[E1]" merged into the previous sentence
    assert factual[2].cited == ["E2"]
    assert [c.is_claim for c in claims][-1] is False        # Limitations line is not a claim


def test_not_found_sentences_are_not_claims():
    claims = split_claims("I could not find supporting information for this question. That does not prove it is absent.")
    assert not any(c.is_claim for c in claims)


def test_supported_claim():
    claim = split_claims("APT29 uses Command and Scripting Interpreter (T1059) [E1].")[0]
    r = verify_claim(claim, book())
    assert r.verdict == SUPPORTED and r.basis == "confirmed_authoritative"


def test_missing_identifier_is_unsupported():
    claim = split_claims("APT29 uses technique T1486 for impact [E1].")[0]
    r = verify_claim(claim, book())
    assert r.verdict == UNSUPPORTED and any("T1486" in x for x in r.reasons)


def test_wrong_number_is_partial():
    claim = split_claims("CVE-2024-3400 has a CVSS score of 7.5 in the command injection record [E3].")[0]
    r = verify_claim(claim, book())
    assert r.verdict == PARTIAL and any("7.5" in x for x in r.reasons)


def test_uncited_claim_gets_hint_to_evidence_that_contains_it():
    claim = split_claims("Volt Typhoon used living off the land techniques.")[0]
    r = verify_claim(claim, book())
    assert r.verdict == UNCITED and r.hint == ["E2"]


def test_citing_nonexistent_evidence_is_uncited():
    claim = split_claims("APT29 uses Phishing [E9].")[0]
    assert verify_claim(claim, book()).verdict == UNCITED


def test_candidate_stated_as_fact_is_flagged_but_hedged_is_fine():
    flat = verify_claim(split_claims("Volt Typhoon is a threat actor that used living off the land techniques [E2].")[0], book())
    assert flat.overstated and flat.verdict == PARTIAL
    hedged = verify_claim(split_claims("Volt Typhoon is reportedly a threat actor that used living off the land techniques; this is an unconfirmed candidate [E2].")[0], book())
    assert not hedged.overstated and hedged.verdict == SUPPORTED


def test_confirmed_wording_needs_authoritative_evidence():
    r = verify_claim(split_claims("It is confirmed that Volt Typhoon used living off the land techniques [E2].")[0], book())
    assert r.overstated


def test_annotation_and_headline():
    answer = ("APT29 uses Command and Scripting Interpreter (T1059) [E1]. APT29 also uses T1486 [E1].\n"
              "Limitations: pilot data.")
    rep = verify_answer(answer, book())
    assert rep.counts[SUPPORTED] == 1 and rep.counts[UNSUPPORTED] == 1
    assert rep.needs_review
    assert "T1486 [E1]. [UNVERIFIED]" in rep.answer
    assert "(T1059) [E1]. [UNVERIFIED]" not in rep.answer
    assert rep.headline in rep.answer and "[UNVERIFIED] = " in rep.answer
    assert rep.to_dict()["counts"]["unsupported"] == 1


def test_clean_answer_needs_no_review():
    rep = verify_answer("APT29 uses Command and Scripting Interpreter (T1059) [E1].", book())
    assert not rep.needs_review and "[UNVERIFIED]" not in rep.answer


def test_llm_judge_can_only_downgrade():
    good = "APT29 uses Command and Scripting Interpreter (T1059) [E1]."
    down = FakeLLM(lambda s, u: '{"verdict": "unsupported", "reason": "not stated"}')
    rep = verify_answer(good, book(), llm=down, use_llm_judge=True)
    assert rep.counts[UNSUPPORTED] == 1 and any("LLM judge" in x for x in rep.results[0].reasons)

    # a lenient judge cannot rescue a claim the deterministic check rejected
    bad = "APT29 uses technique T1486 for impact [E1]."
    up = FakeLLM(lambda s, u: '{"verdict": "supported", "reason": "fine"}')
    assert verify_answer(bad, book(), llm=up, use_llm_judge=True).counts[UNSUPPORTED] == 1
    assert up.calls == []        # judge is not even consulted for non-supported claims

    outage = FakeLLM(fail=True)
    assert verify_answer(good, book(), llm=outage, use_llm_judge=True).counts[SUPPORTED] == 1


def test_no_claims_headline():
    rep = verify_answer("Limitations: none.", book())
    assert "no factual claims" in rep.headline and not rep.needs_review
