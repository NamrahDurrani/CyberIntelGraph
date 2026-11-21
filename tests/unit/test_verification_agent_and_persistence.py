"""Milestone 14 - independent verification agent, outcomes, rewrite, and MongoDB persistence."""
from cti_agent.evidence import EvidenceBook, EvidenceStatus as S
from cti_agent.graph import run_question
from cti_agent.testing import FakeLLM, FakeRunner, make_test_deps, sample_graph
from cti_verification.hooks import get_hooks
from cti_verification.persistence import MongoInvestigationStore, build_documents, scrub
from cti_verification.settings import VerifySettings
from cti_verification.testing import FakeFetcher, FakeMongoDb
from cti_verification.verification_agent import (assess_sufficiency, check_structured_claims, find_contradictions,
                                                 run_verification)


def claim(cid, status, ev, subject="APT29", pred="USES", obj="Phishing", text=None):
    return {"claim_id": cid, "text": text or f"{subject} {pred} {obj}", "subject": subject, "predicate": pred,
            "object": obj, "evidence_ids": ev, "status": status}


def book():
    b = EvidenceBook()
    b.add(S.CONFIRMED_AUTHORITATIVE, "graph_relations", "APT29 -[USES]-> AttackTechnique", text="- Phishing (T1566)", source="graph")
    b.add(S.LLM_CANDIDATE, "graphrag_candidate", "candidate Volt Typhoon", text="Volt Typhoon", source="graphrag")
    b.add(S.CONFIRMED_AUTHORITATIVE, "entity_profile", "Vulnerability CVE-2024-3400", text="cve_id: CVE-2024-3400", source="nvd",
          entities=["CVE-2024-3400"], meta={"date_added": "not-a-date"})
    return b


# ------------------------------------------------------------ structured claims
def test_structured_claim_checks():
    claims = [claim("ok", "documented", ["E1"]),
              claim("ghost", "documented", ["E9"]),
              claim("weak", "documented", ["E2"], subject="Volt Typhoon", pred="is_a", obj="actor"),
              claim("fake-id", "documented", ["E1"], text="APT29 uses T9999"),
              claim("bad-format", "documented", ["E3"], subject="CVE-24-1", pred="is_a", obj="Vulnerability", text="CVE-24-1 is a vulnerability"),
              claim("baddate", "documented", ["E3"], subject="CVE-2024-3400", pred="is_a", obj="Vulnerability")]
    got = {c.claim_id: c for c in check_structured_claims(claims, book())}
    assert not got["ok"].issues
    assert got["ghost"].critical and got["ghost"].effective_status == "unsupported"
    assert got["weak"].effective_status == "candidate" and not got["weak"].critical      # downgraded, not deleted
    assert got["fake-id"].critical and any("T9999" in i for i in got["fake-id"].issues)
    assert got["bad-format"].critical and any("invalid CVE" in i for i in got["bad-format"].issues)
    assert any("unreadable date" in i for i in got["baddate"].issues)


def test_contradictions_found_vs_not_found_and_stored_vs_live():
    claims = [claim("a", "documented", ["E1"]), claim("b", "not_found", ["E1"])]
    assert any(c["type"] == "found_vs_not_found" for c in find_contradictions(claims, book(), {}))
    b = EvidenceBook()
    b.add(S.CONFIRMED_AUTHORITATIVE, "kev_in_graph", "stored KEV fields for CVE-2024-3400", entities=["CVE-2024-3400"])
    b.add(S.NOT_FOUND, "fresh_kev", "CVE-2024-3400 is not listed in KEV", entities=["CVE-2024-3400"])
    found = find_contradictions([], b, {"discrepancies": ["CVE-2024-3400: CVSS in the graph is 9.8, live NVD says 10.0"]})
    assert {c["type"] for c in found} == {"stored_vs_live"} and len(found) == 2


def test_sufficiency_dimensions():
    b = book()
    ok = assess_sufficiency("What does APT29 use?", b, {}, [], 0, [])
    assert ok["sufficient"] and ok["dimensions"]["freshness"]["level"] == "ok"
    stale = assess_sufficiency("Is CVE-2024-3400 exploited?", b, {}, [], 0, [])
    assert stale["dimensions"]["freshness"]["level"] == "warn" and stale["needs_live_check"]
    bad = assess_sufficiency("q", b, {}, ["X"], 1, [{"type": "x", "detail": "d"}])
    assert not bad["sufficient"] and bad["dimensions"]["completeness"]["level"] == "warn"
    assert not assess_sufficiency("q", EvidenceBook(), {}, [], 0, [])["sufficient"]


def run_v(answer, claims=None, fresh=None, question="What does APT29 use?", evidence=None):
    return run_verification(question=question, answer=answer, claims=claims or [], evidence=(evidence or book()).to_dicts(),
                            fresh=fresh, unresolved=[], agent_failures=0, llm=None, use_llm_judge=False, min_overlap=0.5)


def test_outcome_pass_partial_fail_tool_error():
    assert run_v("APT29 uses Phishing (T1566) [E1].", [claim("ok", "documented", ["E1"])])["outcome"] == "PASS"
    partial = run_v("APT29 uses Phishing (T1566) [E1]. Volt Typhoon is a threat actor [E2].")
    assert partial["outcome"] == "PARTIAL" and partial["needs_review"]
    fail = run_v("APT29 uses T9999 [E1]. APT29 uses T8888 [E1].")
    assert fail["outcome"] == "FAIL"
    integrity = run_v("APT29 uses Phishing (T1566) [E1].", [claim("ghost", "documented", ["E9"])])
    assert integrity["outcome"] == "FAIL"
    tool = run_v("CVE-2024-3400 is a vulnerability [E3].", fresh={"errors": ["CISA KEV: outage"]}, question="Is CVE-2024-3400 exploited?")
    assert tool["outcome"] == "TOOL_ERROR" and tool["tool_error"] and "could not be reached" in tool["headline"]
    assert "Verification TOOL_ERROR" in tool["annotated_answer"]


def test_contradiction_forces_partial_even_when_wording_is_supported():
    r = run_v("APT29 uses Phishing (T1566) [E1].", [claim("ok", "documented", ["E1"])],
              fresh={"discrepancies": ["CVE-1: CVSS differs"]})
    assert r["outcome"] == "PARTIAL" and "Contradiction:" in r["annotated_answer"]


# ------------------------------------------------------------ in the workflow
def deps_with(tmp_path, llm=None, mongo=None, fetcher=None, graph=None, **vs_kw):
    deps = make_test_deps(runner=FakeRunner(graph) if graph else None, llm=llm)
    deps.extras.update({"fresh_fetcher": fetcher or FakeFetcher(), "fresh_sleep": lambda s: None,
                        "verify_settings": VerifySettings(cache_dir=str(tmp_path), nvd_delay_seconds=0.0, **vs_kw)})
    if mongo is not None:
        deps.extras["mongo_db"] = mongo
    return deps


def test_grounded_answer_passes_end_to_end(tmp_path):
    final = run_question("Which techniques does APT29 use?", deps_with(tmp_path), get_hooks())
    assert final["verification"]["outcome"] == "PASS" and "Verification PASS" in final["answer"]
    assert all(c["verified_status"] == c["status"] for c in final["claims"])


def test_failed_answer_gets_one_corrective_rewrite_that_is_kept_only_if_better(tmp_path):
    calls = {"n": 0}

    def llm(system, user):
        if "Evidence blocks" not in user:
            return '{"entities": []}'
        calls["n"] += 1
        if "reviewer found" in user:                       # the corrective rewrite
            return "APT29 -[USES]-> AttackTechnique: 2 total, showing 2 [E2]."
        return "APT29 uses technique T9999 [E1]. APT29 uses T8888 [E1]."

    final = run_question("Which techniques does APT29 use?", deps_with(tmp_path, llm=FakeLLM(llm)), get_hooks())
    assert calls["n"] == 2 and final["verification"]["rewrites"] == 1
    assert final["verification"]["outcome"] in ("PASS", "PARTIAL") and "T9999" not in final["answer"]

    calls["n"] = 0
    never_better = FakeLLM(lambda s, u: '{"entities": []}' if "Evidence blocks" not in u
                           else "APT29 uses technique T9999 [E1]. APT29 uses T8888 [E1].")
    final2 = run_question("Which techniques does APT29 use?", deps_with(tmp_path, llm=never_better), get_hooks())
    assert final2["verification"]["outcome"] == "FAIL" and final2["verification"]["rewrites"] == 0
    assert "[UNVERIFIED]" in final2["answer"]                                      # kept, but clearly marked

    final3 = run_question("Which techniques does APT29 use?",
                          deps_with(tmp_path, llm=never_better, max_rewrites=0), get_hooks())
    assert final3["verification"]["rewrites"] == 0


def test_live_outage_gives_tool_error_not_fail_or_not_found(tmp_path):
    def llm(system, user):
        if "Evidence blocks" not in user:
            return '{"entities": []}'
        return "CVE-2024-3400 is a Vulnerability in the knowledge graph [E1]."

    final = run_question("Is CVE-2024-3400 exploited?", deps_with(tmp_path, llm=FakeLLM(llm), fetcher=FakeFetcher(fail={"kev", "nvd"})), get_hooks())
    assert final["verification"]["outcome"] == "TOOL_ERROR"
    assert "not_found" not in {e["status"] for e in final["evidence"] if e["kind"].startswith("fresh_")}


# ------------------------------------------------------------ persistence
def test_secrets_are_scrubbed():
    text = scrub({"a": "see mongodb+srv://user:pw@cluster.example/db and gsk_ABCDEFGHIJKLMN", "b": ["password=hunter2"]})
    assert "pw@" not in str(text) and "gsk_" not in str(text) and "hunter2" not in str(text)


def test_investigation_saved_idempotently_without_copying_the_graph(tmp_path):
    db = FakeMongoDb()
    deps = deps_with(tmp_path, mongo=db)
    final = run_question("Which techniques does APT29 use?", deps, get_hooks())
    assert final["persistence"]["mongo"] == "saved"
    runs, traces = db["investigation_runs"].docs, db["investigation_traces"].docs
    assert len(runs) == 1 and runs[0]["investigation_id"] == final["investigation_id"] and runs[0]["claims"]
    assert len(traces) == len(final["agents"]) and all("tool_calls" in t for t in traces)
    assert all(len(e["text"]) <= 1000 for e in runs[0]["evidence"])
    store = MongoInvestigationStore(db, deps.extras["verify_settings"])
    store.save(final)
    assert len(db["investigation_runs"].docs) == 1                                  # upsert, no duplicate
    assert store.get(final["investigation_id"])["question"] == final["question"]
    assert store.get("nope") is None and store.list()[0]["investigation_id"] == final["investigation_id"]
    assert len(store.traces(final["investigation_id"])) == len(traces)


def test_database_outage_never_loses_the_result(tmp_path):
    final = run_question("Which techniques does APT29 use?", deps_with(tmp_path, mongo=FakeMongoDb(fail=True)), get_hooks())
    assert final["persistence"]["mongo"].startswith("FAILED") and final["answer"] and final["trace_file"]
    assert any("NOT saved to MongoDB" in w for w in final["warnings"])


def test_persistence_skipped_without_uri_or_when_disabled(tmp_path):
    assert run_question("Which techniques does APT29 use?", deps_with(tmp_path), get_hooks())["persistence"]["mongo"].startswith("skipped (no MongoDB")
    off = run_question("Which techniques does APT29 use?", deps_with(tmp_path, mongo=FakeMongoDb(), persist_mongo=False), get_hooks())
    assert off["persistence"]["mongo"].startswith("skipped (PERSIST_MONGO")


def test_build_documents_shape():
    final = run_question("Which techniques does APT29 use?", deps_with(__import__("pathlib").Path("/tmp")), {})
    run, traces = build_documents(final)
    assert run["report_version"] == 1 and run["persisted_at"] and traces[0]["investigation_id"] == run["investigation_id"]
