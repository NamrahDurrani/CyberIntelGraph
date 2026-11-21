"""Milestone 13 - end-to-end workflow tests on the in-memory graph (no network)."""
import pytest

from cti_agent.evidence import EvidenceStatus
from cti_agent.graph import build_graph, run_question
from cti_agent.hooks import load_hooks
from cti_agent.testing import FakeLLM, FakeRunner, StaticRetriever, make_test_deps, sample_graph
from cti_agent.tools.text_tools import NullRetriever, TextHit

NO_HOOKS: dict = {}


def run(question, **kw):
    hooks = kw.pop("hooks", NO_HOOKS)
    deps = make_test_deps(**kw)
    return run_question(question, deps, hooks), deps


def statuses(final):
    return {e["status"] for e in final["evidence"]}


def kinds(final):
    return {e["kind"]: e for e in final["evidence"]}


def test_actor_question_uses_parallel_specialists_and_returns_documented_claims():
    final, _ = run("Which techniques does APT29 use?")
    assert final["workflow_status"] == "completed"
    assert set(final["selected_agents"]) == {"threat_actor", "attack", "evidence"}
    assert [e["name"] for e in final["entities"]] == ["APT29"]
    rel = [e for e in final["evidence"] if e["kind"] == "graph_relations"]
    assert rel and "Command and Scripting Interpreter" in rel[0]["text"]
    assert rel[0]["status"] == EvidenceStatus.CONFIRMED_AUTHORITATIVE.value
    claim = next(c for c in final["claims"] if c["predicate"] == "USES" and c["object"] == "Phishing")
    assert claim["status"] == "documented" and claim["evidence_ids"] and claim["subject"] == "APT29"
    assert final["citations_used"] and final["invalid_citations"] == []
    assert len(final["agents"]) == 3 and all(a["status"] in ("ok", "no_results") for a in final["agents"])


def test_cve_question_selects_vulnerability_agent_and_marks_report_mentions_reported():
    final, _ = run("What software does CVE-2024-3400 affect and which weakness?")
    assert "vulnerability" in final["selected_agents"]
    assert "CVE-2024-3400" in [e["name"] for e in final["entities"]]
    k = kinds(final)
    assert k["report_mentions"]["status"] == EvidenceStatus.REPORTED_IN_DOCUMENT.value
    assert any("PAN-OS" in e["text"] for e in final["evidence"])
    assert any(c["predicate"] == "HAS_WEAKNESS" and c["status"] == "documented" for c in final["claims"])


def test_candidates_stay_candidates_and_are_never_promoted():
    final, _ = run("What is known about Volt Typhoon?")
    cands = [e for e in final["evidence"] if e["kind"] == "graphrag_candidate"]
    assert cands and all(c["status"] == EvidenceStatus.LLM_CANDIDATE.value for c in cands)
    assert "living off the land" in cands[0]["text"].lower()
    assert not any(e["kind"] == "entity_profile" for e in final["evidence"])
    cc = [c for c in final["claims"] if c["predicate"] == "extracted_candidate"]
    assert cc and all(c["status"] == "candidate" for c in cc)


def test_connection_between_entities_found_by_different_agents_is_inferred():
    g = sample_graph()
    g.edge("a1", "USES", "s1")
    g.edge("s1", "USES", "w1")
    final, _ = run("Is APT29 connected to CWE-77?", runner=FakeRunner(g))
    path = kinds(final)["graph_path"]
    assert path["status"] == EvidenceStatus.INFERRED.value and path["meta"]["hops"] == 2
    claim = next(c for c in final["claims"] if c["predicate"] == "connected_to")
    assert claim["status"] == "inferred" and "not a stated fact" in claim["explanation"]


def test_unknown_entity_is_not_found_and_llm_does_not_invent():
    llm = FakeLLM()
    final, _ = run("Tell me about Zorblax", llm=llm)
    assert statuses(final) == {"not_found"} and final["workflow_status"] == "no_results"
    assert "could not find" in final["answer"].lower() and "does not prove" in final["answer"].lower()
    assert not any("Evidence blocks" in u for _, u in llm.calls)
    assert any(c["status"] == "not_found" for c in final["claims"])


def test_tool_failure_is_unable_to_verify_never_not_found():
    final, _ = run("Which techniques does APT29 use?", runner=FakeRunner(fail_tools={"find_entities"}))
    assert "unable_to_verify" in statuses(final) and "not_found" not in statuses(final)
    assert final["errors"] and final["workflow_status"] in ("partial", "no_results")
    assert "tool failed" in final["answer"] and "not evidence that the information does not exist" in final["answer"]
    assert any(c["status"] == "unverified" for c in final["claims"])


def test_llm_outage_falls_back_to_evidence_listing():
    final, _ = run("Which techniques does APT29 use?", llm=FakeLLM(fail=True))
    assert "Evidence found" in final["answer"] and final["citations_used"]
    assert any("LLM unavailable" in w for w in final["warnings"])


def test_invalid_and_missing_citations_are_flagged():
    llm = FakeLLM(lambda s, u: "Made-up fact [E99]. Real fact [E1, E98]." if "Evidence blocks" in u else '{"entities": []}')
    final, _ = run("Which techniques does APT29 use?", llm=llm)
    assert "[E?]" in final["answer"] and "[E1]" in final["answer"]
    assert set(final["invalid_citations"]) == {"E99", "E98"}
    llm2 = FakeLLM(lambda s, u: "APT29 uses techniques." if "Evidence blocks" in u else '{"entities": []}')
    final2, _ = run("Which techniques does APT29 use?", llm=llm2)
    assert any("no evidence citations" in w for w in final2["warnings"])


def test_document_passages_are_reported_evidence_deduplicated():
    hit = TextHit(text="CISA reports exploitation of PAN-OS.", chunk_id="aa24::1", doc_id="aa24-100a")
    dup = TextHit(text="CISA  reports exploitation of PAN-OS.", chunk_id="aa24::2", doc_id="aa24-100a")
    final, _ = run("What did CISA report about PAN-OS?", retriever=StaticRetriever([hit, dup]))
    chunks = [e for e in final["evidence"] if e["kind"] == "text_chunk"]
    assert len(chunks) == 1 and chunks[0]["status"] == "reported_in_document" and "aa24-100a" in chunks[0]["source"]
    assert any("duplicate" in l for l in final["limitations"])


def test_retriever_failure_recorded_and_missing_retriever_noted():
    failing, _ = run("What did CISA report about PAN-OS?", retriever=StaticRetriever(fail=True))
    assert any("text_retriever" in e["error"] for e in failing["errors"])
    none, _ = run("Which techniques does APT29 use?", retriever=NullRetriever())
    assert any("No document retriever" in l for l in none["limitations"])


def test_graph_is_only_read():
    runner = FakeRunner()
    run("Which techniques does APT29 use?", runner=runner)
    allowed = {"schema_labels", "schema_rel_types", "schema_keys", "find_entities", "neighbor_summary", "neighbor_sample",
               "shortest_path", "candidates_for", "candidate_relations", "textunits_matching", "report_mentions"}
    assert runner.calls and set(runner.calls) <= allowed


def test_investigation_record_saved_with_id_and_timestamps(tmp_path):
    final, _ = run("Which techniques does APT29 use?", trace_dir=str(tmp_path))
    assert final["trace_file"].endswith(".json") and list(tmp_path.glob("*.json"))
    assert final["investigation_id"] and final["created_at"] <= final["finished_at"]
    assert final["thread_id"]


def test_empty_question_rejected():
    with pytest.raises(ValueError):
        run_question("   ", make_test_deps(), NO_HOOKS)


def test_all_three_hook_points_are_wired_in_order():
    assert load_hooks(("no_such_hook_module_xyz",)) == {"pre_assess": [], "post_generate": [], "post_finalize": []}
    order = []

    def mk(name, update):
        def factory(deps):
            def node(state):
                order.append(name)
                return update(state)
            return node
        return factory

    hooks = {
        "pre_assess": [("my_pre", mk("pre", lambda s: {"trace": ["pre ran"]}))],
        "post_generate": [("my_post", mk("post", lambda s: {"answer": s["answer"] + "\n(post)"}))],
        "post_finalize": [("my_fin", mk("fin", lambda s: {"final": {**s["final"], "extra": True}}))],
    }
    final, _ = run("Which techniques does APT29 use?", hooks=hooks)
    assert order == ["pre", "post", "fin"] and "pre ran" in final["trace"]
    assert final["extra"] is True


def test_graph_compiles_with_expected_nodes():
    names = set(build_graph(make_test_deps(), NO_HOOKS).get_graph().nodes)
    assert {"plan", "run_agent", "collect", "review", "gate", "assess", "generate", "check_citations", "finalize"} <= names
