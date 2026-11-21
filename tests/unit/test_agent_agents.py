"""Milestone 13 - schemas, supervisor planning, specialist agents, retries, budgets, checkpoints."""
import time

import pytest
from pydantic import ValidationError

from cti_agent import agents as agents_mod
from cti_agent.agents import execute_task
from cti_agent.graph import resume_investigation, run_question
from cti_agent.schemas import AgentResult, Claim, ClaimStatus, ResearchTask
from cti_agent.supervisor import build_plan
from cti_agent.testing import FakeLLM, FakeRunner, make_test_deps, sample_graph

NO_HOOKS: dict = {}


# ------------------------------------------------------------------ schemas
def test_documented_claim_without_evidence_is_rejected():
    with pytest.raises(ValidationError):
        Claim(claim_id="c1", text="x", subject="a", predicate="p", status=ClaimStatus.DOCUMENTED)
    ok = Claim(claim_id="c2", text="not found", subject="a", predicate="p", status=ClaimStatus.NOT_FOUND)
    assert ok.evidence_ids == []
    assert {s.value for s in ClaimStatus} == {"documented", "inferred", "candidate", "unsupported", "not_found", "unverified"}


def test_agent_result_and_task_validation():
    with pytest.raises(ValidationError):
        AgentResult(agent_name="x", task_id="t", status="great")
    with pytest.raises(ValidationError):
        ResearchTask(task_id="t", agent="hacker", objective="x")


# ------------------------------------------------------------------ supervisor plan
def agents_of(plan):
    return [t["agent"] for t in plan]


def test_plan_for_cve_only_needs_vulnerability_and_evidence():
    plan = build_plan("What is CVE-2024-3400?", {"cve": ["CVE-2024-3400"]}, [], "vulnerability", 4)
    assert agents_of(plan) == ["vulnerability", "evidence"]
    assert plan[0]["identifiers"] == {"cve": ["CVE-2024-3400"]}


def test_plan_for_actor_techniques_and_vulnerabilities():
    plan = build_plan("Investigate LockBit and identify its exploited vulnerabilities and ATT&CK techniques", {},
                      ["LockBit"], "vulnerability", 4)
    assert set(agents_of(plan)) == {"vulnerability", "threat_actor", "attack", "evidence"}
    assert len({t["task_id"] for t in plan}) == len(plan)


def test_plan_respects_max_parallel_and_always_has_a_task():
    plan = build_plan("q", {}, ["A", "B"], "general", 2)
    assert len(plan) == 2
    assert agents_of(build_plan("hello", {}, [], "general", 4)) == ["evidence"]


# ------------------------------------------------------------------ agents
def test_execute_task_never_raises():
    deps = make_test_deps()
    assert execute_task(deps, {"nonsense": 1}, "q")["status"] == "failed"
    late = execute_task(deps, {"task_id": "t1", "agent": "attack", "objective": "x", "terms": ["APT29"]}, "q",
                        deadline=time.time() - 5)
    assert late["status"] == "failed" and "time budget" in late["errors"][0]

    class Broken:
        def __init__(self, deps): pass
        def run(self, task, question): raise RuntimeError("boom")

    original = agents_mod.AGENTS["attack"]
    agents_mod.AGENTS["attack"] = Broken
    try:
        res = execute_task(deps, {"task_id": "t2", "agent": "attack", "objective": "x"}, "q")
    finally:
        agents_mod.AGENTS["attack"] = original
    assert res["status"] == "failed" and "boom" in res["errors"][0]
    AgentResult.model_validate(res)


def test_vulnerability_agent_reports_stored_kev_fields_without_inventing_actor_links():
    g = sample_graph()
    g.nodes["v1"][1].update({"known_ransomware_campaign_use": "Known", "date_added": "2024-04-12"})
    res = execute_task(make_test_deps(runner=FakeRunner(g)),
                       {"task_id": "t1", "agent": "vulnerability", "objective": "x", "identifiers": {"cve": ["CVE-2024-3400"]}}, "q")
    kev = [e for e in res["evidence"] if e["kind"] == "kev_in_graph"]
    assert kev and "Known" in kev[0]["text"] and "stored copy" in kev[0]["meta"]["note"]
    assert not any(c["predicate"] in ("exploited_by", "used_by") for c in res["claims"])
    assert res["status"] == "ok" and res["tool_calls"] and all("tool" in c for c in res["tool_calls"])


def test_threat_actor_agent_extracts_aliases():
    g = sample_graph()
    g.nodes["a1"][1]["aliases"] = ["Cozy Bear", "The Dukes", "APT29"]
    res = execute_task(make_test_deps(runner=FakeRunner(g)),
                       {"task_id": "t1", "agent": "threat_actor", "objective": "x", "terms": ["APT29"]}, "q")
    alias_claims = [c for c in res["claims"] if c["predicate"] == "alias_of"]
    assert {c["subject"] for c in alias_claims} == {"Cozy Bear", "The Dukes"}
    assert not any(e["kind"] == "graph_relations" and "AttackTechnique" in e["summary"] for e in res["evidence"])


def test_attack_agent_finds_groups_that_use_a_technique():
    res = execute_task(make_test_deps(),
                       {"task_id": "t1", "agent": "attack", "objective": "x", "identifiers": {"technique": ["T1059"]}}, "q")
    assert any(c["subject"] == "APT29" and c["predicate"] == "USES" for c in res["claims"])


def test_agent_tool_budget_is_enforced():
    deps = make_test_deps(max_tool_calls=1)
    res = execute_task(deps, {"task_id": "t1", "agent": "attack", "objective": "x", "terms": ["APT29"]}, "q")
    assert any("budget" in l for l in res["limitations"]) and len(res["tool_calls"]) == 1


# ------------------------------------------------------------------ workflow behaviour
def run(question, **kw):
    return run_question(question, make_test_deps(**kw.pop("deps_kw", {}), **{k: v for k, v in kw.items() if k in ("runner", "llm", "retriever")}), NO_HOOKS)


def test_no_agent_result_is_lost_in_parallel_runs():
    final = run("Investigate APT29 and CVE-2024-3400 techniques and vulnerabilities")
    assert {a["agent_name"] for a in final["agents"]} >= {"vulnerability", "threat_actor", "attack", "evidence"}
    assert {e["name"] for e in final["entities"]} >= {"APT29", "CVE-2024-3400"}


def test_same_evidence_from_two_agents_is_stored_once():
    final = run("Which techniques does APT29 use?")
    profiles = [e for e in final["evidence"] if e["kind"] == "entity_profile"]
    assert len(profiles) == 1


def test_failed_agent_is_retried_once_and_recovers():
    runner = FakeRunner(flaky={"find_entities"})
    final = run("Which techniques does APT29 use?", runner=runner)
    assert any("review: retry" in t for t in final["trace"])
    assert final["workflow_status"] == "completed" and [e["name"] for e in final["entities"]] == ["APT29"]
    assert any(a["attempt"] == 1 for a in final["agents"])


def test_retries_are_bounded():
    deps = make_test_deps(runner=FakeRunner(fail_tools={"find_entities"}), max_retries=2)
    final = run_question("Which techniques does APT29 use?", deps, NO_HOOKS)
    assert sum("review: retry" in t for t in final["trace"]) <= 2 * 2          # at most 2 retries x 2 failing agents
    assert max(a["attempt"] for a in final["agents"]) == 2
    deps0 = make_test_deps(runner=FakeRunner(fail_tools={"find_entities"}), max_retries=0)
    final0 = run_question("Which techniques does APT29 use?", deps0, NO_HOOKS)
    assert not any("review: retry" in t for t in final0["trace"])


def test_broadened_retry_finds_entity_from_partial_word():
    final = run('Tell me about "Phishing Kitxyz"')
    assert any(e["name"] == "Phishing" for e in final["entities"])
    assert any("single words" in t for t in final["trace"])


def test_time_budget_exhausted_degrades_gracefully():
    deps = make_test_deps(max_duration_seconds=-1)
    final = run_question("Which techniques does APT29 use?", deps, NO_HOOKS)
    assert final["workflow_status"] in ("partial", "no_results") and final["errors"]
    assert not any("review: retry" in t for t in final["trace"])


def test_pause_and_resume_from_checkpoint():
    deps = make_test_deps()
    paused = run_question("Which techniques does APT29 use?", deps, NO_HOOKS, thread_id="thread-1", pause_before=["generate"])
    assert paused["workflow_status"] == "paused" and paused["next"] == ["generate"] and "final" not in paused
    final = resume_investigation("thread-1", deps, NO_HOOKS)
    assert final["workflow_status"] == "completed" and final["thread_id"] == "thread-1" and final["answer"]
    with pytest.raises(KeyError):
        resume_investigation("no-such-thread", deps, NO_HOOKS)


def test_resume_refused_when_checkpointing_disabled():
    deps = make_test_deps(checkpoint="none")
    run_question("Which techniques does APT29 use?", deps, NO_HOOKS)
    with pytest.raises(RuntimeError):
        resume_investigation("x", deps, NO_HOOKS)
