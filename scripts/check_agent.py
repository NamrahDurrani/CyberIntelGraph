r"""Milestone 13 gate. Two modes:

  python scripts\check_agent.py            OFFLINE: full workflow on a built-in mini graph (no Neo4j, no Groq)
  python scripts\check_agent.py --live     LIVE: real Neo4j Aura + real Groq on a few sample questions

Prints PASS / FAIL per check and exits 1 on any FAIL. A live run never writes to Neo4j.
"""
from __future__ import annotations

import argparse
import sys

import _bootstrap  # noqa: F401

from cti_agent.evidence import EvidenceStatus
from cti_agent.graph import run_question
from cti_agent.testing import FakeLLM, FakeRunner, StaticRetriever, make_test_deps

NO_HOOKS: dict = {}
results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    results.append((ok, label))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  -> {detail}" if detail and not ok else ""))


def offline() -> None:
    from cti_agent.graph import resume_investigation
    from cti_agent.schemas import ClaimStatus

    print("OFFLINE check (mini graph)")
    deps = make_test_deps(llm=FakeLLM(), retriever=StaticRetriever())
    final = run_question("Which techniques does APT29 use?", deps, NO_HOOKS)
    check(bool(final["entities"]), "entity resolved from the graph")
    check({"threat_actor", "attack", "evidence"} <= {a["agent_name"] for a in final["agents"]}, "supervisor ran the specialist agents in parallel")
    check(any(c["status"] == ClaimStatus.DOCUMENTED.value and c["evidence_ids"] for c in final["claims"]), "structured claims carry evidence ids")
    check(any(e["status"] == "confirmed_authoritative" for e in final["evidence"]), "confirmed evidence present")
    check(bool(final["citations_used"]) and not final["invalid_citations"], "answer cites only real evidence")

    final = run_question("What is known about Volt Typhoon?", make_test_deps(), NO_HOOKS)
    cands = [e for e in final["evidence"] if e["kind"] == "graphrag_candidate"]
    check(bool(cands) and all(c["status"] == "llm_candidate" for c in cands), "GraphRAG candidates stay 'llm_candidate'")
    check(not any(e["kind"] == "entity_profile" for e in final["evidence"]), "candidate never promoted to a canonical entity")

    final = run_question("Tell me about Zorblax", make_test_deps(), NO_HOOKS)
    check({e["status"] for e in final["evidence"]} == {"not_found"}, "unknown entity -> not_found (no invention)")

    final = run_question("Which techniques does APT29 use?", make_test_deps(runner=FakeRunner(fail_tools={"find_entities"})), NO_HOOKS)
    check("unable_to_verify" in {e["status"] for e in final["evidence"]}, "tool failure -> unable_to_verify, not not_found")

    final = run_question("Which techniques does APT29 use?", make_test_deps(llm=FakeLLM(fail=True)), NO_HOOKS)
    check("Evidence found" in final["answer"], "LLM outage -> evidence-only fallback answer")

    final = run_question("Which techniques does APT29 use?", make_test_deps(runner=FakeRunner(flaky={"find_entities"})), NO_HOOKS)
    check(final["workflow_status"] == "completed" and any("review: retry" in t for t in final["trace"]), "a failed agent is retried once and recovers")

    deps = make_test_deps()
    paused = run_question("Which techniques does APT29 use?", deps, NO_HOOKS, thread_id="check-1", pause_before=["generate"])
    resumed = resume_investigation("check-1", deps, NO_HOOKS)
    check(paused["workflow_status"] == "paused" and resumed["workflow_status"] == "completed", "pause and resume from a checkpoint")


def live() -> None:
    from dataclasses import replace

    from cti_agent.config import Settings
    from cti_agent.deps import build_default_deps
    from cti_agent.neo4j_client import Neo4jConnectionError

    print("LIVE check (real Neo4j + Groq)")
    settings = Settings.from_env()
    try:
        deps = build_default_deps(settings, refresh_schema=False)
        deps.runner.verify()
    except (Neo4jConnectionError, Exception) as exc:  # noqa: BLE001
        check(False, "connect to Neo4j", str(exc))
        return
    check(True, "connected to Neo4j and loaded schema")
    check(bool(deps.schema.canonical_labels), "canonical labels known")
    check(deps.schema.candidate_label is not None, "candidate label detected", "run scripts\\probe_graph_schema.py")
    print(f"  retriever: {deps.retriever.name}   llm: {type(deps.llm).__name__}")
    questions = [
        "Which software and weaknesses are linked to CVE-2024-3400?",
        "Which techniques does APT29 use?",
        "What do the advisories say about Volt Typhoon?",
    ]
    try:
        for q in questions:
            print(f"\n  Q: {q}")
            final = run_question(q, deps, NO_HOOKS)
            counts = {k: v for k, v in final["evidence_counts"].items() if v}
            print(f"     entities: {[e['name'] for e in final['entities']]}")
            print(f"     evidence: {counts}")
            print(f"     answer: {' '.join(final['answer'].split())[:260]}")
            check(not final["invalid_citations"], f"no invented citations ({q[:32]}...)")
    finally:
        deps.runner.close()
    print("\n  (Read the answers yourself: PASS here means the plumbing works, not that the answer is right.)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    (live if args.live else offline)()
    failed = [l for ok, l in results if not ok]
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(len(failed)) + ' CHECK(S) FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
