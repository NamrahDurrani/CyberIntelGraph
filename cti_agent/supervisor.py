"""Supervisor / investigation planner.

The plan is built deterministically from what the question contains, so the
same question always produces the same plan; the LLM is only an optional helper
for spotting extra entity names. The supervisor never states facts: it only
decides which specialists run, with which inputs."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from langgraph.types import Send

from .deps import Deps
from .llm import LLMUnavailable, NullLLM, extract_json
from .nlp import classify_intent, extract_identifiers, heuristic_terms, matching_intents

UNDERSTAND_SYSTEM = """Extract the cybersecurity entities named in the user's question
(threat actors, malware, tools, software products, vulnerability names, techniques).
Reply with JSON only, no prose: {"entities": ["name", ...]}. Use the names exactly as a database would store them."""

ATTACK_ID_KINDS = ("technique", "group", "software")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_plan(question: str, identifiers: dict[str, list[str]], terms: list[str], intent: str,
               max_parallel: int) -> list[dict[str, Any]]:
    """Choose specialists from the question. Not every investigation needs every agent."""
    tasks: list[dict[str, Any]] = []

    def add(agent: str, objective: str, terms_: list[str], ids: dict[str, list[str]]) -> None:
        tasks.append({"task_id": f"t{len(tasks) + 1}-{agent}", "agent": agent, "objective": objective,
                      "terms": terms_, "identifiers": ids, "attempt": 0})

    cve_ids = {k: identifiers[k] for k in ("cve", "cwe") if k in identifiers}
    attack_ids = {k: identifiers[k] for k in ATTACK_ID_KINDS if k in identifiers}
    wants_attack = bool(attack_ids) or "techniques" in matching_intents(question) or intent == "techniques"

    if cve_ids:
        add("vulnerability", "Retrieve CVE / weakness records, affected software and stored exploitation data", [], cve_ids)
    if "vulnerability" in matching_intents(question) and terms and not cve_ids:
        add("vulnerability", "Look up the named vulnerabilities, weaknesses or software", terms, {})
    if terms or attack_ids.get("group") or attack_ids.get("software"):
        add("threat_actor", "Investigate the named actors, groups, malware, tools and campaigns",
            terms, {k: v for k, v in attack_ids.items() if k in ("group", "software")})
    if wants_attack or (terms and not cve_ids):
        add("attack", "Map entities to documented MITRE ATT&CK techniques, tactics and mitigations", terms, attack_ids)
    all_ids = {**cve_ids, **attack_ids}
    add("evidence", "Retrieve supporting document passages and GraphRAG candidates", terms, all_ids)
    return tasks[: max(1, max_parallel)]


def make_plan_node(deps: Deps):
    s = deps.settings

    def plan(state: dict) -> dict:
        question = state["question"]
        identifiers = extract_identifiers(question)
        terms = heuristic_terms(question, identifiers)
        trace = [f"supervisor: identifiers={identifiers} heuristic_terms={terms}"]
        if not isinstance(deps.llm, NullLLM):
            try:
                reply = deps.llm.complete(UNDERSTAND_SYSTEM, question, max_tokens=400)
                extra = [str(t).strip() for t in extract_json(reply).get("entities", []) if str(t).strip()]
                known = {t.lower() for t in terms}
                terms += [t for t in extra if t.lower() not in known]
                trace.append(f"supervisor: llm_entities={extra}")
            except (LLMUnavailable, ValueError) as exc:
                trace.append(f"supervisor: llm entity helper skipped ({exc})")
        id_values = {v.lower() for vals in identifiers.values() for v in vals}
        terms = [t for t in dict.fromkeys(terms) if t.lower() not in id_values][:8]
        intent = classify_intent(question)
        tasks = build_plan(question, identifiers, terms, intent, s.max_parallel)
        trace.append("supervisor: plan -> " + ", ".join(t["agent"] for t in tasks))
        started = now_iso()
        return {
            "investigation_id": state.get("investigation_id") or uuid.uuid4().hex[:12],
            "created_at": started, "updated_at": started,
            "deadline_ts": time.time() + s.max_duration_seconds,
            "identifiers": identifiers, "terms": terms, "intent": intent,
            "investigation_scope": {"intent": intent, "identifiers": identifiers, "entities": terms},
            "investigation_plan": [{k: t[k] for k in ("task_id", "agent", "objective")} for t in tasks],
            "research_tasks": tasks, "selected_agents": [t["agent"] for t in tasks],
            "task_attempts": {}, "retry_tasks": [], "workflow_status": "running", "trace": trace,
        }

    return plan


def fan_out(state: dict) -> list[Send]:
    """One Send per task: LangGraph runs them in parallel."""
    return [Send("run_agent", {"task": t, "question": state["question"], "deadline_ts": state.get("deadline_ts")})
            for t in state.get("research_tasks", [])]


def route_review(state: dict):
    retry = state.get("retry_tasks") or []
    if retry:
        return [Send("run_agent", {"task": t, "question": state["question"], "deadline_ts": state.get("deadline_ts")})
                for t in retry]
    return "gate"
