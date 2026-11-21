"""Specialist research agents. Each one owns a narrow job and a narrow set of
read-only tools; none of them talks to another agent. The supervisor hands out
tasks and the graph collects structured results."""

from __future__ import annotations

import time
from typing import Any

from ..deps import Deps
from ..schemas import AgentResult, ResearchTask
from .attack import AttackAgent
from .evidence_agent import EvidenceAgent
from .threat_actor import ThreatActorAgent
from .vulnerability import VulnerabilityAgent

AGENTS = {
    "threat_actor": ThreatActorAgent,
    "vulnerability": VulnerabilityAgent,
    "attack": AttackAgent,
    "evidence": EvidenceAgent,
}


def execute_task(deps: Deps, task: dict[str, Any], question: str, deadline: float | None = None) -> dict[str, Any]:
    """Run one task and ALWAYS return a valid AgentResult dict (never raises)."""
    try:
        parsed = ResearchTask.model_validate(task)
    except Exception as exc:  # noqa: BLE001 - malformed task from the planner
        return AgentResult(agent_name="unknown", task_id=str(task.get("task_id", "?")), status="failed",
                           errors=[f"malformed task: {exc}"]).model_dump(mode="json")
    if deadline is not None and time.time() > deadline:
        return AgentResult(agent_name=parsed.agent, task_id=parsed.task_id, status="failed", attempt=parsed.attempt,
                           errors=["investigation time budget exhausted before this task started"]).model_dump(mode="json")
    try:
        result = AGENTS[parsed.agent](deps).run(parsed, question)
        return AgentResult.model_validate(result.model_dump()).model_dump(mode="json")
    except Exception as exc:  # noqa: BLE001
        return AgentResult(agent_name=parsed.agent, task_id=parsed.task_id, status="failed", attempt=parsed.attempt,
                           errors=[f"{type(exc).__name__}: {exc}"[:300]]).model_dump(mode="json")
