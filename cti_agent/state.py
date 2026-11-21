"""Shared investigation state. LangGraph passes this dictionary between steps.

Fields written by parallel agents (agent_results) or by several steps (trace,
warnings) use an append reducer so results can never overwrite each other.
Everything is plain JSON so checkpoints can be saved and resumed."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class AgentState(TypedDict, total=False):
    # request
    investigation_id: str
    conversation_id: str
    question: str
    created_at: str
    updated_at: str
    deadline_ts: float
    # supervisor
    investigation_scope: dict[str, Any]
    investigation_plan: list[dict[str, Any]]
    research_tasks: list[dict[str, Any]]
    selected_agents: list[str]
    identifiers: dict[str, list[str]]
    terms: list[str]
    intent: str
    # parallel work (append-only)
    agent_results: Annotated[list[dict[str, Any]], operator.add]
    trace: Annotated[list[str], operator.add]
    warnings: Annotated[list[str], operator.add]
    # collected / assessed
    task_attempts: dict[str, int]
    retry_tasks: list[dict[str, Any]]
    retrieved_entities: list[dict[str, Any]]
    resolved: list[dict[str, Any]]
    unresolved: list[str]
    evidence: list[dict[str, Any]]
    claims: list[dict[str, Any]]
    evidence_summary: dict[str, int]
    limitations: list[str]
    errors: list[dict[str, str]]
    # outputs
    answer: str
    citations_used: list[str]
    invalid_citations: list[str]
    workflow_status: str
    verification: dict[str, Any]     # Milestone 14
    fresh: dict[str, Any]            # Milestone 14
    final: dict[str, Any]
