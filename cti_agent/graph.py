"""Builds the LangGraph workflow.

START -> plan (supervisor) --parallel--> run_agent x N -> collect -> review
  review --(failed / no-match tasks, retries left)--> run_agent ... -> collect -> review
  review -> gate -> [pre_assess hooks] -> assess -> generate -> check_citations
  -> [post_generate hooks] -> finalize -> [post_finalize hooks] -> END
"""

from __future__ import annotations

import uuid
from typing import Any

from langgraph.graph import END, START, StateGraph

from .checkpoint import make_checkpointer
from .deps import Deps, build_default_deps
from .hooks import load_hooks
from .nodes import make_nodes
from .state import AgentState
from .supervisor import fan_out, make_plan_node, route_review


def _checkpointer(deps: Deps):
    if "checkpointer" not in deps.extras:
        saver, note = make_checkpointer(deps.settings)
        deps.extras["checkpointer"], deps.extras["checkpoint_note"] = saver, note
    return deps.extras["checkpointer"]


def build_graph(deps: Deps, hooks: dict[str, list] | None = None, *, interrupt_before: list[str] | None = None):
    hooks = load_hooks() if hooks is None else hooks
    nodes = make_nodes(deps)
    graph = StateGraph(AgentState)
    graph.add_node("plan", make_plan_node(deps))
    for name, fn in nodes.items():
        graph.add_node(name, fn)
    pre = [(n, f(deps)) for n, f in hooks.get("pre_assess", [])]
    post = [(n, f(deps)) for n, f in hooks.get("post_generate", [])]
    fin = [(n, f(deps)) for n, f in hooks.get("post_finalize", [])]
    for name, fn in pre + post + fin:
        graph.add_node(name, fn)

    graph.add_edge(START, "plan")
    graph.add_conditional_edges("plan", fan_out, ["run_agent"])
    graph.add_edge("run_agent", "collect")
    graph.add_edge("collect", "review")
    graph.add_conditional_edges("review", route_review, ["run_agent", "gate"])

    chain = ["gate"] + [n for n, _ in pre] + ["assess", "generate", "check_citations"]
    chain += [n for n, _ in post] + ["finalize"] + [n for n, _ in fin]
    for a, b in zip(chain, chain[1:]):
        graph.add_edge(a, b)
    graph.add_edge(chain[-1], END)
    return graph.compile(checkpointer=_checkpointer(deps), interrupt_before=interrupt_before or None)


def _config(thread_id: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread_id}, "recursion_limit": 100}


def run_question(question: str, deps: Deps | None = None, hooks: dict[str, list] | None = None, *,
                 thread_id: str | None = None, pause_before: list[str] | None = None,
                 conversation_id: str | None = None) -> dict[str, Any]:
    """Run one investigation. With pause_before=["generate"] the run stops there and can be
    continued with resume_investigation(thread_id). Returns the final record."""
    if not question or not question.strip():
        raise ValueError("The question is empty.")
    deps = deps or build_default_deps()
    thread = thread_id or uuid.uuid4().hex
    app = build_graph(deps, hooks, interrupt_before=pause_before)
    initial: dict[str, Any] = {"question": question.strip()}
    if conversation_id:
        initial["conversation_id"] = conversation_id
    result = app.invoke(initial, config=_config(thread))
    return _finish(app, result, thread, question)


def resume_investigation(thread_id: str, deps: Deps, hooks: dict[str, list] | None = None) -> dict[str, Any]:
    """Continue a paused / interrupted investigation from its last checkpoint."""
    if deps.extras.get("checkpointer") is None and _checkpointer(deps) is None:
        raise RuntimeError("Checkpointing is disabled (AGENT_CHECKPOINT=none), so nothing can be resumed.")
    app = build_graph(deps, hooks)
    snapshot = app.get_state(_config(thread_id))
    if not snapshot.values:
        raise KeyError(f"No saved investigation for thread {thread_id!r}")
    result = app.invoke(None, config=_config(thread_id))
    return _finish(app, result, thread_id, snapshot.values.get("question", ""))


def _finish(app, result: dict[str, Any], thread: str, question: str) -> dict[str, Any]:
    final = result.get("final")
    if final is None:
        values = app.get_state(_config(thread)).values
        return {"workflow_status": "paused", "thread_id": thread, "question": question,
                "investigation_id": values.get("investigation_id"), "next": list(app.get_state(_config(thread)).next)}
    final["thread_id"] = thread
    return final
