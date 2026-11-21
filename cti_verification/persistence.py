"""MongoDB persistence of finished investigations ('post_finalize' hook).

IMPORTANT - why new collections: the Milestone 12 repositories use server-side schema
validators for users / conversations / messages / jobs / reports. This module could not see
those repositories, so it writes to its OWN collections (investigation_runs,
investigation_traces) instead of risking rejected documents. Milestone 15 can move the data
into the validated `reports` / `agent_traces` repositories once their interfaces are wired in.

Rules: the JSON file copy already exists before this runs, so a database problem can never
lose a result; failures are reported in final["persistence"], never raised; the knowledge
graph is not copied (claims and evidence keep ids, summaries, sources and short excerpts only);
credentials are never written."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable

from cti_agent.deps import Deps

from .settings import VerifySettings

MAX_EXCERPT = 1000
SECRET_PATTERNS = [re.compile(r"mongodb(\+srv)?://[^\s\"']+", re.IGNORECASE), re.compile(r"gsk_[A-Za-z0-9]{10,}"),
                   re.compile(r"(?i)(api[_-]?key|password|secret)\s*[=:]\s*\S+")]


def scrub(value: Any) -> Any:
    """Remove anything that looks like a credential from strings, recursively."""
    if isinstance(value, str):
        for pattern in SECRET_PATTERNS:
            value = pattern.sub("[redacted]", value)
        return value
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value


def build_documents(final: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    now = datetime.now(timezone.utc).isoformat()
    evidence = [{**e, "text": (e.get("text") or "")[:MAX_EXCERPT]} for e in final.get("evidence", [])]
    run = scrub({
        "investigation_id": final["investigation_id"], "thread_id": final.get("thread_id"),
        "conversation_id": final.get("conversation_id"), "question": final["question"],
        "workflow_status": final["workflow_status"], "created_at": final.get("created_at"),
        "finished_at": final.get("finished_at"), "persisted_at": now, "scope": final.get("scope"),
        "plan": final.get("plan"), "selected_agents": final.get("selected_agents"), "answer": final["answer"],
        "entities": final.get("entities"), "unresolved": final.get("unresolved"), "claims": final.get("claims"),
        "evidence": evidence, "evidence_counts": final.get("evidence_counts"),
        "citations_used": final.get("citations_used"), "limitations": final.get("limitations"),
        "warnings": final.get("warnings"), "verification": final.get("verification"), "fresh": final.get("fresh"),
        "report_version": 1,
    })
    traces = [scrub({
        "investigation_id": final["investigation_id"], "agent_name": a["agent_name"], "task_id": a["task_id"],
        "attempt": a["attempt"], "status": a["status"], "summary": a["summary"], "duration_ms": a["duration_ms"],
        "tool_calls": a["tool_calls"], "errors": a["errors"], "limitations": a["limitations"], "persisted_at": now,
    }) for a in final.get("agents", [])]
    return run, traces


class MongoInvestigationStore:
    def __init__(self, db: Any, settings: VerifySettings):
        self.db, self.s = db, settings

    def save(self, final: dict[str, Any]) -> dict[str, Any]:
        run, traces = build_documents(final)
        runs, trace_col = self.db[self.s.runs_collection], self.db[self.s.traces_collection]
        try:
            runs.create_index("investigation_id", unique=True)
            trace_col.create_index([("investigation_id", 1), ("task_id", 1), ("attempt", 1)], unique=True)
        except Exception:  # noqa: BLE001 - index creation is best effort
            pass
        runs.update_one({"investigation_id": run["investigation_id"]}, {"$set": run}, upsert=True)   # idempotent
        for t in traces:
            trace_col.update_one({"investigation_id": t["investigation_id"], "task_id": t["task_id"],
                                  "attempt": t["attempt"]}, {"$set": t}, upsert=True)
        return {"mongo": "saved", "runs": self.s.runs_collection, "traces": len(traces)}

    def get(self, investigation_id: str) -> dict[str, Any] | None:
        doc = self.db[self.s.runs_collection].find_one({"investigation_id": investigation_id}, {"_id": 0})
        return doc

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        cur = self.db[self.s.runs_collection].find({}, {"_id": 0, "investigation_id": 1, "question": 1,
                                                        "workflow_status": 1, "created_at": 1}).sort("created_at", -1).limit(limit)
        return list(cur)

    def traces(self, investigation_id: str) -> list[dict[str, Any]]:
        return list(self.db[self.s.traces_collection].find({"investigation_id": investigation_id}, {"_id": 0}))


def connect_db(deps: Deps, vs: VerifySettings) -> Any | None:
    """Injected test database, or a real MongoClient from the .env URI."""
    if deps.extras.get("mongo_db") is not None:
        return deps.extras["mongo_db"]
    if not deps.settings.mongo_uri:
        return None
    from pymongo import MongoClient

    client = MongoClient(deps.settings.mongo_uri, serverSelectionTimeoutMS=8000)
    client.admin.command("ping")
    deps.extras["_mongo_client"] = client
    return client[deps.settings.mongo_database]


def make_persist_node(deps: Deps) -> Callable[[dict], dict]:
    vs: VerifySettings = deps.extras.get("verify_settings") or VerifySettings.from_env()

    def persist(state: dict) -> dict:
        final = dict(state["final"])
        if not vs.persist_mongo:
            final["persistence"] = {"mongo": "skipped (PERSIST_MONGO=false)"}
        else:
            try:
                db = connect_db(deps, vs)
                if db is None:
                    final["persistence"] = {"mongo": "skipped (no MongoDB URI in .env)"}
                else:
                    final["persistence"] = MongoInvestigationStore(db, vs).save(final)
            except Exception as exc:  # noqa: BLE001
                final["persistence"] = {"mongo": f"FAILED: {type(exc).__name__}: {str(exc)[:160]}"}
                final["warnings"] = list(final.get("warnings", [])) + [
                    "The investigation was NOT saved to MongoDB (the JSON file copy exists)."]
        return {"final": final}

    return persist
