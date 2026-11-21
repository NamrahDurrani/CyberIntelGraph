"""LangGraph checkpointing: saves the workflow state after every step so a
paused or interrupted investigation can be resumed with the same thread id.

  AGENT_CHECKPOINT=memory   (default) in-process only - survives pauses, not a restart
  AGENT_CHECKPOINT=none     no checkpointing
  AGENT_CHECKPOINT=mongo    MongoDB (needs: pip install langgraph-checkpoint-mongodb).
                            If the package is missing or the connection fails, the agent
                            falls back to 'memory' and says so.
Application data (reports, traces) is separate from checkpoint storage."""

from __future__ import annotations

from typing import Any

from .config import Settings


def make_checkpointer(settings: Settings) -> tuple[Any | None, str]:
    kind = (settings.checkpoint or "memory").strip().lower()
    if kind in ("none", "off", "false", "0"):
        return None, "checkpointing disabled"
    if kind == "mongo":
        try:
            from langgraph.checkpoint.mongodb import MongoDBSaver  # type: ignore
            from pymongo import MongoClient

            if not settings.mongo_uri:
                raise RuntimeError("no MongoDB URI in .env")
            client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
            client.admin.command("ping")
            return MongoDBSaver(client, db_name=settings.mongo_database), "mongo checkpointer"
        except Exception as exc:  # noqa: BLE001 - fall back, but be explicit
            note = f"mongo checkpointer unavailable ({type(exc).__name__}: {str(exc)[:120]}); using in-memory checkpointing"
            from langgraph.checkpoint.memory import MemorySaver

            return MemorySaver(), note
    from langgraph.checkpoint.memory import MemorySaver

    return MemorySaver(), "memory checkpointer"
