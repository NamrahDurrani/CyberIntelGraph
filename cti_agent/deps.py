"""Everything the agent nodes need from the outside world, bundled in one place
so tests can swap in fakes for Neo4j, the LLM and the document retriever."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import Settings
from .llm import LLM, build_llm
from .neo4j_client import Neo4jRunner
from .schema_map import Runner, SchemaMap
from .tools.text_tools import TextRetriever, load_retriever


@dataclass
class Deps:
    settings: Settings
    runner: Runner
    schema: SchemaMap
    llm: LLM
    retriever: TextRetriever
    extras: dict[str, Any] = field(default_factory=dict)


def build_default_deps(settings: Settings | None = None, refresh_schema: bool = False) -> Deps:
    settings = settings or Settings.from_env()
    runner = Neo4jRunner.from_settings(settings)
    schema = SchemaMap.load_or_discover(runner, settings.resolve(settings.schema_cache), refresh=refresh_schema)
    retriever = load_retriever(settings.rag_retriever, runner, schema)
    return Deps(settings=settings, runner=runner, schema=schema, llm=build_llm(settings), retriever=retriever)
