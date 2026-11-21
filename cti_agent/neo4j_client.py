"""Thin read-only Neo4j wrapper. Every query runs inside a READ transaction,
so the server itself rejects writes: the agent can never modify the graph."""

from __future__ import annotations

from typing import Any

from .config import Settings


class Neo4jConnectionError(RuntimeError):
    pass


class Neo4jRunner:
    def __init__(self, uri: str, user: str, password: str, database: str | None = None):
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise Neo4jConnectionError("The 'neo4j' package is not installed in this venv.") from exc
        self._database = database or None
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    @classmethod
    def from_settings(cls, settings: Settings) -> "Neo4jRunner":
        missing = settings.missing_neo4j()
        if missing:
            raise Neo4jConnectionError("Missing in .env: " + ", ".join(missing))
        return cls(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password, settings.neo4j_database)

    def __call__(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        def work(tx):
            return [record.data() for record in tx.run(cypher, params or {})]

        kwargs = {"database": self._database} if self._database else {}
        with self._driver.session(**kwargs) as session:
            return session.execute_read(work)

    def verify(self) -> None:
        self._driver.verify_connectivity()

    def close(self) -> None:
        self._driver.close()
