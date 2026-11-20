"""Async MongoDB client (official PyMongo async API).

A failed connection or query is an ERROR, never "the record does not exist": every failure is raised as
`MongoUnavailable`; only a successful query that returns nothing means "not found".
"""
from __future__ import annotations

from typing import Any

from database.mongodb.settings import MongoSettings, redact


class MongoUnavailable(Exception):
    """MongoDB could not be reached or answered with an error (details never include the password)."""


def _scrub(text: str, settings: MongoSettings) -> str:
    return text.replace(settings.uri, settings.redacted())


class MongoClientFactory:
    """Owns one AsyncMongoClient. Use as `async with MongoClientFactory(settings) as m:` then `m.db`."""

    def __init__(self, settings: MongoSettings):
        self.settings = settings
        self._client: Any = None

    def _client_kwargs(self) -> dict[str, Any]:
        kw: dict[str, Any] = dict(
            appname=self.settings.app_name,
            serverSelectionTimeoutMS=self.settings.server_selection_timeout_ms,
            connectTimeoutMS=self.settings.connect_timeout_ms,
            retryWrites=True,
            tz_aware=True,                           # datetimes come back timezone-aware (UTC)
        )
        ca = self.settings.ca_file
        if not ca:                                    # same lesson as Neo4j on Windows: give TLS a known CA bundle
            try:
                import certifi
                ca = certifi.where()
            except ImportError:
                ca = None
        if ca:
            kw["tlsCAFile"] = ca
        return kw

    async def connect(self) -> "MongoClientFactory":
        from pymongo import AsyncMongoClient
        from pymongo.errors import PyMongoError
        try:
            self._client = AsyncMongoClient(self.settings.uri, **self._client_kwargs())
            await self._client.admin.command("ping")
        except PyMongoError as e:
            await self.close()
            raise MongoUnavailable(f"cannot reach MongoDB at {self.settings.redacted()}: "
                                   f"{type(e).__name__}: {_scrub(str(e), self.settings)[:300]}") from None
        return self

    @property
    def db(self):
        if self._client is None:
            raise MongoUnavailable("not connected: call connect() first")
        return self._client[self.settings.database]

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> "MongoClientFactory":
        return await self.connect()

    async def __aexit__(self, *exc) -> None:
        await self.close()


__all__ = ["MongoClientFactory", "MongoUnavailable", "redact"]
