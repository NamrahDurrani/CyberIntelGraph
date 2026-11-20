"""Shared plumbing for the repositories.

Honesty rules (project principle: a failed query is NEVER evidence that a record does not exist):
  * `get()` returns None ONLY when MongoDB answered and nothing matched.
  * any connection / server error raises MongoUnavailable instead.
  * the validator's refusal (error 121) becomes DocumentRejected; a unique-index clash becomes DuplicateRecord.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pymongo.errors import DuplicateKeyError, PyMongoError, WriteError

from database.mongodb.client import MongoUnavailable
from database.mongodb.schema import SCHEMA_VERSION


class NotFound(Exception):
    """`require()` found no such record (the database answered normally)."""


class DocumentRejected(Exception):
    """MongoDB's validator refused the document (wrong type, missing field or value not allowed)."""


class DuplicateRecord(Exception):
    """A unique index already has this value."""


def utcnow() -> datetime:
    """Timezone-aware UTC, rounded to milliseconds (MongoDB stores milliseconds; this keeps round-trips equal)."""
    n = datetime.now(timezone.utc)
    return n.replace(microsecond=(n.microsecond // 1000) * 1000)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class BaseRepository:
    collection_name: str = ""
    id_prefix: str = "doc"

    def __init__(self, db):
        self.db = db
        self.col = db[self.collection_name]

    # ---- error translation ----------------------------------------------------------------------
    @staticmethod
    def _translate(e: Exception) -> Exception:
        if isinstance(e, DuplicateKeyError):
            return DuplicateRecord(str(e)[:200])
        if isinstance(e, WriteError) and e.code == 121:
            detail = str(getattr(e, "details", "") or "")[:400]
            return DocumentRejected("MongoDB validator refused the document" + (f": {detail}" if detail else ""))
        return MongoUnavailable(f"{type(e).__name__}: {str(e)[:300]}")

    async def _run(self, coro):
        try:
            return await coro
        except PyMongoError as e:
            raise self._translate(e) from None

    # ---- generic operations --------------------------------------------------------------------------
    def _stamp(self, doc: dict[str, Any]) -> dict[str, Any]:
        out = dict(doc)
        out.setdefault("_id", new_id(self.id_prefix))
        out.setdefault("created_at", utcnow())
        out.setdefault("schema_version", SCHEMA_VERSION)
        return out

    async def insert(self, doc: dict[str, Any]) -> dict[str, Any]:
        full = self._stamp(doc)
        await self._run(self.col.insert_one(full))
        return full

    async def get(self, _id: str) -> dict[str, Any] | None:
        return await self._run(self.col.find_one({"_id": _id}))

    async def require(self, _id: str) -> dict[str, Any]:
        doc = await self.get(_id)
        if doc is None:
            raise NotFound(f"{self.collection_name}/{_id}")
        return doc

    async def set_fields(self, _id: str, fields: dict[str, Any]) -> dict[str, Any]:
        res = await self._run(self.col.update_one({"_id": _id}, {"$set": fields}))
        if res.matched_count == 0:
            raise NotFound(f"{self.collection_name}/{_id}")
        return await self.require(_id)

    async def delete(self, _id: str) -> bool:
        res = await self._run(self.col.delete_one({"_id": _id}))
        return res.deleted_count == 1

    async def _list(self, flt: dict[str, Any], sort: list[tuple[str, int]], limit: int) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        return await self._run(self.col.find(flt).sort(sort).limit(limit).to_list())
