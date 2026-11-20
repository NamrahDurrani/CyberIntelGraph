"""The eight repositories (Milestone 12). Field names and rules mirror database/mongodb/schema.py."""
from __future__ import annotations

from typing import Any

from database.mongodb.schema import CLAIM_CLASSES
from database.repositories.base import BaseRepository, DocumentRejected, DuplicateRecord, utcnow


def _check_classes(items: list[dict[str, Any]] | None, what: str) -> None:
    """Fail early, in Python, with a clear message (the server validator is the second line of defence)."""
    for it in items or []:
        if it.get("claim_class") not in CLAIM_CLASSES:
            raise DocumentRejected(f"{what}: claim_class must be one of {CLAIM_CLASSES}, got {it.get('claim_class')!r}")


class UsersRepository(BaseRepository):
    collection_name, id_prefix = "users", "user"

    async def create(self, username: str, *, role: str = "researcher", display_name: str | None = None):
        doc = {"username": username, "role": role, "updated_at": utcnow()}
        if display_name:
            doc["display_name"] = display_name
        return await self.insert(doc)

    async def by_username(self, username: str):
        return await self._run(self.col.find_one({"username": username}))


class ConversationsRepository(BaseRepository):
    collection_name, id_prefix = "conversations", "conv"

    async def create(self, user_id: str, title: str):
        now = utcnow()
        return await self.insert({"user_id": user_id, "title": title, "status": "active", "updated_at": now, "created_at": now})

    async def for_user(self, user_id: str, limit: int = 50):
        return await self._list({"user_id": user_id}, [("updated_at", -1)], limit)

    async def archive(self, conversation_id: str):
        return await self.set_fields(conversation_id, {"status": "archived", "updated_at": utcnow()})


class MessagesRepository(BaseRepository):
    collection_name, id_prefix = "messages", "msg"

    async def append(self, conversation_id: str, role: str, content: str, *, citations: list[dict[str, Any]] | None = None,
                     trace_id: str | None = None, attempts: int = 3):
        """Add the next message. `seq` = last + 1; if two writers collide the unique index refuses the second and we retry."""
        _check_classes(citations, "citation")
        for attempt in range(attempts):
            last = await self._run(self.col.find_one({"conversation_id": conversation_id}, sort=[("seq", -1)]))
            doc: dict[str, Any] = {"conversation_id": conversation_id, "seq": (last["seq"] + 1) if last else 1,
                                   "role": role, "content": content}
            if citations:
                doc["citations"] = citations
            if trace_id:
                doc["trace_id"] = trace_id
            try:
                saved = await self.insert(doc)
            except DuplicateRecord:
                if attempt == attempts - 1:
                    raise
                continue
            await self._run(self.db["conversations"].update_one({"_id": conversation_id},
                                                                {"$set": {"last_message_at": saved["created_at"], "updated_at": saved["created_at"]}}))
            return saved

    async def history(self, conversation_id: str, limit: int = 200):
        return await self._list({"conversation_id": conversation_id}, [("seq", 1)], limit)


class JobsRepository(BaseRepository):
    collection_name, id_prefix = "research_jobs", "job"
    _ALLOWED = {"queued": {"running", "cancelled"}, "running": {"succeeded", "failed", "cancelled"}}

    async def create(self, user_id: str, question: str, conversation_id: str | None = None):
        doc = {"user_id": user_id, "question": question, "status": "queued"}
        if conversation_id:
            doc["conversation_id"] = conversation_id
        return await self.insert(doc)

    async def move_to(self, job_id: str, status: str, *, error: str | None = None, report_id: str | None = None):
        """queued -> running -> succeeded/failed; an invalid jump is refused instead of silently accepted."""
        job = await self.require(job_id)
        if status not in self._ALLOWED.get(job["status"], set()):
            raise DocumentRejected(f"job {job_id}: cannot go from {job['status']!r} to {status!r}")
        fields: dict[str, Any] = {"status": status}
        if status == "running":
            fields["started_at"] = utcnow()
        else:
            fields["finished_at"] = utcnow()
        if error:
            fields["error"] = error[:2000]
        if report_id:
            fields["report_id"] = report_id
        return await self.set_fields(job_id, fields)

    async def by_status(self, status: str, limit: int = 50):
        return await self._list({"status": status}, [("created_at", -1)], limit)


class ReportsRepository(BaseRepository):
    collection_name, id_prefix = "reports", "rep"

    async def save(self, job_id: str, user_id: str, title: str, body_markdown: str, *, claims: list[dict[str, Any]] | None = None,
                   graph_entity_ids: list[str] | None = None, conversation_id: str | None = None, attempts: int = 3):
        """Each save of the same job is a NEW version (version 1, 2, ...); older versions are kept."""
        _check_classes(claims, "claim")
        for attempt in range(attempts):
            last = await self._run(self.col.find_one({"job_id": job_id}, sort=[("version", -1)]))
            doc: dict[str, Any] = {"job_id": job_id, "user_id": user_id, "title": title, "body_markdown": body_markdown,
                                   "version": (last["version"] + 1) if last else 1}
            if claims:
                doc["claims"] = claims
            if graph_entity_ids:
                doc["graph_entity_ids"] = graph_entity_ids
            if conversation_id:
                doc["conversation_id"] = conversation_id
            try:
                return await self.insert(doc)
            except DuplicateRecord:
                if attempt == attempts - 1:
                    raise

    async def latest_for_job(self, job_id: str):
        return await self._run(self.col.find_one({"job_id": job_id}, sort=[("version", -1)]))


class DocumentMetadataRepository(BaseRepository):
    collection_name, id_prefix = "document_metadata", "doc"

    async def register(self, source: str, source_uri: str, content_hash: str, **extra: Any):
        """Record a raw file's identity (hash). The raw file itself is never copied into MongoDB."""
        return await self.insert({"source": source, "source_uri": source_uri, "content_hash": content_hash, **extra})


class FeedbackRepository(BaseRepository):
    collection_name, id_prefix = "feedback", "fb"

    async def add(self, user_id: str, rating: str, *, message_id: str | None = None, report_id: str | None = None, comment: str | None = None):
        doc: dict[str, Any] = {"user_id": user_id, "rating": rating}
        for k, v in (("message_id", message_id), ("report_id", report_id), ("comment", comment)):
            if v:
                doc[k] = v
        return await self.insert(doc)


class TracesRepository(BaseRepository):
    collection_name, id_prefix = "agent_traces", "trace"

    async def record(self, job_id: str, step: int, node: str, status: str, **extra: Any):
        return await self.insert({"job_id": job_id, "step": step, "node": node, "status": status, **extra})

    async def for_job(self, job_id: str, limit: int = 500):
        return await self._list({"job_id": job_id}, [("step", 1)], limit)


class Repositories:
    """All repositories on one database handle: `repos = Repositories(m.db)`."""

    def __init__(self, db):
        self.users = UsersRepository(db)
        self.conversations = ConversationsRepository(db)
        self.messages = MessagesRepository(db)
        self.jobs = JobsRepository(db)
        self.reports = ReportsRepository(db)
        self.documents = DocumentMetadataRepository(db)
        self.feedback = FeedbackRepository(db)
        self.traces = TracesRepository(db)
