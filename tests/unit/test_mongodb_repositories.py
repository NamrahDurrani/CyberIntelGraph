"""Milestone 12 stage 4 tests: repositories against an in-memory async fake (no server needed).
The live proof is scripts/check_mongodb_roundtrip.py on your Atlas cluster."""
import asyncio
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pymongo.errors import DuplicateKeyError, ServerSelectionTimeoutError, WriteError   # noqa: E402

from database.mongodb.client import MongoUnavailable                                       # noqa: E402
from database.repositories import (DocumentRejected, DuplicateRecord, NotFound, Repositories)   # noqa: E402

UNIQUE = {"users": [("username",)], "messages": [("conversation_id", "seq")], "reports": [("job_id", "version")]}


class Res:
    def __init__(self, matched=0, deleted=0):
        self.matched_count, self.deleted_count = matched, deleted


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    def sort(self, spec):
        for k, d in reversed(spec):
            self.rows.sort(key=lambda r: r.get(k), reverse=(d == -1))
        return self

    def limit(self, n):
        self.rows = self.rows[:n]
        return self

    async def to_list(self):
        return [copy.deepcopy(r) for r in self.rows]


class FakeCol:
    def __init__(self, name):
        self.name, self.docs, self.fail = name, {}, None

    def _match(self, flt):
        return [d for d in self.docs.values() if all(d.get(k) == v for k, v in flt.items())]

    async def insert_one(self, doc):
        if self.fail:
            raise self.fail
        if self.name == "users" and (not doc.get("username") or doc.get("role") not in ("researcher", "admin")):
            raise WriteError("Document failed validation", code=121, details={"x": 1})
        if doc["_id"] in self.docs:
            raise DuplicateKeyError("dup _id")
        for fields in UNIQUE.get(self.name, []):
            if any(all(d.get(f) == doc.get(f) for f in fields) for d in self.docs.values()):
                raise DuplicateKeyError("dup " + ",".join(fields))
        self.docs[doc["_id"]] = copy.deepcopy(doc)

    async def find_one(self, flt, sort=None):
        if self.fail:
            raise self.fail
        rows = self._match(flt)
        if sort:
            for k, d in reversed(sort):
                rows.sort(key=lambda r: r.get(k), reverse=(d == -1))
        return copy.deepcopy(rows[0]) if rows else None

    def find(self, flt):
        return Cursor(self._match(flt))

    async def update_one(self, flt, upd):
        rows = self._match(flt)
        for r in rows[:1]:
            r.update(upd["$set"])
        return Res(matched=len(rows[:1]))

    async def delete_one(self, flt):
        rows = self._match(flt)
        for r in rows[:1]:
            del self.docs[r["_id"]]
        return Res(deleted=len(rows[:1]))


class FakeDb:
    def __init__(self):
        self.cols = {}

    def __getitem__(self, n):
        return self.cols.setdefault(n, FakeCol(n))


def run(c):
    return asyncio.run(c)


class RepoTests(unittest.TestCase):
    def setUp(self):
        self.db = FakeDb()
        self.r = Repositories(self.db)

    def test_insert_stamps_id_created_at_utc_ms_and_schema_version(self):
        u = run(self.r.users.create("ana"))
        self.assertTrue(u["_id"].startswith("user_"))
        self.assertEqual(u["schema_version"], 1)
        self.assertEqual(u["created_at"].microsecond % 1000, 0)
        self.assertEqual(u["created_at"].utcoffset().total_seconds(), 0)

    def test_get_unknown_is_none_but_require_raises_notfound(self):
        self.assertIsNone(run(self.r.reports.get("nope")))
        with self.assertRaises(NotFound):
            run(self.r.reports.require("nope"))

    def test_database_error_is_never_reported_as_not_found(self):
        self.db["reports"].fail = ServerSelectionTimeoutError("down")
        with self.assertRaises(MongoUnavailable):
            run(self.r.reports.get("x"))
        with self.assertRaises(MongoUnavailable):
            run(self.r.reports.latest_for_job("j"))

    def test_validator_and_duplicates_are_translated(self):
        with self.assertRaises(DocumentRejected):
            run(self.r.users.insert({"username": "", "role": "root"}))
        run(self.r.users.create("ana"))
        with self.assertRaises(DuplicateRecord):
            run(self.r.users.create("ana"))

    def test_messages_get_increasing_seq_and_touch_the_conversation(self):
        u = run(self.r.users.create("ana")); c = run(self.r.conversations.create(u["_id"], "t"))
        m1 = run(self.r.messages.append(c["_id"], "user", "hi"))
        m2 = run(self.r.messages.append(c["_id"], "assistant", "yo", citations=[{"entity_id": "X:1", "claim_class": "inferred"}]))
        self.assertEqual((m1["seq"], m2["seq"]), (1, 2))
        self.assertEqual([m["seq"] for m in run(self.r.messages.history(c["_id"]))], [1, 2])
        self.assertEqual(run(self.r.conversations.get(c["_id"]))["last_message_at"], m2["created_at"])

    def test_seq_collision_is_retried(self):
        col = self.db["messages"]; real = col.find_one; state = {"n": 0}

        async def stale_once(flt, sort=None):               # first read is stale -> proposes seq 1 again -> unique index refuses
            state["n"] += 1
            return None if state["n"] == 1 else await real(flt, sort)
        run(self.r.messages.append("c1", "user", "first"))
        col.find_one = stale_once
        m = run(self.r.messages.append("c1", "user", "second"))
        self.assertEqual(m["seq"], 2)

    def test_bad_evidence_class_is_refused_before_the_database(self):
        with self.assertRaises(DocumentRejected):
            run(self.r.messages.append("c", "assistant", "x", citations=[{"entity_id": "a", "claim_class": "certain"}]))
        with self.assertRaises(DocumentRejected):
            run(self.r.reports.save("j", "u", "t", "b", claims=[{"text": "t", "claim_class": "sure"}]))
        self.assertEqual(self.db["reports"].docs, {})

    def test_report_versions_increase_and_old_ones_are_kept(self):
        a = run(self.r.reports.save("j1", "u", "t", "b", claims=[{"text": "t", "claim_class": "documented"}], graph_entity_ids=["E:1"]))
        b = run(self.r.reports.save("j1", "u", "t2", "b2"))
        self.assertEqual((a["version"], b["version"]), (1, 2))
        self.assertEqual(run(self.r.reports.get(a["_id"])), a)
        self.assertEqual(run(self.r.reports.latest_for_job("j1"))["_id"], b["_id"])

    def test_job_transitions(self):
        j = run(self.r.jobs.create("u", "q"))
        run(self.r.jobs.move_to(j["_id"], "running"))
        done = run(self.r.jobs.move_to(j["_id"], "failed", error="x" * 5000))
        self.assertEqual(len(done["error"]), 2000)
        for bad in ("running", "queued"):
            with self.assertRaises(DocumentRejected):
                run(self.r.jobs.move_to(j["_id"], bad))
        with self.assertRaises(NotFound):
            run(self.r.jobs.move_to("job_missing", "running"))

    def test_list_limit_is_capped_and_sorted_newest_first(self):
        u = run(self.r.users.create("ana"))
        ids = [run(self.r.conversations.create(u["_id"], f"t{i}"))["_id"] for i in range(3)]
        got = run(self.r.conversations.for_user(u["_id"], limit=2))
        self.assertEqual(len(got), 2)
        self.assertGreaterEqual(got[0]["updated_at"], got[1]["updated_at"])
        self.assertEqual(len(run(self.r.conversations.for_user(u["_id"], limit=10**9))), 3)
        self.assertEqual(len(ids), 3)

    def test_feedback_traces_documents(self):
        fb = run(self.r.feedback.add("u", "up", message_id="m1", comment="good"))
        self.assertEqual(run(self.r.feedback.get(fb["_id"])), fb)
        for i in (2, 1):
            run(self.r.traces.record("j", i, "supervisor", "ok", duration_ms=5))
        self.assertEqual([t["step"] for t in run(self.r.traces.for_job("j"))], [1, 2])
        d = run(self.r.documents.register("cisa_kev", "https://example.org/kev.json", "a" * 64, record_count=10))
        self.assertEqual(run(self.r.documents.get(d["_id"])), d)


if __name__ == "__main__":
    unittest.main()
