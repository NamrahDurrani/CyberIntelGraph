"""Milestone 12 stage 3 tests: schema definition sanity + the setup logic against an in-memory async fake."""
import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pymongo.errors import WriteError                       # noqa: E402

from database.mongodb import setup                          # noqa: E402
from database.mongodb.schema import CLAIM_CLASSES, COLLECTIONS   # noqa: E402

EXPECTED = {"users", "conversations", "messages", "research_jobs", "reports", "document_metadata", "feedback", "agent_traces"}


class Cur:
    def __init__(self, rows):
        self.rows = rows

    async def to_list(self):
        return self.rows


class FakeColl:
    def __init__(self, db, name):
        self.db, self.name = db, name
        self.indexes = {"_id_": {}}
        self.docs = {}

    async def index_information(self):
        return dict(self.indexes)

    async def create_indexes(self, models):
        for m in models:
            self.indexes[m.document["name"]] = m.document

    async def insert_one(self, doc):
        if self.db.enforce and self.name == "users" and not doc.get("username"):
            raise WriteError("Document failed validation", code=121)
        self.docs[doc["_id"]] = doc

    async def delete_one(self, f):
        self.docs.pop(f["_id"], None)


class FakeDb:
    def __init__(self, enforce=True):
        self.enforce, self.colls, self.opts, self.cmds = enforce, {}, {}, []

    def __getitem__(self, n):
        return self.colls[n]

    async def list_collection_names(self):
        return list(self.colls)

    async def list_collections(self, filter=None):
        n = filter["name"]
        return Cur([{"name": n, "options": self.opts[n]}] if n in self.opts else [])

    async def create_collection(self, name, **opts):
        self.colls[name] = FakeColl(self, name)
        self.opts[name] = opts

    async def command(self, cmd, name, **opts):
        self.cmds.append((cmd, name)); self.opts[name] = opts


class SchemaDefinitionTests(unittest.TestCase):
    def test_exactly_the_roadmap_collections(self):
        self.assertEqual(set(COLLECTIONS), EXPECTED)

    def test_every_collection_has_a_validator_with_required_fields_and_indexes(self):
        for name, spec in COLLECTIONS.items():
            js = spec["validator"]["$jsonSchema"]
            self.assertTrue({"_id", "created_at", "schema_version"} <= set(js["required"]), name)
            self.assertTrue(set(js["required"]) <= set(js["properties"]), f"{name}: required field without a definition")
            self.assertTrue(spec["indexes"], name)

    def test_index_names_are_unique_and_fields_exist_in_schema(self):
        names = []
        for name, spec in COLLECTIONS.items():
            props = spec["validator"]["$jsonSchema"]["properties"]
            for iname, keys, _ in spec["indexes"]:
                names.append(iname)
                for f, direction in keys:
                    self.assertIn(f, props, f"{iname}: {f}")
                    self.assertIn(direction, (1, -1))
        self.assertEqual(len(names), len(set(names)))

    def test_evidence_classes_match_milestone_11(self):
        self.assertEqual(CLAIM_CLASSES[:3], ["documented", "inferred", "candidate"])

    def test_the_graph_is_referenced_not_copied(self):
        reports = COLLECTIONS["reports"]["validator"]["$jsonSchema"]["properties"]
        self.assertIn("graph_entity_ids", reports)
        self.assertNotIn("nodes", reports)
        self.assertNotIn("relationships", reports)


class SetupTests(unittest.TestCase):
    def test_apply_creates_everything_and_is_idempotent(self):
        db = FakeDb()
        first = asyncio.run(setup.apply(db))
        self.assertEqual(sum(l.startswith("created collection") for l in first), 8)
        self.assertTrue(all(r["exists"] and r["validator_current"] and not r["missing_indexes"] for r in asyncio.run(setup.plan(db))))
        self.assertEqual(asyncio.run(setup.apply(db)), [])             # second run: nothing to do
        self.assertEqual(db.cmds, [])

    def test_plan_is_read_only(self):
        db = FakeDb()
        rows = asyncio.run(setup.plan(db))
        self.assertEqual(db.colls, {})
        self.assertTrue(all(not r["exists"] for r in rows))

    def test_changed_validator_is_refreshed_with_collmod_not_recreated(self):
        db = FakeDb()
        asyncio.run(setup.apply(db))
        db.opts["users"] = {"validator": {"old": 1}, "validationAction": "error"}
        log = asyncio.run(setup.apply(db))
        self.assertEqual(log, ["updated validator on users"])
        self.assertEqual(db.cmds, [("collMod", "users")])

    def test_probe_detects_enforced_and_unenforced_validators(self):
        db = FakeDb(enforce=True); asyncio.run(setup.apply(db))
        self.assertTrue(asyncio.run(setup.validator_rejects_bad_document(db)))
        db = FakeDb(enforce=False); asyncio.run(setup.apply(db))
        self.assertFalse(asyncio.run(setup.validator_rejects_bad_document(db)))
        self.assertEqual(db["users"].docs, {})                          # a wrongly accepted probe is cleaned up


if __name__ == "__main__":
    unittest.main()
