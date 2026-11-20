"""Milestone 12 stage 2 tests: settings, secret redaction, failure handling. No server needed."""
import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from database.mongodb import settings as S                                   # noqa: E402
from database.mongodb.client import MongoClientFactory, MongoUnavailable   # noqa: E402

URI = "mongodb+srv://appuser:S3cret!pw@cluster0.abcde.mongodb.net/?retryWrites=true"


def env(**kw):
    return mock.patch.dict(os.environ, kw, clear=True)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(S, "_load_dotenv", lambda: None); p.start(); self.addCleanup(p.stop)

    def test_reads_uri_and_db(self):
        with env(MONGODB_URI=URI, MONGODB_DB="cyberintel"):
            s = S.MongoSettings.from_env()
        self.assertEqual(s.database, "cyberintel")

    def test_default_database_name(self):
        with env(MONGODB_URI=URI):
            self.assertEqual(S.MongoSettings.from_env().database, "cyberintelgraph")

    def test_missing_uri_and_bad_values_are_explained(self):
        for e in ({}, {"MONGODB_URI": "http://x"}, {"MONGODB_URI": "mongodb+srv://u:<db_password>@h/"},
                  {"MONGODB_URI": URI, "MONGODB_DB": "bad.name"}, {"MONGODB_URI": URI, "MONGODB_DB": "a b"}):
            with env(**e), self.assertRaises(S.MongoConfigError):
                S.MongoSettings.from_env()

    def test_password_never_appears_in_redacted_repr_or_errors(self):
        s = S.MongoSettings(URI)
        for text in (s.redacted(), repr(s), str(s)):
            self.assertNotIn("S3cret", text)
        self.assertEqual(s.redacted(), "mongodb+srv://appuser:***@cluster0.abcde.mongodb.net")
        with env(MONGODB_URI="mongodb+srv://u:S3cret@h/", MONGODB_DB="bad.name"), self.assertRaises(S.MongoConfigError) as cm:
            S.MongoSettings.from_env()
        self.assertNotIn("S3cret", str(cm.exception))


class ClientTests(unittest.TestCase):
    def test_failure_is_raised_as_unavailable_without_the_password(self):
        from pymongo.errors import ServerSelectionTimeoutError

        class Boom:
            def __init__(self, *a, **k):
                self.admin = self

            async def command(self, *a, **k):
                raise ServerSelectionTimeoutError(f"timed out connecting to {URI}")

            async def close(self):
                pass
        with mock.patch("pymongo.AsyncMongoClient", Boom):
            with self.assertRaises(MongoUnavailable) as cm:
                asyncio.run(MongoClientFactory(S.MongoSettings(URI)).connect())
        self.assertNotIn("S3cret", str(cm.exception))
        self.assertIn("appuser:***@", str(cm.exception))

    def test_db_before_connect_is_an_error_not_an_empty_result(self):
        with self.assertRaises(MongoUnavailable):
            MongoClientFactory(S.MongoSettings(URI)).db

    def test_client_options_include_timeouts_utc_and_ca_bundle(self):
        kw = MongoClientFactory(S.MongoSettings(URI))._client_kwargs()
        self.assertEqual(kw["serverSelectionTimeoutMS"], 10_000)
        self.assertTrue(kw["tz_aware"])
        self.assertIn("tlsCAFile", kw)

    def test_success_path_pings_and_closes(self):
        calls = []

        class Ok:
            def __init__(self, *a, **k):
                self.admin = self

            async def command(self, name, *a, **k):
                calls.append(name)

            def __getitem__(self, n):
                return n

            async def close(self):
                calls.append("close")

        async def go():
            async with MongoClientFactory(S.MongoSettings(URI, database="cyberintel")) as m:
                return m.db
        with mock.patch("pymongo.AsyncMongoClient", Ok):
            self.assertEqual(asyncio.run(go()), "cyberintel")
        self.assertEqual(calls, ["ping", "close"])


if __name__ == "__main__":
    unittest.main()
