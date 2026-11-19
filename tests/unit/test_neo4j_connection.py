"""Milestone 11.1 regression tests: the three failures seen on the first real run against Aura.

1. `TypeError: Query object is only supported for session.run`   (Query object passed to tx.run)
2. `Unable to retrieve routing information` / `SessionExpired`    (single connection attempt, no fallback / retry)
3. `UnboundLocalError: 'rep'` in scripts/check_neo4j_retrieval.py (crash hid the real error)

No server needed: the doubles below behave like the real driver where it matters.
"""
import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

try:
    import neo4j
    from neo4j.exceptions import ServiceUnavailable, SessionExpired
except ImportError:                                                            # pragma: no cover
    neo4j = None

from neo4j_engine.connection.client import Neo4jClient, Neo4jSettings          # noqa: E402

SETTINGS = Neo4jSettings("neo4j+s://abc.databases.neo4j.io", "neo4j", "secret-pw", "neo4j", None)


class Rec:
    def __init__(self, d):
        self._d = d

    def data(self):
        return self._d


class StrictTx:
    """Like the real driver: tx.run() refuses a Query object (only session.run accepts one)."""
    def __init__(self):
        self.seen = []

    def run(self, query, parameters=None, **kw):
        if neo4j is not None and isinstance(query, neo4j.Query):
            raise TypeError("Query object is only supported for session.run")
        self.seen.append((query, parameters, kw))
        return [Rec({"n": 1})]


class FakeSession:
    def __init__(self, fail_times=0, exc=None, tx=None):
        self.fail_times, self.exc, self.tx = fail_times, exc, tx or StrictTx()
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_read(self, work):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc("simulated")
        self.timeout = getattr(work, "timeout", None)            # set by neo4j.unit_of_work
        return work(self.tx)


class FakeDriver:
    def __init__(self, session):
        self._s = session
        self.closed = False

    def session(self, **kw):
        return self._s

    def verify_connectivity(self):
        pass

    def close(self):
        self.closed = True


def reconnect(client, session):
    """Stand-in for connect(): like the real one it installs a fresh driver."""
    client._driver = FakeDriver(session)
    return client


def connected_client(session):
    c = Neo4jClient(SETTINGS, timeout=12.0, retry_delay=0)
    c._driver = FakeDriver(session)
    return c


@unittest.skipIf(neo4j is None, "neo4j driver not installed")
class RunReadTests(unittest.TestCase):
    def test_query_object_is_not_passed_to_tx_run(self):                       # failure 1
        s = FakeSession()
        rows = connected_client(s).run_read("MATCH (n) RETURN count(n) AS n", {"id": "x"})
        self.assertEqual(rows, [{"n": 1}])
        text, params, _ = s.tx.seen[0]
        self.assertIsInstance(text, str)
        self.assertEqual(params, {"id": "x"})

    def test_timeout_is_still_applied_server_side(self):
        s = FakeSession()
        connected_client(s).run_read("MATCH (n) RETURN n LIMIT 1")
        self.assertEqual(s.timeout, 12.0)

    def test_transient_connection_errors_are_retried(self):                    # failure 2
        s = FakeSession(fail_times=2, exc=SessionExpired)
        c = connected_client(s)
        with mock.patch.object(Neo4jClient, "connect", lambda self: reconnect(self, s)):
            self.assertEqual(c.run_read("MATCH (n) RETURN n LIMIT 1"), [{"n": 1}])
        self.assertEqual(s.calls, 3)

    def test_persistent_connection_error_is_raised_after_retries(self):
        s = FakeSession(fail_times=99, exc=ServiceUnavailable)
        c = connected_client(s)
        with mock.patch.object(Neo4jClient, "connect", lambda self: reconnect(self, s)):
            with self.assertRaises(ServiceUnavailable):
                c.run_read("MATCH (n) RETURN n LIMIT 1")
        self.assertEqual(s.calls, c.retries)

    def test_write_query_still_refused_before_any_network(self):
        from neo4j_engine.connection.client import ReadOnlyViolation
        with self.assertRaises(ReadOnlyViolation):
            connected_client(FakeSession()).run_read("MATCH (n) DETACH DELETE n")


@unittest.skipIf(neo4j is None, "neo4j driver not installed")
class ConnectTests(unittest.TestCase):
    def _driver_factory(self, outcomes):
        """outcomes: list of exception-or-None per attempt; records the (uri, kwargs) tried."""
        tried = []

        def factory(uri, **kw):
            tried.append((uri, kw))
            outcome = outcomes[len(tried) - 1]

            class D(FakeDriver):
                def verify_connectivity(self_inner):
                    if outcome:
                        raise outcome
            return D(FakeSession())
        return factory, tried

    def test_falls_back_to_certifi_bundle_when_system_store_fails(self):       # failure 2 (no NEO4J_CA_BUNDLE set)
        factory, tried = self._driver_factory([ServiceUnavailable("Unable to retrieve routing information"), None])
        with mock.patch.object(neo4j.GraphDatabase, "driver", side_effect=factory):
            c = Neo4jClient(SETTINGS).connect()
        self.assertEqual(c.connected_via, "the certifi CA bundle")
        self.assertEqual(tried[0][0], "neo4j+s://abc.databases.neo4j.io")      # first try: system store, scheme untouched
        self.assertEqual(tried[1][0], "neo4j://abc.databases.neo4j.io")        # second: explicit trust store (+s not allowed with it)
        self.assertTrue(tried[1][1]["encrypted"])
        for _, kw in tried:                                                     # same timeouts as the Milestone 10 sync
            self.assertEqual(kw["connection_timeout"], 15)

    def test_last_resort_is_direct_bolt_without_routing(self):
        factory, tried = self._driver_factory([ServiceUnavailable("routing"), ServiceUnavailable("routing"), None])
        with mock.patch.object(neo4j.GraphDatabase, "driver", side_effect=factory):
            c = Neo4jClient(SETTINGS).connect()
        self.assertEqual(c.connected_via, "a direct bolt connection (no routing table)")
        self.assertTrue(tried[-1][0].startswith("bolt"))

    def test_explicit_ca_bundle_is_respected_and_not_second_guessed(self):
        s = Neo4jSettings(SETTINGS.uri, "neo4j", "secret-pw", "neo4j", "C:/certs/x.pem")
        factory, tried = self._driver_factory([None])
        with mock.patch.object(neo4j.GraphDatabase, "driver", side_effect=factory), \
                mock.patch.object(neo4j, "TrustCustomCAs", side_effect=lambda p: ("ca", p)):
            c = Neo4jClient(s).connect()
        self.assertEqual(c.connected_via, "your CA bundle")
        self.assertEqual(len(tried), 1)

    def test_all_attempts_fail_message_lists_attempts_and_never_the_password(self):
        factory, _ = self._driver_factory([ServiceUnavailable("a")] * 5)
        with mock.patch.object(neo4j.GraphDatabase, "driver", side_effect=factory):
            with self.assertRaises(ConnectionError) as cm:
                Neo4jClient(SETTINGS).connect()
        msg = str(cm.exception)
        self.assertIn("system certificate store", msg)
        self.assertIn("direct bolt", msg)
        self.assertNotIn("secret-pw", msg)


class CheckScriptTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("check_neo4j_retrieval", ROOT / "scripts" / "check_neo4j_retrieval.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_early_failure_reports_the_real_error_instead_of_unbound_local(self):   # failure 3
        mod = self._load()

        class Boom:
            query_log = []

            def __init__(self, settings):
                pass

            def connect(self):
                return self

            def run_read(self, *a, **k):
                raise RuntimeError("the real problem")

            def close(self):
                pass
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(mod, "ROOT", Path(tmp)), \
                mock.patch.object(mod, "Neo4jClient", Boom), \
                mock.patch.object(mod.Neo4jSettings, "from_env", return_value=SETTINGS):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = mod.main()
            out = buf.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("the real problem", out)
            self.assertNotIn("UnboundLocalError", out)
            self.assertTrue(list(Path(tmp).glob("outputs/reports/neo4j_retrieval_*.json")))


if __name__ == "__main__":
    unittest.main()
