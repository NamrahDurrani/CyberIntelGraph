"""Neo4j connection for Milestone 11 (read-only retrieval).

Design rules
------------
* Settings come from the environment / .env (never hard-coded, never printed).
* Every retrieval query runs in a READ transaction with a timeout.
* A defensive validator refuses any query containing a write keyword, so a
  coding mistake can never modify the graph from the retrieval layer.
* Neo4j temporal values are converted to ISO strings so results are plain JSON.

Custom CA bundles: the neo4j driver refuses `encrypted` / `trusted_certificates`
together with the `neo4j+s://` scheme, so when a CA bundle is used the scheme is
rewritten to `neo4j://` with `encrypted=True` (same security, explicit trust store).

Connection strategy (Milestone 11.1): the same ladder as the Milestone 10 sync, because that is what is proven to
work on this machine: (1) the operating-system certificate store, (2) the certifi CA bundle, (3) a direct bolt
connection without a routing table. Reads are retried a few times on transient connection errors.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable

try:  # optional: .env support (installed since Milestone 3)
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


class ReadOnlyViolation(ValueError):
    """Raised when a query that could write is sent to the retrieval client."""


class Neo4jConfigError(RuntimeError):
    """Raised when connection settings are missing or unusable."""


_WRITE_WORDS = (
    "CREATE", "MERGE", "DELETE", "DETACH", "SET", "REMOVE", "DROP", "LOAD",
    "FOREACH", "GRANT", "DENY", "REVOKE", "ALTER", "RENAME", "START", "STOP",
)
_PROC_WRITE = re.compile(r"\bCALL\s+(apoc\.(create|merge|refactor|periodic|cypher\.doIt|trigger|schema)|db\.create|dbms\.)", re.I)


def _strip_literals(cypher: str) -> str:
    """Remove string literals and `backticked` identifiers before keyword scanning."""
    out = re.sub(r"`[^`]*`", "``", cypher)
    out = re.sub(r"'(?:[^'\\]|\\.)*'", "''", out)
    out = re.sub(r'"(?:[^"\\]|\\.)*"', '""', out)
    out = re.sub(r"//[^\n]*", "", out)
    return out


def assert_read_only(cypher: str) -> None:
    """Refuse queries containing write keywords. Defence in depth (the transaction
    is also opened in READ mode, which the server enforces)."""
    body = _strip_literals(cypher)
    for word in _WRITE_WORDS:
        if re.search(rf"\b{word}\b", body, re.I):
            raise ReadOnlyViolation(f"query contains write keyword {word!r}")
    if _PROC_WRITE.search(body):
        raise ReadOnlyViolation("query calls a procedure that may write")


@dataclass(frozen=True)
class Neo4jSettings:
    uri: str
    user: str
    password: str
    database: str = "neo4j"
    ca_bundle: str | None = None

    @staticmethod
    def from_env(env: dict[str, str] | None = None, *, load: bool = True) -> "Neo4jSettings":
        if load and env is None and load_dotenv is not None:
            load_dotenv(override=False)
        e = os.environ if env is None else env
        uri = (e.get("NEO4J_URI") or "").strip()
        # NEO4J_USER is what your Milestone 10 sync logged in with; NEO4J_USERNAME
        # (the Aura credentials file name) is the fallback.
        user = (e.get("NEO4J_USER") or e.get("NEO4J_USERNAME") or "").strip()
        password = e.get("NEO4J_PASSWORD") or ""
        database = (e.get("NEO4J_DATABASE") or "neo4j").strip()
        ca = (e.get("NEO4J_CA_BUNDLE") or e.get("SSL_CERT_FILE") or e.get("REQUESTS_CA_BUNDLE") or "").strip() or None
        missing = [k for k, v in (("NEO4J_URI", uri), ("NEO4J_USER", user), ("NEO4J_PASSWORD", password)) if not v]
        if missing:
            raise Neo4jConfigError("missing in .env / environment: " + ", ".join(missing))
        return Neo4jSettings(uri, user, password, database, ca)

    def describe(self) -> str:
        """Safe to print: no password."""
        host = self.uri.split("://", 1)[-1]
        return f"{host} as {self.user}, database {self.database}" + (", custom CA bundle" if self.ca_bundle else "")


def driver_kwargs(uri: str, ca_bundle: str | None) -> tuple[str, dict[str, Any]]:
    """Return (uri, kwargs) for GraphDatabase.driver, handling the CA-bundle rule."""
    if not ca_bundle:
        return uri, {}
    from neo4j import TrustCustomCAs  # imported lazily so unit tests do not need a server
    scheme, _, rest = uri.partition("://")
    base = {"neo4j+s": "neo4j", "bolt+s": "bolt"}.get(scheme)
    if base is None:
        if scheme in ("neo4j+ssc", "bolt+ssc"):
            return uri, {}  # self-signed mode: a CA bundle is meaningless
        base = scheme
    return f"{base}://{rest}", {"encrypted": True, "trusted_certificates": TrustCustomCAs(ca_bundle)}


def clean_value(v: Any) -> Any:
    """Make driver values JSON-friendly (temporal types -> ISO strings)."""
    if isinstance(v, dict):
        return {k: clean_value(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [clean_value(x) for x in v]
    iso = getattr(v, "iso_format", None)
    if callable(iso):
        return iso()
    to_native = getattr(v, "to_native", None)
    if callable(to_native):
        try:
            return to_native().isoformat()
        except Exception:
            return str(v)
    return v


class Neo4jClient:
    """Thin read-only wrapper. Use as a context manager."""

    DRIVER_OPTIONS = dict(connection_timeout=15, connection_acquisition_timeout=30, max_transaction_retry_time=20)

    def __init__(self, settings: Neo4jSettings, *, timeout: float = 30.0, retries: int = 3, retry_delay: float = 2.0):
        self.settings = settings
        self.timeout = timeout
        self.retries = max(1, int(retries))
        self.retry_delay = retry_delay
        self.connected_via: str | None = None
        self._driver = None
        self.query_log: list[dict[str, Any]] = []   # {cypher, seconds, rows}

    # -- lifecycle -----------------------------------------------------------
    def _attempts(self) -> list[tuple[str, str, str | None]]:
        """[(label, uri, ca_bundle)] in the order they are tried."""
        s = self.settings
        scheme, _, rest = s.uri.partition("://")
        tls = scheme.endswith("+s")
        certifi_path = None
        try:
            import certifi
            certifi_path = certifi.where()
        except Exception:  # noqa: BLE001
            pass
        out: list[tuple[str, str, str | None]] = []
        if s.ca_bundle:
            out.append(("your CA bundle", s.uri, s.ca_bundle))
        else:
            out.append(("the system certificate store", s.uri, None))
            if tls and certifi_path:
                out.append(("the certifi CA bundle", s.uri, certifi_path))
        if scheme == "neo4j+s":                      # no routing table to fetch: works when routing discovery is the problem
            out.append(("a direct bolt connection (no routing table)", f"bolt+s://{rest}", s.ca_bundle or certifi_path))
        return out

    def connect(self) -> "Neo4jClient":
        from neo4j import GraphDatabase
        errors: list[str] = []
        for label, uri, bundle in self._attempts():
            uri2, kwargs = driver_kwargs(uri, bundle)
            driver = None
            try:
                driver = GraphDatabase.driver(uri2, auth=(self.settings.user, self.settings.password), **self.DRIVER_OPTIONS, **kwargs)
                driver.verify_connectivity()
            except Exception as exc:  # noqa: BLE001  (auth, TLS, routing, timeout - try the next way in)
                errors.append(f"{label}: {type(exc).__name__}: {str(exc)[:120]}")
                if driver is not None:
                    try:
                        driver.close()
                    except Exception:  # noqa: BLE001
                        pass
                continue
            self._driver, self.connected_via = driver, label
            return self
        raise ConnectionError("could not connect to Neo4j. Tried:\n  - " + "\n  - ".join(errors) +
                              "\nCheck that the Aura instance is running (console.neo4j.io), then the password and the network.")

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> "Neo4jClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- queries -------------------------------------------------------------
    def run_read(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run one read-only query; returns a list of plain dict rows."""
        assert_read_only(cypher)
        if self._driver is None:
            raise RuntimeError("client is not connected")
        from neo4j import READ_ACCESS, unit_of_work
        from neo4j.exceptions import ServiceUnavailable, SessionExpired

        # The server-side timeout of a managed transaction is set with unit_of_work. (A neo4j.Query object is only
        # accepted by session.run, not tx.run: that was the Milestone 11 TypeError.)
        @unit_of_work(timeout=self.timeout)
        def work(tx):
            return [clean_value(r.data()) for r in tx.run(cypher, params or {})]

        t0 = time.perf_counter()
        for attempt in range(1, self.retries + 1):
            try:
                with self._driver.session(database=self.settings.database, default_access_mode=READ_ACCESS) as session:
                    rows = session.execute_read(work)
                break
            except (SessionExpired, ServiceUnavailable):          # transient: stale routing table, dropped connection
                if attempt == self.retries:
                    raise
                time.sleep(self.retry_delay * attempt)
                self.close()
                self.connect()
        self.query_log.append({"cypher": " ".join(cypher.split())[:160], "seconds": round(time.perf_counter() - t0, 4), "rows": len(rows)})
        return rows

    _INDEX_STMT = re.compile(r"CREATE (RANGE |TEXT )?INDEX [A-Za-z0-9_]+ IF NOT EXISTS FOR \(n:[A-Za-z0-9_]+\) ON \(n\.`[A-Za-z0-9_]+`\)")

    def run_schema_write(self, statements: Iterable[str]) -> list[str]:
        """ONLY for index creation (`schema --apply-indexes`). Every statement is
        validated BEFORE anything is sent; only `CREATE ... INDEX ... IF NOT EXISTS` passes."""
        stmts = [st.strip() for st in statements]
        for st in stmts:
            if not self._INDEX_STMT.fullmatch(st):
                raise ReadOnlyViolation(f"refusing non-index statement: {st[:60]}")
        if self._driver is None:
            raise RuntimeError("client is not connected")
        with self._driver.session(database=self.settings.database) as session:
            for st in stmts:
                session.run(st).consume()
        return stmts
