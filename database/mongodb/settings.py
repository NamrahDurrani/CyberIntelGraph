"""MongoDB settings from the environment (.env). The connection string is a secret: it is never printed,
logged or put in an exception message - use `redacted()` whenever you need to show it."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = "cyberintelgraph"
_DB_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,38}$")      # MongoDB forbids / \ . " $ and spaces; Atlas limit is 38 chars


class MongoConfigError(Exception):
    """A setting is missing or malformed (message never contains the connection string)."""


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env", override=False)
    except ImportError:
        pass


def redact(uri: str) -> str:
    """mongodb+srv://user:pass@host/x?y -> mongodb+srv://user:***@host"""
    m = re.match(r"^(mongodb(?:\+srv)?://)(?:([^:@/]+)(?::[^@]*)?@)?([^/?]+)", uri or "")
    if not m:
        return "<unparseable connection string>"
    scheme, user, host = m.groups()
    return f"{scheme}{user + ':***@' if user else ''}{host}"


@dataclass(frozen=True)
class MongoSettings:
    uri: str
    database: str = DEFAULT_DB
    app_name: str = "CyberIntelGraph"
    server_selection_timeout_ms: int = 10_000
    connect_timeout_ms: int = 10_000
    ca_file: str | None = None            # optional MONGODB_CA_BUNDLE / SSL_CERT_FILE; certifi is the default

    @staticmethod
    def from_env() -> "MongoSettings":
        _load_dotenv()
        uri = (os.environ.get("MONGODB_URI") or "").strip().strip('"').strip("'")
        if not uri:
            raise MongoConfigError("MONGODB_URI is not set. Put it in .env (never in Git or chat).")
        if not uri.startswith(("mongodb://", "mongodb+srv://")):
            raise MongoConfigError("MONGODB_URI must start with mongodb+srv:// (Atlas) or mongodb://")
        if "<password>" in uri or "<db_password>" in uri:
            raise MongoConfigError("MONGODB_URI still contains the <password> placeholder: replace it with your database user's password.")
        db = (os.environ.get("MONGODB_DB") or DEFAULT_DB).strip()
        if not _DB_NAME.match(db):
            raise MongoConfigError(f"MONGODB_DB {db!r} is not a valid database name (letters, digits, _ and - only, max 38).")
        ca = os.environ.get("MONGODB_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or None
        return MongoSettings(uri=uri, database=db, ca_file=ca)

    def redacted(self) -> str:
        return redact(self.uri)

    def __repr__(self) -> str:                      # a stray print(settings) must not leak the password
        return f"MongoSettings(uri={self.redacted()!r}, database={self.database!r})"
