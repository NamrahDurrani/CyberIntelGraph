r"""Live check: saves one test investigation to MongoDB Atlas, reads it back, saves again (must not duplicate),
then deletes its own test documents. Uses only the collections investigation_runs / investigation_traces.

  python scripts\check_mongodb_persistence.py
"""
from __future__ import annotations

import sys
import uuid

import _bootstrap  # noqa: F401

from cti_agent.config import Settings
from cti_agent.graph import run_question
from cti_agent.testing import FakeLLM, FakeRunner, make_test_deps
from cti_verification.hooks import get_hooks
from cti_verification.persistence import MongoInvestigationStore, connect_db
from cti_verification.settings import VerifySettings
from cti_verification.testing import FakeFetcher

results: list[bool] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  -> {detail}" if detail and not ok else ""))


def main() -> int:
    settings = Settings.from_env()
    if not settings.mongo_uri:
        print("CANNOT RUN: no MongoDB URI found in .env (looked for MONGODB_URI, MONGO_URI, MONGODB_URL, MONGODB_ATLAS_URI).")
        return 2
    vs = VerifySettings.from_env()
    tag = uuid.uuid4().hex[:8]
    deps = make_test_deps(llm=FakeLLM(), runner=FakeRunner())
    deps.settings = settings.__class__(**{**settings.__dict__, "trace_dir": deps.settings.trace_dir, "schema_cache": deps.settings.schema_cache})
    deps.extras.update({"fresh_fetcher": FakeFetcher(), "fresh_sleep": lambda s: None, "verify_settings": vs})
    try:
        db = connect_db(deps, vs)
        print(f"connected to database '{settings.mongo_database}' (run tag {tag})")
    except Exception as exc:  # noqa: BLE001
        print(f"CANNOT CONNECT: {type(exc).__name__}: {str(exc)[:200]}")
        return 2
    final = run_question(f"[{tag}] Which techniques does APT29 use?", deps, get_hooks())
    inv_id = final["investigation_id"]
    try:
        check(final["persistence"]["mongo"] == "saved", "workflow saved the investigation", str(final["persistence"]))
        store = MongoInvestigationStore(db, vs)
        doc = store.get(inv_id)
        check(doc is not None and doc["question"] == final["question"], "investigation reads back")
        check(bool(doc) and len(doc["claims"]) == len(final["claims"]), "claims round-trip")
        check(len(store.traces(inv_id)) == len(final["agents"]), "agent traces saved")
        store.save(final)
        check(db[vs.runs_collection].count_documents({"investigation_id": inv_id}) == 1, "saving again does not duplicate")
        check(store.get("does-not-exist") is None, "unknown id is None (database answered), not an error")
    finally:
        db[vs.runs_collection].delete_many({"investigation_id": inv_id})
        db[vs.traces_collection].delete_many({"investigation_id": inv_id})
        print("  test documents cleaned up")
    ok = all(results)
    print(f"\nRESULT: {'ALL CHECKS PASSED' if ok else 'CHECK(S) FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
