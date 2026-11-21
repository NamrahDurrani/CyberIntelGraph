r"""Milestone 14 gate.

  python scripts\check_verification.py            OFFLINE: verification agent, live-fallback logic and persistence on fakes
  python scripts\check_verification.py --live     LIVE: real CISA KEV + NVD downloads (needs internet; uses NVD_API_KEY if set)

Exits 1 on any FAIL. A live run only READS the public APIs and writes the cache under data/fresh_cache/.
"""
from __future__ import annotations

import argparse
import sys
import tempfile

import _bootstrap  # noqa: F401

from cti_agent.graph import run_question
from cti_agent.testing import FakeLLM, FakeRunner, make_test_deps, sample_graph
from cti_verification.hooks import get_hooks
from cti_verification.settings import VerifySettings
from cti_verification.testing import FakeFetcher, FakeMongoDb, kev_entry, kev_payload, nvd_payload

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    results.append((ok, label))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  -> {detail}" if detail and not ok else ""))


def make(llm=None, fetcher=None, graph=None, mongo=None, **vs):
    deps = make_test_deps(runner=FakeRunner(graph) if graph else None, llm=llm)
    deps.extras.update({"fresh_fetcher": fetcher or FakeFetcher(), "fresh_sleep": lambda s: None,
                        "verify_settings": VerifySettings(cache_dir=tempfile.mkdtemp(), nvd_delay_seconds=0.0, **vs)})
    if mongo is not None:
        deps.extras["mongo_db"] = mongo
    return deps


def offline() -> None:
    print("OFFLINE check")
    f = run_question("Which techniques does APT29 use?", make(), get_hooks())
    check(f["verification"]["outcome"] == "PASS", "grounded answer -> PASS")

    bad = FakeLLM(lambda s, u: '{"entities": []}' if "Evidence blocks" not in u else "APT29 uses technique T9999 [E1]. APT29 uses T8888 [E1].")
    f = run_question("Which techniques does APT29 use?", make(llm=bad), get_hooks())
    check(f["verification"]["outcome"] == "FAIL" and "[UNVERIFIED]" in f["answer"], "invented technique ids -> FAIL and marked [UNVERIFIED]")

    f = run_question("Is CVE-2024-3400 exploited?", make(), get_hooks())
    kinds = {e["kind"]: e for e in f["evidence"]}
    check(kinds["fresh_kev"]["status"] == "confirmed_authoritative" and "sha256=" in kinds["fresh_nvd"]["source"], "live KEV + NVD evidence with provenance hash")

    f = run_question("Is CVE-2024-3400 exploited?", make(fetcher=FakeFetcher(fail={"kev", "nvd"})), get_hooks())
    live = [e["status"] for e in f["evidence"] if e["kind"].startswith("fresh_")]
    check(set(live) == {"unable_to_verify"}, "live outage -> unable_to_verify (never not_found)")
    check(f["verification"]["outcome"] in ("TOOL_ERROR", "FAIL", "PARTIAL") and f["verification"]["tool_error"], "live outage is reported as a tool error")

    f = run_question("Is CVE-2024-3400 exploited?", make(fetcher=FakeFetcher(kev=kev_payload([kev_entry("CVE-2026-1")]))), get_hooks())
    check({e["kind"]: e["status"] for e in f["evidence"]}["fresh_kev"] == "not_found", "not listed in KEV -> not_found with a 'not proof' note")

    g = sample_graph()
    g.nodes["v1"][1].update({"last_modified": "2024-05-01T00:00:00", "cvss": 9.8})
    f = run_question("Is CVE-2024-3400 exploited?", make(graph=g), get_hooks())
    check(len(f["fresh"]["discrepancies"]) == 2 and f["verification"]["contradictions"], "stale graph copy detected and reported as a contradiction")

    db = FakeMongoDb()
    f = run_question("Which techniques does APT29 use?", make(mongo=db), get_hooks())
    check(f["persistence"]["mongo"] == "saved" and len(db["investigation_runs"].docs) == 1, "investigation + traces saved (idempotent upsert)")
    f = run_question("Which techniques does APT29 use?", make(mongo=FakeMongoDb(fail=True)), get_hooks())
    check(f["persistence"]["mongo"].startswith("FAILED") and bool(f["trace_file"]), "database outage never loses the result")


def live() -> None:
    from pathlib import Path

    from cti_agent.config import project_root
    from cti_verification.fresh import FetchError, LiveSources

    print("LIVE check (real CISA KEV + NVD)")
    vs = VerifySettings.from_env()
    print(f"  NVD API key: {'set' if vs.nvd_api_key else 'not set (slower, rate-limited)'}")
    src = LiveSources(vs, project_root() / vs.cache_dir)
    try:
        cat = src.kev_catalog()
        count = len(cat.payload.get("vulnerabilities", []))
        check(count > 1000, "CISA KEV catalog downloaded", f"{count} entries")
        print(f"     catalog {cat.payload.get('catalogVersion')}, {count} entries, retrieved {cat.retrieved_at}, stale={cat.stale}")
        entry = LiveSources.kev_entry(cat, "CVE-2021-44228")
        check(entry is not None, "CVE-2021-44228 (Log4Shell) is listed in KEV")
        recent = LiveSources.kev_recent(cat, 3)
        print("     newest KEV additions: " + ", ".join(f"{r['cveID']} ({r['dateAdded']})" for r in recent))
    except FetchError as exc:
        check(False, "CISA KEV download", str(exc))
    try:
        cached, nvd = src.nvd_record("CVE-2021-44228")
        check(nvd is not None and nvd["cvss_score"] is not None, "NVD record for CVE-2021-44228 downloaded and parsed")
        if nvd:
            print(f"     CVSS {nvd['cvss_score']} {nvd['cvss_severity']}, status {nvd['status']}, last modified {nvd['last_modified']}")
    except FetchError as exc:
        check(False, "NVD download", str(exc))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    (live if args.live else offline)()
    failed = [l for ok, l in results if not ok]
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(len(failed)) + ' CHECK(S) FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
