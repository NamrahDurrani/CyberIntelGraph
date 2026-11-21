"""Milestone 14 - live lookups (fake network) and the full agent with both milestones wired together."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from cti_agent.graph import run_question
from cti_agent.hooks import load_hooks
from cti_agent.testing import FakeLLM, FakeRunner, make_test_deps, sample_graph
from cti_verification.fresh import FetchError, LiveSources, parse_nvd
from cti_verification.hooks import get_hooks
from cti_verification.nodes import wants_fresh
from cti_verification.settings import VerifySettings
from cti_verification.testing import FakeFetcher, kev_entry, kev_payload, nvd_payload


def vs(tmp_path, **kw):
    return VerifySettings(cache_dir=str(tmp_path), nvd_delay_seconds=0.0, **kw)


def sources(tmp_path, fetcher=None, now=None, **kw):
    return LiveSources(vs(tmp_path, **kw), tmp_path, fetcher or FakeFetcher(), now=now, sleep=lambda s: None)


# ------------------------------------------------------------------ sources
def test_kev_lookup_and_recent(tmp_path):
    kev = kev_payload([kev_entry("CVE-2024-3400"), kev_entry("CVE-2026-0001", added="2026-11-18"),
                       kev_entry("CVE-2025-0002", added="2025-05-05")])
    src = sources(tmp_path, FakeFetcher(kev=kev))
    cat = src.kev_catalog()
    assert LiveSources.kev_entry(cat, "cve-2024-3400")["product"] == "PAN-OS"
    assert LiveSources.kev_entry(cat, "CVE-1999-0001") is None
    assert [e["cveID"] for e in LiveSources.kev_recent(cat, 2)] == ["CVE-2026-0001", "CVE-2025-0002"]


def test_cache_ttl_and_stale_fallback(tmp_path):
    clock = {"t": datetime(2026, 11, 20, 8, tzinfo=timezone.utc)}
    fetcher = FakeFetcher(clock=lambda: clock["t"])
    src = sources(tmp_path, fetcher, now=lambda: clock["t"], cache_ttl_hours=12.0)
    src.kev_catalog()
    assert fetcher.calls == ["kev"]
    clock["t"] += timedelta(hours=1)
    src.kev_catalog()
    assert fetcher.calls == ["kev"]                     # served from cache inside the TTL
    clock["t"] += timedelta(hours=13)
    fetcher.fail.add("kev")
    stale = src.kev_catalog()                            # download fails -> old copy, flagged stale
    assert stale.stale is True and stale.payload["catalogVersion"] == "2026.11.19"


def test_failed_download_without_cache_raises(tmp_path):
    with pytest.raises(FetchError):
        sources(tmp_path, FakeFetcher(fail={"kev"})).kev_catalog()


def test_cache_keeps_provenance_and_stays_out_of_raw(tmp_path):
    sources(tmp_path).kev_catalog()
    import json
    stored = json.loads((tmp_path / "kev_live.json").read_text())
    assert {"url", "retrieved_at", "sha256", "payload"} <= set(stored) and len(stored["sha256"]) == 64
    assert "raw" not in str(tmp_path / "kev_live.json")


def test_nvd_parse_and_unknown_cve(tmp_path):
    src = sources(tmp_path)
    cached, parsed = src.nvd_record("CVE-2024-3400")
    assert parsed["cvss_score"] == 10.0 and parsed["cwes"] == ["CWE-77"] and parsed["reference_count"] == 2
    _, none = src.nvd_record("CVE-2030-9999")
    assert none is None and parse_nvd({}) is None
    with pytest.raises(FetchError):
        src.nvd_record("not-a-cve")


# ------------------------------------------------------------------ helpers
def deps_with(tmp_path, fetcher, graph=None, llm=None, **kw):
    deps = make_test_deps(runner=FakeRunner(graph) if graph else None, llm=llm)
    deps.extras.update({"fresh_fetcher": fetcher, "verify_settings": vs(tmp_path, **kw), "fresh_sleep": lambda s: None})
    return deps


def run(question, deps):
    return run_question(question, deps, get_hooks())


def kinds(final):
    return {e["kind"]: e for e in final["evidence"]}


# ------------------------------------------------------------- integration
def test_hooks_are_discovered_by_the_agent():
    hooks = load_hooks()
    assert [n for n, _ in hooks["pre_assess"]] == ["fresh_lookup"]
    assert [n for n, _ in hooks["post_generate"]] == ["verification_agent"]
    assert [n for n, _ in hooks["post_finalize"]] == ["persist_mongo"]


def test_live_kev_and_nvd_evidence_added_for_cve(tmp_path):
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, FakeFetcher()))
    k = kinds(final)
    assert k["fresh_kev"]["status"] == "confirmed_authoritative" and "is listed in the CISA KEV" in k["fresh_kev"]["summary"]
    assert k["fresh_nvd"]["status"] == "confirmed_authoritative" and "sha256=" in k["fresh_nvd"]["source"]
    assert final["fresh"]["checked"] == ["CVE-2024-3400"] and final["fresh"]["kev_catalog_version"] == "2026.11.19"
    assert final["verification"] is not None and "Verification " in final["answer"]


def test_cve_missing_from_graph_still_answered_from_live_data(tmp_path):
    fetcher = FakeFetcher(kev=kev_payload([kev_entry("CVE-2026-7777")]),
                          nvd={"CVE-2026-7777": nvd_payload("CVE-2026-7777")})
    final = run("What is CVE-2026-7777?", deps_with(tmp_path, fetcher))
    assert any(e["kind"] == "fresh_kev" and e["status"] == "confirmed_authoritative" for e in final["evidence"])
    assert "CVE-2026-7777" in final["unresolved"]                  # graph did not have it - still reported honestly
    assert any(e["kind"] == "lookup_miss" for e in final["evidence"])


def test_not_listed_in_kev_is_not_found_not_proof(tmp_path):
    fetcher = FakeFetcher(kev=kev_payload([kev_entry("CVE-2026-0001")]))
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, fetcher))
    ev = kinds(final)["fresh_kev"]
    assert ev["status"] == "not_found" and "does not prove" in ev["text"]


def test_network_failure_is_unable_to_verify_never_not_found(tmp_path):
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, FakeFetcher(fail={"kev", "nvd"})))
    k = kinds(final)
    assert k["fresh_kev"]["status"] == "unable_to_verify" and k["fresh_nvd"]["status"] == "unable_to_verify"
    assert len(final["fresh"]["errors"]) == 2
    assert any("NOT treated" in w for w in final["warnings"])
    assert "unable to verify" in final["answer"].lower()


def test_discrepancy_when_graph_is_older_than_live_nvd(tmp_path):
    g = sample_graph()
    g.nodes["v1"][1].update({"last_modified": "2024-05-01T00:00:00", "cvss": 9.8})
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, FakeFetcher(), graph=g))
    assert len(final["fresh"]["discrepancies"]) == 2               # newer date AND different CVSS
    check = kinds(final)["freshness_check"]
    assert "may be outdated" in check["summary"] and "9.8" in check["text"]
    assert "Freshness:" in final["answer"]


def test_no_comparable_fields_is_noted_not_guessed(tmp_path):
    g = sample_graph()
    del g.nodes["v1"][1]["cvss"]
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, FakeFetcher(), graph=g))
    assert final["fresh"]["discrepancies"] == [] and final["fresh"]["notes"]


def test_recent_kev_question_without_cve(tmp_path):
    kev = kev_payload([kev_entry("CVE-2026-0001", added="2026-11-18"), kev_entry("CVE-2024-3400")])
    final = run("What are the latest exploited vulnerabilities added to KEV?", deps_with(tmp_path, FakeFetcher(kev=kev)))
    ev = kinds(final)["fresh_kev_recent"]
    assert "CVE-2026-0001" in ev["text"] and ev["text"].index("CVE-2026-0001") < ev["text"].index("CVE-2024-3400")


def test_fresh_lookup_skipped_without_cve_or_when_disabled(tmp_path):
    fetcher = FakeFetcher()
    final = run("Which techniques does APT29 use?", deps_with(tmp_path, fetcher))
    assert fetcher.calls == [] and final["fresh"] is None
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, fetcher, fresh_enabled=False))
    assert fetcher.calls == [] and "fresh_kev" not in kinds(final)


def test_max_fresh_cves_limit(tmp_path):
    fetcher = FakeFetcher()
    run("Compare CVE-2024-0001, CVE-2024-0002, CVE-2024-0003 and CVE-2024-0004", deps_with(tmp_path, fetcher, max_fresh_cves=2))
    assert [c for c in fetcher.calls if c.startswith("nvd")] == ["nvd:CVE-2024-0001", "nvd:CVE-2024-0002"]


def test_verification_flags_an_invented_statement_in_the_answer(tmp_path):
    def llm(system, user):
        if "Evidence blocks" not in user:
            return '{"entities": []}'
        return ("CVE-2024-3400 is listed in the CISA KEV catalog [E1]. "
                "It was used by APT29 to deploy ransomware [E1].")
    final = run("Is CVE-2024-3400 exploited?", deps_with(tmp_path, FakeFetcher(), llm=FakeLLM(llm)))
    v = final["verification"]
    assert v["needs_review"] and v["outcome"] in ("PARTIAL", "FAIL")
    assert any(r["verdict"] in ("unsupported", "partial", "uncited") for r in v["answer_results"])
    assert "[UNVERIFIED]" in final["answer"] or "[CHECK]" in final["answer"]


def test_wants_fresh_words():
    assert wants_fresh("what is the latest KEV addition?") and not wants_fresh("what does APT29 use?")
