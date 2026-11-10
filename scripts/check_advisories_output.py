"""Independent check of the CISA advisories collector output (Milestone 3 validation, Rule 7).

Re-reads the files on disk (does NOT trust the collector's own summary) and checks:
  1. every manifest entry marked ok: raw HTML exists and its SHA-256 matches the manifest
  2. normalized file: record_count matches; doc_ids, slugs and URLs are unique
  3. every URL is on www.cisa.gov
  4. every record has the provenance fields, a title, text, and points to an existing raw file whose hash matches raw_sha256
  5. dates are valid ISO dates, last_revised is not before release_date, and EVERY document has a publication date
     (a date derived from the alert code is allowed but must be marked as derived)
  6. every mentioned CVE / ATT&CK / CWE id has a valid format and actually occurs in the record's text
Information only: how close we are to the 50-75 document target, date range, coverage, short pages, most mentioned CVEs.

Run from the project root (venv active):
    python scripts\\check_advisories_output.py
Exit code 0 = all checks passed, 1 = at least one failed.
"""
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw" / "advisories"
MANIFEST = RAW_DIR / "manifest.jsonl"
NORMALIZED = ROOT / "data" / "processed" / "advisories_normalized.json"
KEV = ROOT / "data" / "processed" / "cisa_kev_normalized.json"
PROVENANCE = ("source_name", "source_url", "source_record_id", "retrieved_at", "original_format",
              "raw_file_reference", "raw_sha256", "collection_method", "evidence_type")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CWE_RE = re.compile(r"^CWE-\d{1,5}$")

results: list[bool] = []


def check(ok: bool, message: str) -> None:
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {message}")


def valid_date(value) -> bool:
    try:
        date.fromisoformat(value)
        return True
    except (TypeError, ValueError):
        return False


def main() -> int:
    print("Checking CISA advisories output ...")
    if not MANIFEST.is_file() or not NORMALIZED.is_file():
        print("  [FAIL] manifest or normalized file not found - run the advisories collector first")
        return 1
    entries = [json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]
    doc = json.loads(NORMALIZED.read_text(encoding="utf-8"))
    meta, records = doc["metadata"], doc["records"]
    print(f"  (manifest: {len(entries)} downloads; {len(records)} normalized documents)")

    # 1 raw integrity
    bad = []
    for e in entries:
        if e.get("outcome") != "ok":
            continue
        path = RAW_DIR / e["raw_file"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != e["sha256"]:
            bad.append(e["raw_file"])
    check(not bad, f"all {sum(1 for e in entries if e.get('outcome') == 'ok')} raw pages exist and match their SHA-256"
          if not bad else f"{len(bad)} raw page(s) missing or changed, e.g. {bad[:3]}")

    # 2 counts + uniqueness
    check(meta["record_count"] == len(records), f"record_count ({meta['record_count']}) == records ({len(records)})")
    for key in ("doc_id", "slug", "url"):
        values = [r[key] for r in records]
        check(len(values) == len(set(values)), f"{key} values are unique")

    # 3 hosts
    off_site = [r["url"] for r in records if urlparse(r["url"]).hostname != "www.cisa.gov"]
    check(not off_site, "every URL is on www.cisa.gov" if not off_site else f"off-site URLs: {off_site[:3]}")

    # 4 provenance + content + raw reference
    missing = [r["doc_id"] for r in records if any(not r.get(k) for k in PROVENANCE)]
    check(not missing, "every record has all provenance fields" if not missing else f"{len(missing)} miss provenance, e.g. {missing[:3]}")
    empty = [r["doc_id"] for r in records if not r["title"] or not r["text"]]
    check(not empty, "every record has a title and text" if not empty else f"empty title/text: {empty[:3]}")
    mismatch = []
    for r in records:
        path = ROOT / r["raw_file_reference"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != r["raw_sha256"]:
            mismatch.append(r["doc_id"])
    check(not mismatch, "every raw_file_reference exists and matches raw_sha256" if not mismatch else f"raw mismatch: {mismatch[:3]}")

    # 5 dates
    bad_dates = [r["doc_id"] for r in records for k in ("published_at", "release_date", "last_revised")
                 if r.get(k) and not valid_date(r[k])]
    check(not bad_dates, "all dates are valid ISO dates" if not bad_dates else f"bad dates in {bad_dates[:3]}")
    reversed_dates = [r["doc_id"] for r in records if r["release_date"] and r["last_revised"] and r["last_revised"] < r["release_date"]]
    check(not reversed_dates, "last_revised is never before release_date" if not reversed_dates else f"reversed: {reversed_dates[:3]}")
    undated = [r["doc_id"] for r in records if not r.get("published_at")]
    check(not undated, "every document has a publication date" if not undated else f"{len(undated)} document(s) have no date at all, e.g. {undated[:3]}")
    unmarked = [r["doc_id"] for r in records if r.get("published_at_is_derived") and "DERIVED" not in (r.get("published_at_source") or "")]
    check(not unmarked, "derived dates are always marked as derived" if not unmarked else f"unmarked derived dates: {unmarked[:3]}")

    # 6 mentions
    bad_mentions = []
    for r in records:
        haystack = (r["title"] + "\n" + r["text"]).upper()
        for key, pattern in (("mentioned_cve_ids", CVE_RE), ("mentioned_attack_ids", ATTACK_RE), ("mentioned_cwe_ids", CWE_RE)):
            for value in r[key]:
                if not pattern.match(value) or value.upper() not in haystack:
                    bad_mentions.append((r["doc_id"], value))
    check(not bad_mentions, "every mentioned id is well formed and really occurs in the text" if not bad_mentions
          else f"bad mentions: {bad_mentions[:3]}")

    # information
    n = len(records)
    dates = sorted(r["published_at"] for r in records if r["published_at"])
    cves = Counter(c for r in records for c in r["mentioned_cve_ids"])
    print("\nProfile (information only):")
    print(f"  documents                : {n}   (target: 50-75; {'reached' if n >= 50 else 'not reached yet'})")
    if dates:
        print(f"  published range          : {dates[0]} .. {dates[-1]}")
    print(f"  with release date label  : {sum(1 for r in records if r['release_date'])}/{n}")
    print(f"  with alert code          : {sum(1 for r in records if r['alert_code'])}/{n}")
    sources = Counter(("derived from alert code" if r.get("published_at_is_derived") else (r["published_at_source"] or "none")) for r in records)
    print(f"  published_at source      : {dict(sources)}")
    both = [r for r in records if r.get("release_date_matches_alert_code") is not None]
    agree = sum(1 for r in both if r["release_date_matches_alert_code"])
    print(f"  Release Date label vs alert-code date: {agree}/{len(both)} agree (tests the 'AAyy-ddd' convention used for derived dates)")
    print(f"  marked 'Archived Content': {sum(1 for r in records if r.get('archived'))}/{n};  advisory types: {dict(Counter(r.get('advisory_type') or 'unknown' for r in records))}")
    print(f"  very short (<500 chars)  : {[r['slug'] for r in records if len(r['text']) < 500][:5]}")
    print(f"  total words              : {sum(r['word_count'] for r in records)}")
    print(f"  attachments listed       : {sum(len(r['attachments']) for r in records)} (processed in Milestone 6)")
    print(f"  distinct CVE ids mentioned: {len(cves)}; most mentioned: {cves.most_common(3)}")
    if KEV.is_file() and cves:
        kev_ids = {x["cve_id"] for x in json.loads(KEV.read_text(encoding="utf-8"))["records"]}
        print(f"  of those, also in KEV    : {len(set(cves) & kev_ids)}/{len(cves)}")

    failed = results.count(False)
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(failed) + ' CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
