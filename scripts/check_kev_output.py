"""Independent check of the CISA KEV collector output (Milestone 3 validation, Rule 7).

It re-reads the files on disk (it does NOT trust the collector's own summary) and checks:
  1. raw file exists and its SHA-256 matches the .meta.json sidecar
  2. raw file: declared count == number of records
  3. normalized file: record_count matches, no duplicate CVE IDs
  4. every normalized record carries the provenance fields
  5. every record's raw_file_reference points to an existing raw file
  6. the initial subset is a subset of the normalized records

Run from the project root (venv active):
    python scripts\\check_kev_output.py
Exit code 0 = all checks passed, 1 = at least one failed.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw" / "cisa_kev"
NORMALIZED = ROOT / "data" / "processed" / "cisa_kev_normalized.json"
SUBSET = ROOT / "data" / "processed" / "cisa_kev_initial_subset.json"
PROVENANCE = ("source_name", "source_url", "source_record_id", "retrieved_at",
              "raw_file_reference", "collection_method", "original_format")

results: list[tuple[bool, str]] = []


def check(ok: bool, message: str) -> None:
    results.append((ok, message))
    print(f"  [{'PASS' if ok else 'FAIL'}] {message}")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    print("Checking CISA KEV output ...")
    if not NORMALIZED.is_file():
        print(f"  [FAIL] {NORMALIZED.relative_to(ROOT)} not found - run the collector first")
        return 1
    normalized = load(NORMALIZED)
    meta, records = normalized["metadata"], normalized["records"]

    # 1 + 2: raw files
    raw_ref = ROOT / meta["raw_file_reference"]
    check(raw_ref.is_file(), f"raw file exists: {meta['raw_file_reference']}")
    if raw_ref.is_file():
        raw_bytes = raw_ref.read_bytes()
        sha = hashlib.sha256(raw_bytes).hexdigest()
        check(sha == meta["raw_sha256"], "raw file SHA-256 matches the normalized metadata")
        sidecar = raw_ref.with_suffix(".meta.json")
        if sidecar.is_file():
            check(load(sidecar)["sha256"] == sha, "raw file SHA-256 matches its .meta.json sidecar")
        else:
            check(False, "raw .meta.json sidecar exists")
        raw_doc = json.loads(raw_bytes)
        check(int(raw_doc["count"]) == len(raw_doc["vulnerabilities"]),
              f"raw file: declared count ({raw_doc['count']}) == records ({len(raw_doc['vulnerabilities'])})")

    # 3: normalized counts + duplicates
    check(meta["record_count"] == len(records), f"normalized record_count ({meta['record_count']}) == records ({len(records)})")
    ids = [r["cve_id"] for r in records]
    dupes = [cve for cve, n in Counter(ids).items() if n > 1]
    check(not dupes, f"no duplicate CVE IDs ({len(ids)} unique)" if not dupes else f"duplicate CVE IDs: {dupes[:5]}")

    # 4 + 5: provenance
    bad = [r["cve_id"] for r in records if any(not r.get(k) for k in PROVENANCE)]
    check(not bad, "every record has all provenance fields" if not bad else f"{len(bad)} records miss provenance, e.g. {bad[:3]}")
    refs = {r["raw_file_reference"] for r in records}
    check(all((ROOT / ref).is_file() for ref in refs), f"all raw_file_reference values point to existing files ({len(refs)})")

    # 6: subset
    if SUBSET.is_file():
        subset = load(SUBSET)["records"]
        check({r["cve_id"] for r in subset} <= set(ids), f"initial subset ({len(subset)} records) is contained in the normalized set")
    else:
        check(False, "initial subset file exists (collector run with --subset-size 0?)")

    # profile (information only)
    ransomware = sum(1 for r in records if r["known_ransomware_campaign_use"] is True)
    dates = sorted(r["date_added"] for r in records)
    vendors = Counter(r["vendor_project"] for r in records).most_common(5)
    print("\nProfile (information only):")
    print(f"  catalog version     : {meta['catalog_version']}  (released {meta['catalog_date_released']})")
    print(f"  records             : {len(records)}")
    print(f"  ransomware 'Known'  : {ransomware}")
    print(f"  date_added range    : {dates[0]} .. {dates[-1]}")
    print(f"  top vendors         : {vendors}")

    failed = [m for ok, m in results if not ok]
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(len(failed)) + ' CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
