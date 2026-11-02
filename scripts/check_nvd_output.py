"""Independent check of the NVD collector output (Milestone 3 validation, Rule 7).

Re-reads the files on disk (does NOT trust the collector's own summary) and checks:
  1. every successful manifest entry: raw file exists and its SHA-256 matches the manifest
  2. normalized file: record_count matches, no duplicate CVE IDs
  3. every normalized record carries the provenance fields and points to an existing raw file
  4. the CVE id inside each raw file equals the CVE id of the normalized record
  5. published_at is not later than last_modified_at
Information only: coverage (CVSS / CWE / affected products), overlap with the KEV catalog and KEV subset.

Run from the project root (venv active):
    python scripts\\check_nvd_output.py
Exit code 0 = all checks passed, 1 = at least one failed.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw" / "nvd"
MANIFEST = RAW_DIR / "manifest.jsonl"
NORMALIZED = ROOT / "data" / "processed" / "nvd_normalized.json"
KEV_NORMALIZED = ROOT / "data" / "processed" / "cisa_kev_normalized.json"
KEV_SUBSET = ROOT / "data" / "processed" / "cisa_kev_initial_subset.json"
PROVENANCE = ("source_name", "source_url", "source_record_id", "retrieved_at", "published_at",
              "last_modified_at", "original_format", "raw_file_reference", "collection_method")

results: list[bool] = []


def check(ok: bool, message: str) -> None:
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {message}")


def main() -> int:
    print("Checking NVD output ...")
    if not MANIFEST.is_file() or not NORMALIZED.is_file():
        print("  [FAIL] manifest or normalized file not found - run the NVD collector first")
        return 1

    entries = [json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()]
    outcomes = Counter(e.get("outcome") for e in entries)
    print(f"  (manifest: {len(entries)} downloads; outcomes {dict(outcomes)})")

    # 1. raw integrity
    ok_entries = [e for e in entries if e.get("outcome") == "ok"]
    bad = []
    for e in ok_entries:
        path = RAW_DIR / e["raw_file"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != e["sha256"]:
            bad.append(e["raw_file"])
    check(not bad, f"all {len(ok_entries)} successful raw files exist and match their SHA-256" if not bad
          else f"{len(bad)} raw file(s) missing or changed, e.g. {bad[:3]}")

    # 2. normalized counts + duplicates
    normalized = json.loads(NORMALIZED.read_text(encoding="utf-8"))
    meta, records = normalized["metadata"], normalized["records"]
    check(meta["record_count"] == len(records), f"record_count ({meta['record_count']}) == records ({len(records)})")
    ids = [r["cve_id"] for r in records]
    dupes = [c for c, n in Counter(ids).items() if n > 1]
    check(not dupes, f"no duplicate CVE IDs ({len(ids)} unique)" if not dupes else f"duplicates: {dupes[:5]}")

    # 3. provenance + raw reference
    missing_prov = [r["cve_id"] for r in records if any(not r.get(k) for k in PROVENANCE)]
    check(not missing_prov, "every record has all provenance fields" if not missing_prov
          else f"{len(missing_prov)} record(s) miss provenance, e.g. {missing_prov[:3]}")
    missing_raw = [r["cve_id"] for r in records if not (ROOT / r["raw_file_reference"]).is_file()]
    check(not missing_raw, "every raw_file_reference points to an existing file" if not missing_raw
          else f"missing raw files for {missing_raw[:3]}")

    # 4. id inside raw == normalized id
    mismatched = []
    for r in records:
        path = ROOT / r["raw_file_reference"]
        if path.is_file():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw["vulnerabilities"][0]["cve"]["id"].upper() != r["cve_id"]:
                mismatched.append(r["cve_id"])
    check(not mismatched, "CVE id inside each raw file matches the normalized record" if not mismatched
          else f"id mismatch for {mismatched[:3]}")

    # 5. dates
    wrong_dates = [r["cve_id"] for r in records if r["published_at"] > r["last_modified_at"]]
    check(not wrong_dates, "published_at <= last_modified_at for every record" if not wrong_dates
          else f"{len(wrong_dates)} record(s) published after last modified, e.g. {wrong_dates[:3]}")

    # information only
    n = len(records) or 1
    sev = Counter((r["cvss_primary"] or {}).get("severity", "none") for r in records)
    rejected = sum(1 for r in records if r["vuln_status"] == "Rejected")
    print("\nProfile (information only):")
    print(f"  records                 : {len(records)}")
    print(f"  with CVSS               : {sum(1 for r in records if r['cvss_primary'])}/{len(records)}")
    print(f"  with weakness (CWE)     : {sum(1 for r in records if r['weaknesses'])}/{len(records)}")
    print(f"  with affected products  : {sum(1 for r in records if r['affected_products'])}/{len(records)}")
    print(f"  severity (primary CVSS) : {dict(sev)}")
    print(f"  vulnStatus 'Rejected'   : {rejected}")
    print(f"  NVD carries CISA fields : {sum(1 for r in records if r['nvd_cisa_fields'])}/{len(records)}")
    if KEV_NORMALIZED.is_file():
        kev_ids = {r["cve_id"] for r in json.loads(KEV_NORMALIZED.read_text(encoding="utf-8"))["records"]}
        print(f"  also in KEV catalog     : {len(set(ids) & kev_ids)}/{len(records)}")
    if KEV_SUBSET.is_file():
        subset_ids = {r["cve_id"] for r in json.loads(KEV_SUBSET.read_text(encoding="utf-8"))["records"]}
        print(f"  KEV subset covered      : {len(subset_ids & set(ids))}/{len(subset_ids)}")

    failed = results.count(False)
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(failed) + ' CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
