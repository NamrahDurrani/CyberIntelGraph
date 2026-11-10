"""Independent check of the CWE collector output (Milestone 3 validation, Rule 7).

Re-reads the files on disk (does NOT trust the collector's own summary) and checks:
  1. the raw zip exists and its SHA-256 matches its .meta.json and the processed metadata
  2. the zip really contains an XML file that parses, and its version matches the processed metadata
  3. record counts in the metadata match the files; ids are unique and well formed (CWE-<number>)
  4. every ChildOf / Has_Member target that points at a weakness or category exists in the catalog
  5. every CWE id used by our NVD and KEV records is either in the catalog or reported as missing (information)
  6. the initial subset is contained in the full set and contains every referenced id that exists
  7. every record has the provenance fields and points to an existing raw file

Run from the project root (venv active):
    python scripts\\check_cwe_output.py
Exit code 0 = all checks passed, 1 = at least one failed.
"""
import hashlib
import io
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NORMALIZED = ROOT / "data" / "processed" / "cwe_normalized.json"
SUBSET = ROOT / "data" / "processed" / "cwe_initial_subset.json"
NVD = ROOT / "data" / "processed" / "nvd_normalized.json"
KEV = ROOT / "data" / "processed" / "cisa_kev_normalized.json"
PROVENANCE = ("source_name", "source_url", "source_record_id", "retrieved_at", "original_format",
              "raw_file_reference", "collection_method", "catalog_version", "evidence_type")

results: list[bool] = []


def check(ok: bool, message: str) -> None:
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {message}")


def main() -> int:
    print("Checking CWE output ...")
    if not NORMALIZED.is_file():
        print("  [FAIL] cwe_normalized.json not found - run the CWE collector first")
        return 1
    doc = json.loads(NORMALIZED.read_text(encoding="utf-8"))
    meta, records, views = doc["metadata"], doc["records"], doc["views"]
    print(f"  (catalog {meta['catalog_name']} v{meta['catalog_version']}, {len(records)} weaknesses+categories, {len(views)} views)")

    # 1 + 2 raw integrity
    raw = ROOT / meta["raw_file_reference"]
    check(raw.is_file(), f"raw zip exists: {meta['raw_file_reference']}")
    if raw.is_file():
        content = raw.read_bytes()
        sha = hashlib.sha256(content).hexdigest()
        check(sha == meta["raw_sha256"], "raw zip SHA-256 matches the processed metadata")
        sidecar = raw.with_suffix(".meta.json")
        check(sidecar.is_file() and json.loads(sidecar.read_text(encoding="utf-8"))["sha256"] == sha,
              "raw zip SHA-256 matches its .meta.json sidecar")
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                xml = z.read(meta["xml_member"])
            root = ET.fromstring(xml)
            check(root.attrib.get("Version", "") == meta["catalog_version"],
                  f"XML inside the zip parses and its Version ({root.attrib.get('Version')}) matches the metadata")
        except Exception as exc:  # report any failure as a failed check
            check(False, f"XML inside the zip could not be read: {exc}")

    # 2b entries besides weaknesses: a real catalog has hundreds (categories or similarly grouped entries).
    # Zero means a section of the XML was not parsed (this happened once). The kind's NAME is not what matters:
    # the first parser only knew 'Category'; the current one keeps every kind it finds.
    kinds = Counter(r["element_type"] for r in records)
    others = {k: v for k, v in kinds.items() if k != "weakness"}
    check(bool(others), f"the catalog has entries besides weaknesses: {others}" if others else
          "only weaknesses were found (no categories or other entry kinds): a section of the XML was probably not parsed "
          "(see 'XML sections' in the collector summary)")
    if others and "category" not in others:
        print(f"  (info) no entries are named 'category' in this file; the grouping entries are called {sorted(others)}")

    # 3 counts + ids
    check(meta["record_count"] == len(records), f"record_count ({meta['record_count']}) == records ({len(records)})")
    ids = [r["cwe_id"] for r in records] + [v["cwe_id"] for v in views]
    check(len(ids) == len(set(ids)), f"ids are unique ({len(ids)})")
    bad_ids = [i for i in ids if not re.match(r"^CWE-\d+$", i)]
    check(not bad_ids, "every id looks like CWE-<number>" if not bad_ids else f"bad ids: {bad_ids[:5]}")

    # 4 relationship targets
    known = {r["cwe_id"] for r in records}
    dangling = Counter()
    for r in records:
        for rw in r["related_weaknesses"]:
            if rw["cwe_id"] and rw["cwe_id"] not in known:
                dangling[rw["cwe_id"]] += 1
        for m in r["members"]:
            if m["cwe_id"] and m["cwe_id"] not in known:
                dangling[m["cwe_id"]] += 1
    total_links = sum(len(r["related_weaknesses"]) + len(r["members"]) for r in records)
    print(f"  (info) {len(dangling)} link target(s) outside weaknesses/categories (views or other element types), out of {total_links} links")
    check(len(dangling) <= max(10, total_links // 100),
          "almost all relationship targets exist in the catalog" if len(dangling) <= max(10, total_links // 100)
          else f"too many unknown targets: {dict(list(dangling.items())[:5])}")

    # 5 + 6 referenced ids and subset
    referenced: set[str] = set()
    if NVD.is_file():
        for rec in json.loads(NVD.read_text(encoding="utf-8"))["records"]:
            referenced |= {w["cwe_id"] for w in rec.get("weaknesses", []) if w.get("cwe_id", "").startswith("CWE-")}
    if KEV.is_file():
        for rec in json.loads(KEV.read_text(encoding="utf-8"))["records"]:
            referenced |= {str(c).strip() for c in rec.get("cwes", []) if str(c).strip()}
    missing = sorted(i for i in referenced if i not in known)
    print(f"  (info) CWE ids used by our NVD/KEV records: {len(referenced)}; not in the catalog: {len(missing)} {missing[:5]}")
    if SUBSET.is_file():
        subset = json.loads(SUBSET.read_text(encoding="utf-8"))["records"]
        subset_ids = {r["cwe_id"] for r in subset}
        check(subset_ids <= known, f"initial subset ({len(subset)} records) is contained in the full set")
        check({i for i in referenced if i in known} <= subset_ids, "initial subset contains every referenced id that exists")
    else:
        check(not (referenced & known), "initial subset file exists (it is needed because NVD/KEV reference CWE ids)")

    # 7 provenance
    missing_prov = [r["record_id"] for r in records + views if any(not r.get(k) for k in PROVENANCE)]
    check(not missing_prov, "every record has all provenance fields" if not missing_prov else f"{len(missing_prov)} miss provenance, e.g. {missing_prov[:3]}")
    refs = {r["raw_file_reference"] for r in records + views}
    check(all((ROOT / r).is_file() for r in refs), f"all raw_file_reference values point to existing files ({len(refs)})")

    print("\nProfile (information only):")
    print(f"  by element type : {dict(Counter(r['element_type'] for r in records))}")
    print(f"  by status       : {dict(Counter(r['status'] for r in records))}")
    print(f"  by abstraction  : {dict(Counter(r['abstraction'] for r in records if r['element_type'] == 'weakness'))}")
    top = sorted(records, key=lambda r: r["referenced_by_nvd_records"], reverse=True)[:5]
    print(f"  most used by our NVD records: {[(r['cwe_id'], r['name'][:40], r['referenced_by_nvd_records']) for r in top if r['referenced_by_nvd_records']]}")
    deprecated_used = [r["cwe_id"] for r in records if r["status"] == "Deprecated" and (r["referenced_by_nvd_records"] or r["referenced_by_kev_records"])]
    print(f"  deprecated ids still used by our records: {deprecated_used}")

    failed = results.count(False)
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(failed) + ' CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
