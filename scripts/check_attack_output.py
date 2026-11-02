"""Independent check of the MITRE ATT&CK collector output (Milestone 3 validation, Rule 7).

Re-reads the files on disk (does NOT trust the collector's own summary) and checks:
  1. the raw bundle exists and its SHA-256 matches its .meta.json and the processed metadata
  2. record counts in the metadata match the files
  3. STIX ids and ATT&CK ids are unique, ATT&CK ids have the expected format per type
  4. every relationship endpoint exists in the objects file and ids/types agree
  5. relationship type/direction combinations are exactly the documented ones
  6. techniques: tactics exist; sub-techniques: parent exists, is not itself a sub-technique, id prefix matches
  7. every record has the provenance fields and points to an existing raw file

Run from the project root (venv active):
    python scripts\\check_attack_output.py
Exit code 0 = all checks passed, 1 = at least one failed.
"""
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBJECTS = ROOT / "data" / "processed" / "attack_objects_normalized.json"
RELATIONSHIPS = ROOT / "data" / "processed" / "attack_relationships_normalized.json"
ID_PATTERNS = {
    "attack-pattern": r"^T\d{4}(\.\d{3})?$", "x-mitre-tactic": r"^TA\d{4}$", "intrusion-set": r"^G\d{4}$",
    "malware": r"^S\d{4}$", "tool": r"^S\d{4}$", "campaign": r"^C\d{4}$", "course-of-action": r"^M\d{4}$",
}
EXPECTED_COMBOS = {
    ("malware", "uses", "attack-pattern"), ("intrusion-set", "uses", "attack-pattern"),
    ("course-of-action", "mitigates", "attack-pattern"), ("campaign", "uses", "attack-pattern"),
    ("tool", "uses", "attack-pattern"), ("intrusion-set", "uses", "malware"),
    ("attack-pattern", "subtechnique-of", "attack-pattern"), ("intrusion-set", "uses", "tool"),
    ("campaign", "uses", "malware"), ("campaign", "uses", "tool"), ("campaign", "attributed-to", "intrusion-set"),
}
PROVENANCE = ("source_name", "source_url", "source_record_id", "retrieved_at", "original_format",
              "raw_file_reference", "collection_method", "attack_version", "evidence_type")

results: list[bool] = []


def check(ok: bool, message: str) -> None:
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {message}")


def main() -> int:
    print("Checking MITRE ATT&CK output ...")
    if not OBJECTS.is_file() or not RELATIONSHIPS.is_file():
        print("  [FAIL] processed files not found - run the ATT&CK collector first")
        return 1
    obj_doc = json.loads(OBJECTS.read_text(encoding="utf-8"))
    rel_doc = json.loads(RELATIONSHIPS.read_text(encoding="utf-8"))
    meta, objects, rels = obj_doc["metadata"], obj_doc["records"], rel_doc["records"]
    print(f"  (release {meta['attack_version']}, {len(objects)} objects, {len(rels)} relationships)")

    # 1. raw integrity
    raw = ROOT / meta["raw_file_reference"]
    check(raw.is_file(), f"raw bundle exists: {meta['raw_file_reference']}")
    if raw.is_file():
        digest = hashlib.sha256()
        with open(raw, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        sha = digest.hexdigest()
        check(sha == meta["raw_sha256"], "raw bundle SHA-256 matches the processed metadata")
        sidecar = raw.with_suffix(".meta.json")
        check(sidecar.is_file() and json.loads(sidecar.read_text(encoding="utf-8"))["sha256"] == sha,
              "raw bundle SHA-256 matches its .meta.json sidecar")

    # 2. counts
    check(meta["record_count"] == len(objects), f"objects record_count ({meta['record_count']}) == records ({len(objects)})")
    check(rel_doc["metadata"]["record_count"] == len(rels),
          f"relationships record_count ({rel_doc['metadata']['record_count']}) == records ({len(rels)})")

    # 3. uniqueness + id format
    stix_ids = [o["stix_id"] for o in objects]
    check(len(stix_ids) == len(set(stix_ids)), "STIX ids are unique")
    keys = [(o["stix_type"], o["attack_id"]) for o in objects]
    check(len(keys) == len(set(keys)), "ATT&CK ids are unique within each type")
    bad_fmt = [o["attack_id"] for o in objects if not re.match(ID_PATTERNS[o["stix_type"]], o["attack_id"])]
    check(not bad_fmt, "ATT&CK id format is valid for every object" if not bad_fmt else f"bad id format: {bad_fmt[:5]}")
    check(len({r["stix_id"] for r in rels}) == len(rels), "relationship STIX ids are unique")

    # 4. endpoints
    by_stix = {o["stix_id"]: o for o in objects}
    broken = [r["stix_id"] for r in rels
              if r["source_stix_id"] not in by_stix or r["target_stix_id"] not in by_stix
              or by_stix[r["source_stix_id"]]["attack_id"] != r["source_attack_id"]
              or by_stix[r["target_stix_id"]]["attack_id"] != r["target_attack_id"]
              or by_stix[r["source_stix_id"]]["stix_type"] != r["source_stix_type"]
              or by_stix[r["target_stix_id"]]["stix_type"] != r["target_stix_type"]]
    check(not broken, "every relationship endpoint exists and ids/types agree" if not broken else f"{len(broken)} broken, e.g. {broken[:2]}")

    # 5. combos
    combos = Counter((r["source_stix_type"], r["relationship_type"], r["target_stix_type"]) for r in rels)
    unexpected = set(combos) - EXPECTED_COMBOS
    check(not unexpected, "relationship type/direction combinations are the documented ones" if not unexpected
          else f"new combination(s) not in the data dictionary: {sorted(unexpected)}")

    # 6. techniques
    shortnames = {o["shortname"] for o in objects if o["stix_type"] == "x-mitre-tactic"}
    techniques = [o for o in objects if o["stix_type"] == "attack-pattern"]
    bad_tactics = [t["attack_id"] for t in techniques if not t["tactics"] or set(t["tactics"]) - shortnames]
    check(not bad_tactics, "every technique has at least one valid tactic" if not bad_tactics else f"tactic problem: {bad_tactics[:5]}")
    tech_by_id = {t["attack_id"]: t for t in techniques}
    bad_parent = []
    for t in techniques:
        if t["is_subtechnique"]:
            parent = tech_by_id.get(t["parent_attack_id"])
            if parent is None or parent["is_subtechnique"] or t["attack_id"].split(".")[0] != parent["attack_id"]:
                bad_parent.append(t["attack_id"])
        elif t["parent_attack_id"] is not None:
            bad_parent.append(t["attack_id"])
    check(not bad_parent, "every sub-technique has a valid parent (id prefix matches)" if not bad_parent else f"parent problem: {bad_parent[:5]}")

    # 7. provenance
    missing = [o["record_id"] for o in objects + rels if any(not o.get(k) for k in PROVENANCE)]
    check(not missing, "every record has all provenance fields" if not missing else f"{len(missing)} record(s) miss provenance, e.g. {missing[:3]}")
    refs = {o["raw_file_reference"] for o in objects + rels}
    check(all((ROOT / r).is_file() for r in refs), f"all raw_file_reference values point to existing files ({len(refs)})")

    # information only
    print("\nProfile (information only):")
    print(f"  objects by type        : {dict(Counter(o['stix_type'] for o in objects))}")
    print(f"  relationships by type  : {dict(Counter(r['relationship_type'] for r in rels))}")
    print(f"  sub-techniques         : {sum(1 for t in techniques if t['is_subtechnique'])} of {len(techniques)} techniques")
    per_tactic = Counter(tac for t in techniques for tac in t["tactics"])
    print(f"  techniques per tactic  : {dict(per_tactic.most_common(5))} ...")
    print(f"  initial-access techniques: {per_tactic.get('initial-access', 0)}")
    attributed = sum(1 for r in rels if r["relationship_type"] == "attributed-to")
    print(f"  campaigns attributed to a group: {attributed} of {sum(1 for o in objects if o['stix_type'] == 'campaign')} campaigns")

    failed = results.count(False)
    print(f"\nRESULT: {'ALL CHECKS PASSED' if not failed else str(failed) + ' CHECK(S) FAILED'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
