"""Independent check of data/canonical/*.json (does not trust the builder)."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from canonical.mappings import ALLOWED          # noqa: E402
from canonical.models import ENTITY_CLASSES, Relationship  # noqa: E402

D = os.path.join("data", "canonical")
fails = 0


def check(ok, msg, level="FAIL"):
    global fails
    print(f"  [{'PASS' if ok else level}] {msg}")
    if not ok and level == "FAIL":
        fails += 1


def load(name):
    with open(os.path.join(D, name), encoding="utf-8") as fh:
        return json.load(fh)["records"]


print("Checking canonical output ...")
ents, rels, unres = load("entities.json"), load("relationships.json"), load("unresolved_references.json")
ids = [e["canonical_id"] for e in ents]
check(len(ids) == len(set(ids)), f"canonical ids unique ({len(ids)} entities)")
check(all(re.match(r"^[A-Za-z]+:\S+$", i) for i in ids), "every id is <Type>:<key>")
bad = [e["canonical_id"] for e in ents
       if e["entity_type"] not in ENTITY_CLASSES
       or ENTITY_CLASSES[e["entity_type"]].model_validate(e) is None]
check(not bad, "every entity re-validates against its Pydantic model")
check(all(e["evidence"] for e in ents), "every entity has at least one evidence record")
check(all(e["sources"] for e in ents), "every entity lists its sources")
idset = set(ids)
check(all(Relationship.model_validate(r) for r in rels), "every relationship re-validates")
dangling = [r["rel_id"] for r in rels if r["source_id"] not in idset or r["target_id"] not in idset]
check(not dangling, f"no dangling relationship endpoints ({len(rels)} relationships)")
notallowed = [r["rel_id"] for r in rels
              if (r["source_id"].split(":")[0], r["rel_type"], r["target_id"].split(":")[0]) not in ALLOWED]
check(not notallowed, "every relationship uses an allowed (type, relation, type) triple")
check(all(r["evidence"] for r in rels), "every relationship carries evidence")
check(len({r["rel_id"] for r in rels}) == len(rels), "relationship ids unique (idempotent)")
vulns = [e for e in ents if e["entity_type"] == "Vulnerability"]
check(any(v["in_kev"] for v in vulns), "KEV vulnerabilities present")
check(sum(1 for v in vulns if not v["stub"]) >= 150, "at least 150 full (non-stub) vulnerabilities")
stubs = sum(1 for v in vulns if v["stub"])
print(f"  (info) advisory-only vulnerability stubs: {stubs}")
print(f"  (info) unresolved references: {len(unres)}")
by = {}
for e in ents:
    by[e["entity_type"]] = by.get(e["entity_type"], 0) + 1
print("  entities by type:", by)
print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
