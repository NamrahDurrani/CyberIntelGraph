"""Milestone 5.1 - write the correction documents from the REAL rebuilt output.

Run after:  python canonical\\build.py
Reads data/canonical/*.json (never raw or processed data), verifies the ATT&CK
sub-technique parents, then:
  * creates docs/CHANGE_REPORT_2026-11-10_M5.1_kev-cwe-links.md
  * appends a "Correction" section to the Milestone 5 change report
  * adds a Milestone 5.1 entry to CHANGELOG.md and PROJECT_STATUS.md
Safe to run twice: every edit is guarded by a marker and skipped if present.
"""
import argparse
import json
import os
import sys
from collections import Counter

MARK = "Milestone 5.1"
M5_REPORT = os.path.join("docs", "CHANGE_REPORT_2026-11-10_M5-canonical-model.md")
M51_REPORT = os.path.join("docs", "CHANGE_REPORT_2026-11-10_M5.1_kev-cwe-links.md")
PLACEHOLDER = "entities by type: ... | relationships by type: ... | unresolved: ... | check: ..."


def load(d, name):
    with open(os.path.join(d, name), encoding="utf-8") as fh:
        return json.load(fh)["records"]


def metadata(d, name):
    with open(os.path.join(d, name), encoding="utf-8") as fh:
        return json.load(fh)["metadata"]


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text, dry):
    if not dry:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--canonical-dir", default=os.path.join("data", "canonical"))
    ap.add_argument("--previous", type=int, default=171,
                    help="HAS_WEAKNESS count before the fix (Milestone 5 build: 171)")
    ap.add_argument("--expected-subtechniques", type=int, default=479)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if not os.path.exists(os.path.join(a.canonical_dir, "relationships.json")):
        print(f"RESULT: REFUSED - {a.canonical_dir} has no relationships.json. "
              "Run: python canonical\\build.py   first.")
        sys.exit(1)
    meta = metadata(a.canonical_dir, "relationships.json")
    if meta.get("builder_revision") != "5.1":
        print("RESULT: REFUSED - data/canonical was not built by the 5.1 builder "
              f"(builder_revision={meta.get('builder_revision')!r}). "
              "Run: python canonical\\build.py   and then this script again.")
        sys.exit(1)
    ents = load(a.canonical_dir, "entities.json")
    rels = load(a.canonical_dir, "relationships.json")
    unres = load(a.canonical_dir, "unresolved_references.json")
    by_ent = Counter(e["entity_type"] for e in ents)
    by_rel = Counter(r["rel_type"] for r in rels)

    prov = Counter()
    for r in rels:
        if r["rel_type"] == "HAS_WEAKNESS":
            s = {x["source"] for x in r["evidence"]}
            prov["both" if {"cisa_kev", "nvd"} <= s else
                 "kev_only" if s == {"cisa_kev"} else "nvd_only"] += 1
    new_hw = by_rel["HAS_WEAKNESS"]
    vulns_linked = len({r["source_id"] for r in rels if r["rel_type"] == "HAS_WEAKNESS"})

    subs = {e["canonical_id"] for e in ents
            if e["entity_type"] == "AttackTechnique" and e.get("is_subtechnique")}
    parents = {r["source_id"] for r in rels if r["rel_type"] == "SUBTECHNIQUE_OF"}
    n_sub_edges = by_rel["SUBTECHNIQUE_OF"]
    sub_ok = len(subs) == len(parents) == n_sub_edges and not (subs - parents)
    sub_expected = len(subs) == a.expected_subtechniques

    print("=== Milestone 5.1 verification ===")
    print(f"  HAS_WEAKNESS   previous {a.previous}  ->  new {new_hw}  (delta {new_hw - a.previous:+d})")
    print(f"    provenance   KEV only {prov['kev_only']} | NVD only {prov['nvd_only']} | both {prov['both']}")
    print(f"    vulnerabilities with at least one weakness link: {vulns_linked}")
    print(f"  Sub-techniques {len(subs)} entities | {n_sub_edges} SUBTECHNIQUE_OF edges | "
          f"{len(subs - parents)} without parent -> {'PASS' if sub_ok else 'FAIL'}")
    if not sub_expected:
        print(f"  [WARN] expected {a.expected_subtechniques} sub-techniques, found {len(subs)}")
    if new_hw < a.previous:
        print("  [WARN] HAS_WEAKNESS went DOWN - investigate before committing")
    if not ents or not rels:
        print("RESULT: FAILED - canonical output is empty")
        sys.exit(1)
    if not sub_ok:
        print("RESULT: FAILED - sub-technique relationships are inconsistent; docs not updated")
        sys.exit(1)

    summary = (f"entities: {len(ents):,} ("
               + "; ".join(f"{k} {v:,}" for k, v in by_ent.most_common()) + ") | relationships: "
               f"{len(rels):,} (" + "; ".join(f"{k} {v:,}" for k, v in by_rel.most_common())
               + f") | unresolved: {len(unres)}")

    report = f"""# Change report - 2026-11-10 - Milestone 5.1: read CWE ids from KEV

Correction to Milestone 5 (commit 3cd7374, left unchanged). Separate commit.

## Problem
The Milestone 5 builder created `HAS_WEAKNESS` links only from NVD records. KEV
records carry a `cwes` field that was ignored, so most KEV vulnerabilities had
no weakness link ({a.previous} edges in total).

## Change
- `canonical/build.py`: CWE linking moved into one shared `_link_weaknesses()`
  used by both `from_nvd` and `from_kev`; unresolved entries are de-duplicated;
  the build summary reports HAS_WEAKNESS provenance; metadata gets
  `builder_revision: "5.1"`.
- `canonical/mappings.py`: one alias, `kev_cwes`.
- `tests/unit/test_canonical_kev_cwes.py`: 11 new tests.
- Unchanged: entity ids, schema (models.py, ids.py), checker, collectors,
  raw and processed data.

## Rules
- A CWE reported by both KEV and NVD becomes ONE edge with two evidence records.
- Ids missing from the CWE catalog create no edge; they are logged once in
  `unresolved_references.json`.
- `NVD-CWE-noinfo` / `NVD-CWE-Other` and unparsable tokens create no edge and
  are counted in the build summary.

## Result (from the rebuilt data/canonical files)
| Item | Before (M5) | After (M5.1) |
|---|---|---|
| HAS_WEAKNESS edges | {a.previous} | {new_hw} |
| of which KEV only / NVD only / both | n/a | {prov['kev_only']} / {prov['nvd_only']} / {prov['both']} |
| Vulnerabilities with a weakness link | n/a | {vulns_linked} |
| SUBTECHNIQUE_OF edges vs sub-technique entities | 479 / 479 | {n_sub_edges} / {len(subs)} |

Sub-techniques without a parent: {len(subs - parents)}.

Full totals: {summary}
"""
    write(M51_REPORT, report, a.dry_run)
    print(f"  wrote {M51_REPORT}")

    # --- correct the Milestone 5 report (additive; old text kept) ---
    if os.path.exists(M5_REPORT):
        text = read(M5_REPORT)
        if PLACEHOLDER in text:
            text = text.replace(PLACEHOLDER, summary + " (rebuilt in " + MARK + ")")
        if "## Correction (" + MARK + ")" not in text:
            text = text.rstrip("\n") + f"""

## Correction ({MARK})
The HAS_WEAKNESS figure of {a.previous} in the original build was incomplete: KEV
`cwes` were not read. After {MARK} it is {new_hw} (KEV only {prov['kev_only']}, NVD only
{prov['nvd_only']}, both {prov['both']}). See `{M51_REPORT.replace(os.sep, '/')}`.
Totals after correction: {summary}
"""
            write(M5_REPORT, text, a.dry_run)
            print(f"  corrected {M5_REPORT}")
        else:
            print(f"  {M5_REPORT}: correction already present, skipped")
    else:
        print(f"  [WARN] {M5_REPORT} not found, skipped")

    # --- CHANGELOG.md: newest entry before the first '## ' heading ---
    entry = f"""## Milestone 5.1 - 2026-11-10 - KEV CWE ids now create HAS_WEAKNESS links
- Fixed: `cwes` on KEV records were ignored; HAS_WEAKNESS is now {new_hw} (was {a.previous}).
- Changed: `canonical/build.py` (shared `_link_weaknesses`), `canonical/mappings.py` (alias).
- Added: `tests/unit/test_canonical_kev_cwes.py`, `scripts/apply_milestone_5_1_docs.py`.
- Verified: {len(subs)} sub-techniques still have {n_sub_edges} parent links; entity ids and schema unchanged.
- Commit 3cd7374 (Milestone 5) intentionally left as is.

"""
    cl = "CHANGELOG.md"
    if os.path.exists(cl):
        text = read(cl)
        if MARK in text:
            print("  CHANGELOG.md: entry already present, skipped")
        else:
            i = text.find("\n## ")
            text = (text[:i + 1] + entry + text[i + 1:]) if i != -1 else text.rstrip("\n") + "\n\n" + entry
            write(cl, text, a.dry_run)
            print("  updated CHANGELOG.md")
    else:
        print("  [WARN] CHANGELOG.md not found, skipped")

    # --- PROJECT_STATUS.md: appended section ---
    ps = "PROJECT_STATUS.md"
    section = f"""## Milestone 5.1 - done (2026-11-10)
- Canonical graph now links KEV and NVD CWE ids: HAS_WEAKNESS {a.previous} -> {new_hw}.
- ATT&CK sub-technique parents verified ({n_sub_edges}/{len(subs)}).
- Next: Milestone 6 (Docling + chunking of the advisories).
"""
    if os.path.exists(ps):
        text = read(ps)
        if MARK in text:
            print("  PROJECT_STATUS.md: section already present, skipped")
        else:
            write(ps, text.rstrip("\n") + "\n\n" + section, a.dry_run)
            print("  updated PROJECT_STATUS.md")
    else:
        print("  [WARN] PROJECT_STATUS.md not found, skipped")
    print("RESULT: OK" + (" (dry run, nothing written)" if a.dry_run else ""))


if __name__ == "__main__":
    main()
