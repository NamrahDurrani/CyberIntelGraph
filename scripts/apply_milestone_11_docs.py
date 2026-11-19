"""Record the REAL Milestone 11 results in the docs. Refuses to run unless the latest
`outputs/reports/neo4j_retrieval_*.json` says ALL CHECKS PASSED.

    python scripts\\apply_milestone_11_docs.py

Writes docs/CHANGE_REPORT_<date>_M11_cypher_retrieval.md and replaces the lines marked
<!-- M11-VERIFIED --> in CHANGELOG.md, PROJECT_STATUS.md and README.md (safe to re-run)."""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARK = "<!-- M11-VERIFIED -->"


def latest_report() -> tuple[Path, dict]:
    files = sorted((ROOT / "outputs" / "reports").glob("neo4j_retrieval_*.json"))
    if not files:
        sys.exit("REFUSED: no outputs\\reports\\neo4j_retrieval_*.json - run scripts\\check_neo4j_retrieval.py first")
    return files[-1], json.loads(files[-1].read_text(encoding="utf-8"))


def replace_marked(path: Path, new_line: str) -> bool:
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    hit = False
    for i, ln in enumerate(lines):
        if MARK in ln:
            prefix = re.match(r"^(\s*(?:[-*]\s*(?:\[[ x]\]\s*)?)?)", ln).group(1)
            lines[i] = f"{prefix.replace('[ ]', '[x]')}{new_line} {MARK}"
            hit = True
    if hit:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return hit


def main() -> int:
    path, rep = latest_report()
    if rep.get("result") != "ALL CHECKS PASSED":
        sys.exit(f"REFUSED: {path.name} says {rep.get('result')!r}; fix the failures and re-run the check")
    checks = rep["checks"]
    n_pass = sum(c["status"] == "PASS" for c in checks)
    warns = [c for c in checks if c["status"] == "WARN"]
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    actor = rep.get("actor_example", {})
    summary = (f"verified {day} on the real Aura graph: {n_pass} checks passed, {len(warns)} warning(s)"
               + (f"; example {actor.get('name')}: {actor.get('counts')}" if actor else ""))

    doc = ROOT / "docs" / f"CHANGE_REPORT_{day}_M11_cypher_retrieval.md"
    body = [f"# Change report - Milestone 11: Cypher retrieval (live results, {day})", "",
            f"Source: `outputs/reports/{path.name}`  |  Result: **{rep['result']}**", "",
            "## Checks", "| Status | Check | Detail |", "|---|---|---|"]
    body += [f"| {c['status']} | {c['name']} | {c['detail']} |" for c in checks]
    body += ["", "## Resolved graph fields", "```json", json.dumps(rep["graph_map"], indent=2), "```", ""]
    if actor:
        body += ["## Example", f"`{actor['name']}` (`{actor['id']}`): {actor['counts']}", ""]
    body += [f"Queries run: {rep.get('queries_run')}; slowest: {rep.get('slowest_query_seconds')} s.", ""]
    if warns:
        body += ["## Warnings to review"] + [f"- {w['name']}: {w['detail']}" for w in warns] + [""]
    doc.write_text("\n".join(body), encoding="utf-8")

    done = [name for name in ("CHANGELOG.md", "PROJECT_STATUS.md", "README.md") if replace_marked(ROOT / name, summary)]
    print(f"checked: {n_pass} passed, {len(warns)} warnings")
    print(f"wrote {doc.relative_to(ROOT)}")
    print("updated " + ", ".join(done) if done else "no <!-- M11-VERIFIED --> markers found (docs not updated)")
    print("RESULT: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
