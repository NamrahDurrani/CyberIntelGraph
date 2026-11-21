r"""Ask the research agent a question.

  python scripts\run_agent.py "Which techniques does APT29 use?"
  python scripts\run_agent.py "..." --json          (full record)
  python scripts\run_agent.py "..." --no-llm        (evidence only, no Groq call)
  python scripts\run_agent.py "..." --refresh-schema
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace

import _bootstrap  # noqa: F401

from cti_agent.config import Settings
from cti_agent.deps import build_default_deps
from cti_agent.evidence import STATUS_LABEL, EvidenceStatus
from cti_agent.graph import run_question
from cti_agent.neo4j_client import Neo4jConnectionError


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("question")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--refresh-schema", action="store_true")
    ap.add_argument("--claims", type=int, default=15, help="how many claims to print")
    ap.add_argument("--evidence-chars", type=int, default=300, help="characters of evidence text to print")
    args = ap.parse_args()

    settings = Settings.from_env()
    if args.no_llm:
        settings = replace(settings, use_llm=False)
    try:
        deps = build_default_deps(settings, refresh_schema=args.refresh_schema)
    except Neo4jConnectionError as exc:
        print(f"CANNOT START: {exc}")
        return 2
    try:
        final = run_question(args.question, deps)
    finally:
        close = getattr(deps.runner, "close", None)
        if close:
            close()

    if args.json:
        print(json.dumps(final, indent=2, ensure_ascii=False, default=str))
        return 0

    print(f"\nInvestigation {final['investigation_id']}  status: {final['workflow_status']}")
    print("\n=== PLAN ===")
    for t in final["plan"]:
        print(f"- {t['agent']}: {t['objective']}")
    print("\n=== AGENTS ===")
    for a in final["agents"]:
        print(f"- {a['agent_name']:<14} {a['status']:<11} {a['duration_ms']:>5} ms  {len(a['tool_calls'])} tool calls  {a['summary']}")
        for err in a["errors"]:
            print(f"    ERROR: {err}")
    print("\n=== ANSWER ===")
    print(final["answer"])
    print(f"\n=== CLAIMS ({len(final['claims'])}) ===")
    for c in final["claims"][: args.claims]:
        obj = f" -> {c['object']}" if c.get("object") else ""
        print(f"- [{c['status']}] {c['subject']} {c['predicate']}{obj}  {c['evidence_ids']}")
    if len(final["claims"]) > args.claims:
        print(f"  ... {len(final['claims']) - args.claims} more (use --claims N or --json)")
    print("\n=== EVIDENCE ===")
    for ev in final["evidence"]:
        label = STATUS_LABEL[EvidenceStatus(ev["status"])]
        print(f"[{ev['id']}] {label}\n     {ev['summary']}")
        if ev.get("text") and args.evidence_chars:
            snippet = " ".join(ev["text"].split())[: args.evidence_chars]
            print(f"     {snippet}")
        if ev.get("source"):
            print(f"     source: {ev['source']}")
    verification = final.get("verification")
    if verification:
        print("\n=== VERIFICATION ===")
        print(verification.get("headline", ""))
    if final.get("limitations"):
        print("\n=== LIMITATIONS ===")
        for l in final["limitations"]:
            print(f"- {l}")
    if final["warnings"]:
        print("\n=== WARNINGS ===")
        for w in final["warnings"]:
            print(f"- {w}")
    if final.get("trace_file"):
        print(f"\nSaved: {final['trace_file']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
