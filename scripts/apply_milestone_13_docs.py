r"""Adds the Milestone 13 entries to CHANGELOG.md, PROJECT_STATUS.md and README.md
(append-only, safe to run twice) and writes a dated change report.

  python scripts\apply_milestone_13_docs.py              (records "implemented, verification pending")
  python scripts\apply_milestone_13_docs.py --verified   (run ONLY after check_agent --live looked right to you)
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import _bootstrap  # noqa: F401
from _bootstrap import ROOT

MARK = "<!-- milestone-13 -->"


def append_once(path: Path, text: str) -> str:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    if MARK in current:
        return "already present"
    path.write_text(current.rstrip() + "\n\n" + MARK + "\n" + text.strip() + "\n", encoding="utf-8")
    return "updated"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verified", action="store_true")
    args = ap.parse_args()
    today = date.today().isoformat()
    state = (f"Verified on the project PC on {today} (offline checks, unit tests and a live run against Neo4j Aura)."
             if args.verified else "Implemented. Live verification on the project PC is still pending.")

    changelog = f"""## Milestone 13 - LangGraph supervisor and specialist agents ({today})
- Added `cti_agent/`: a supervisor plans the investigation and runs specialist agents in parallel
  (threat_actor, vulnerability, attack, evidence). `collect` merges and de-duplicates their evidence, `review`
  retries only failed / no-match tasks (bounded), then assess -> generate -> citation check -> finalize.
- Typed contracts (Pydantic): ResearchTask, AgentResult, Claim. A documented / inferred / candidate claim must cite evidence.
- Evidence statuses: confirmed_authoritative, reported_in_document, inferred, llm_candidate, not_found, unable_to_verify.
  Claim statuses: documented, inferred, candidate, unsupported, not_found, unverified.
- Read-only Neo4j access; schema discovered from the real graph; GraphRAG candidates never promoted to facts;
  tool failures are unable_to_verify, never not_found.
- Budgets: retries, parallel tasks, time, tool calls. LangGraph checkpointing with pause / resume (memory; mongo optional).
- Hook points (`pre_assess`, `post_generate`, `post_finalize`) so Milestone 14 plugs in without editing these files.
- Each investigation is saved to outputs/investigations/.
- Scripts: run_agent.py, check_agent.py, probe_graph_schema.py, probe_rag_api.py.
- Status: {state}"""

    status = f"""## Milestone 13 - LangGraph supervisor and specialist agents
{state}

What exists: a supervisor that plans an investigation, four read-only specialist agents that run in parallel, structured
claims with evidence ids, and an answer that cites only existing evidence. Run: `python scripts/run_agent.py "<question>"`.

Known limits: no independent claim verification or live KEV/NVD check yet (Milestone 14); no MongoDB persistence or
FastAPI endpoints yet (Milestones 14 and 15); document retrieval needs RAG_RETRIEVER in .env; answer quality depends on the
LLM and on how many advisories GraphRAG has processed (pilot only)."""

    readme = """## Research agent (Milestone 13)
Ask a question: `python scripts/run_agent.py "Which techniques does APT29 use?"`
Offline self-check: `python scripts/check_agent.py`. Live check: `python scripts/check_agent.py --live`.
Details: docs/milestones/M13_langgraph_agent.md"""

    report = f"""# Change report - Milestone 13 ({today})

{changelog}

## Files added
- cti_agent/ (config, evidence, schemas, nlp, supervisor, nodes, graph, state, hooks, checkpoint, store, trace, schema_map,
  neo4j_client, llm, deps, testing, agents/, tools/)
- scripts/run_agent.py, check_agent.py, probe_graph_schema.py, probe_rag_api.py, apply_milestone_13_docs.py, _bootstrap.py
- tests/unit/test_agent_basics.py, test_agent_graph.py, test_agent_agents.py
- docs/milestones/M13_langgraph_agent.md, docs/data_dictionary/AGENT_STATE_AND_EVIDENCE.md
- requirements-agent.txt
"""
    out = {
        "CHANGELOG.md": append_once(ROOT / "CHANGELOG.md", changelog),
        "PROJECT_STATUS.md": append_once(ROOT / "PROJECT_STATUS.md", status),
        "README.md": append_once(ROOT / "README.md", readme),
    }
    report_path = ROOT / "docs" / f"CHANGE_REPORT_{today}_M13_agent.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    for name, result in out.items():
        print(f"{name}: {result}")
    print(f"{report_path.relative_to(ROOT)}: written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
