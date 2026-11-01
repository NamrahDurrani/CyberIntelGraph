# 0001 - Technology stack

- Date: 2026-10-31
- Status: accepted

## Decision
Python 3.12, FastAPI, Pydantic, Docling, Microsoft GraphRAG, Neo4j, MongoDB (not SQLite), LangGraph,
BGE-M3-compatible hosted embeddings, hosted LLM API, Next.js + TypeScript, DeepEval, Git + GitHub.

## Constraints
- Prefer free or low-cost hosted inference; no large local models without justification.
- Install packages milestone by milestone, checking Python 3.12 compatibility and disk space first.
- Keep project data on D:. Any change to this stack is recorded in a new decision file.
