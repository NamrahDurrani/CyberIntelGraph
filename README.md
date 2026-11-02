# CyberIntelGraph

Evidence-grounded, agentic **Cyber Threat Intelligence (CTI)** research system.

It collects intelligence from authoritative sources (NVD, CISA KEV, MITRE ATT&CK, CWE,
CISA advisories), builds one unified knowledge graph (Microsoft GraphRAG + Neo4j), and answers
research questions with citations, source URLs, dates and stated limitations - never with
unsupported claims.

> **Status:** Milestone 1 verified. Milestone 3 in progress: KEV and NVD validated, MITRE ATT&CK collector built. See `PROJECT_STATUS.md`.

## Start here (read in this order)
1. `docs/GETTING_STARTED.md`  - install Python 3.12, create the virtual environment, verify
2. `docs/GITHUB_GUIDE.md`     - turn this folder into a GitHub repository
3. `docs/pipeline/00_milestone_roadmap.md` - the 18 milestones, one by one, with run commands
4. `docs/architecture/folder_guide.md` - what every folder is for

## Quick start (Windows PowerShell)
```powershell
cd C:\CyberIntelGraph
.\scripts\setup_env.ps1          # creates .venv with Python 3.12
.\.venv\Scripts\Activate.ps1     # activate it
.\scripts\verify_structure.ps1   # checks every folder exists
Copy-Item .env.example .env      # then fill in keys later, when a milestone needs them
.\scripts\git_init.ps1           # local Git repo + first commit
```

## Technology stack
Python 3.12 | FastAPI | Pydantic | Docling | Microsoft GraphRAG | Neo4j | MongoDB |
LangGraph | BGE-M3 embeddings | hosted LLM API | Next.js + TypeScript | DeepEval

## Golden rules
- Work **one milestone at a time**; do not jump ahead.
- **Raw data in `data/raw/` is never modified.** Normalized copies go in `data/processed/`.
- Never invent records, citations or test results.
- Install only the packages the current milestone needs.
- Never commit `.env`, `.venv` or large datasets (already in `.gitignore`).
- After every change update `CHANGELOG.md` and `PROJECT_STATUS.md`.

## Collectors (Milestone 3)
| Source | Status | Run |
|---|---|---|
| CISA KEV | validated on the real feed | `python ingestion\collectors\cisa_kev\collector.py` |
| NVD | validated on the real API (150 CVEs) | `python ingestion\collectors\nvd\collector.py` |
| MITRE ATT&CK | implemented, awaiting first run on your PC | `python ingestion\collectors\mitre_attack\collector.py` |
| CWE, CISA advisories | not started | - |

Details: `docs/pipeline/03_cisa_kev_collector.md`, `04_nvd_collector.md`, `05_mitre_attack_collector.md`.
Check results with `python scripts\check_kev_output.py`, `check_nvd_output.py` and `check_attack_output.py`.
Run unit tests: `python -m unittest discover -s tests\unit -v`.
