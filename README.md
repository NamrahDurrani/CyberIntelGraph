# CyberIntelGraph

Evidence-grounded, agentic **Cyber Threat Intelligence (CTI)** research system.

It collects intelligence from authoritative sources (NVD, CISA KEV, MITRE ATT&CK, CWE,
CISA advisories), builds one unified knowledge graph (Microsoft GraphRAG + Neo4j), and answers
research questions with citations, source URLs, dates and stated limitations - never with
unsupported claims.

> **Status:** Milestone 1 verified. Milestone 3 gate passed on the real sources; fixes from that run are delivered (CWE categories, advisory dates and discovery). Milestone 4 (raw data audit) is built. See `PROJECT_STATUS.md`.

## Start here (read in this order)
1. `docs/GETTING_STARTED.md`  - install Python 3.12, create the virtual environment, verify (and `docs/PROJECT_LOCATION.md` if your terminal ever cannot find files)
2. `docs/GITHUB_GUIDE.md`     - turn this folder into a GitHub repository
3. `docs/pipeline/00_milestone_roadmap.md` - the 18 milestones, one by one, with run commands
4. `docs/architecture/folder_guide.md` - what every folder is for

## Quick start (Windows PowerShell)
First time only. Open PowerShell **in the project folder** (the folder that contains this README). The project works from any folder or drive:
```powershell
.\scripts\setup_env.ps1          # creates .venv with Python 3.12
.\.venv\Scripts\Activate.ps1     # activate it
.\scripts\verify_structure.ps1   # checks every folder exists
Copy-Item .env.example .env      # then fill in keys later, when a milestone needs them
.\scripts\install_shortcut.ps1   # once: registers the command  cig
.\scripts\git_init.ps1           # local Git repo + first commit
```
**Every day after that:** open a new terminal anywhere and type `cig` (goes to the project and activates the environment), or `cig doctor` (also runs the health check).
Lost? `python <project folder>\scripts\doctor.py` tells you what is wrong. See `docs/PROJECT_LOCATION.md`.

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
| MITRE ATT&CK | validated on your PC (release 20.0) | `python ingestion\collectors\mitre_attack\collector.py` |
| CWE | validated on your PC (v5.0); category fix delivered, re-run to confirm | `python ingestion\collectors\cwe\collector.py` |
| CISA advisories | validated on your PC (46 documents); date fix and `--discover` delivered | `python ingestion\collectors\advisories\collector.py --discover https://www.cisa.gov/news-events/cybersecurity-advisories --discover-pages 5` |

Details: `docs/pipeline/03_cisa_kev_collector.md`, `04_nvd_collector.md`, `05_mitre_attack_collector.md`, `06_cwe_collector.md`, `07_advisories_collector.md`.
Check results with `python scripts\check_kev_output.py`, `check_nvd_output.py`, `check_attack_output.py`, `check_cwe_output.py` and `check_advisories_output.py`.
Milestone 3 gate (all five at once): `python scripts\check_all_outputs.py`.
Run unit tests: `python -m unittest discover -s tests\unit -v`.

## Milestone 4: raw data audit
One command audits all five sources together (raw integrity, freshness, targets, cross-source checks, field inventory, Git hygiene, check scripts, documentation):
`python ingestion\validation\audit_raw_data.py --write-doc`. Details: `docs/pipeline/08_raw_data_audit.md`. Optional: `.\scripts\protect_raw_data.ps1` makes raw files read-only.
