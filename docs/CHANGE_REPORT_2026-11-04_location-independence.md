# Change Report: location-independent tooling (2026-11-04)

## What happened
Your terminal was in `C:\Users\User\OneDrive\Desktop\My Projects\CyberIntelGraph`, a folder with no `ingestion\`, `tests\` or `.venv`.
The update had been extracted into `C:\CyberIntelGraph` because my command named that folder explicitly. So:
| Command | Result | Why |
|---|---|---|
| `.\.venv\Scripts\Activate.ps1` | not recognized | no `.venv` in that folder |
| `python -m unittest discover -s tests\unit` | `Ran 0 tests / NO TESTS RAN` | no `tests\unit` in that folder |
| `python ingestion\collectors\cwe\collector.py` etc. | `[Errno 2] No such file or directory` | no `ingestion\` in that folder |
| `cd "$HOME\CyberIntelGraph"` | path not found | the project is not under `$HOME` |

Nothing was broken or lost. The commands ran in the wrong place, and the global Python (not the project's `.venv`) was the one running.

## Root cause
My instructions repeated the fixed path `C:\CyberIntelGraph` in many places. The **code** never depended on it (Python files find the project from their own location, PowerShell scripts from `$PSScriptRoot`),
but the **instructions and your terminal** did. When the location changed, the two disagreed.

## Changes
| Change | File | Effect |
|---|---|---|
| Project doctor | `scripts/doctor.py` | Works from any folder with any Python. Reports project folder, whether the terminal is inside it, whether `.venv` is the running Python, Python version, packages, key files, tests, data per source, `.env` (yes/no only), disk space, OneDrive, shortcut variable, Git. Exit 1 only on FAIL |
| `cig` shortcut | `scripts/install_shortcut.ps1` | Run once. Stores the project folder in `CYBERINTELGRAPH_HOME` and adds a `cig` function to your PowerShell profile: `cig` goes to the project and activates `.venv`; `cig doctor` also runs the health check. `-Remove` uninstalls. Re-run it after a move |
| Friendly guard | all five `collector.py` files | If `requests` / `beautifulsoup4` is missing (global Python), the collector explains how to activate the environment and exits with code 2 instead of a traceback |
| Location guide | `docs/PROJECT_LOCATION.md` | Symptoms table, `cig`, the doctor, the OneDrive trade-off, the exact move procedure (venv recreated, data copied, audit proves the raw data survived), VS Code tip |
| Docs without hard-coded paths | README, GETTING_STARTED, GITHUB_GUIDE, all pipeline pages, roadmap, PROJECT_GUIDE | `cd C:\CyberIntelGraph` became `cig`; first-time steps say "open PowerShell in the project folder"; extraction commands use a `$project` variable |
| Tests | `tests/unit/test_doctor_and_guards.py` | 14 new tests (doctor states, `.env` never printed, OneDrive and shortcut cases, collector guards) |

## Tested
- 143 unit tests pass (129 + 14), also with deprecation warnings treated as errors.
- Simulation: project copied under a `OneDrive/Desktop/My Projects` path with spaces, terminal in a different empty folder: the doctor reported the project folder, the terminal warning, the OneDrive warning, the spaces note and the missing `.venv`.
- A collector run with `requests` made unavailable printed the activation guidance and exited with code 2.
- **Not tested here:** `install_shortcut.ps1` and `protect_raw_data.ps1` (no PowerShell in my environment). They are short and avoid anything unusual; the doctor tells you whether `cig` is installed and pointing at the right folder.

## Where is your project, and what to do now
See the reply: two commands tell you whether the project is at `C:\CyberIntelGraph` (most likely) or elsewhere, and what to do in each case.
