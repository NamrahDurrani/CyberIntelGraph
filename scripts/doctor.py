"""Project doctor: where is the project, is the environment right, is anything missing?

It answers the questions that went wrong when a terminal was opened in the wrong folder:
  - Where is the project (found from THIS file's location, so it works from any folder, on any drive)?
  - Is the terminal inside it? Is the project's virtual environment (.venv) the Python that is running?
  - Are the packages, scripts, collectors, tests, configuration and data in place?
  - Is the project inside OneDrive? Is there enough disk space? Does CYBERINTELGRAPH_HOME (the `cig` shortcut) point here?
  - Is .env present and is the NVD key set? (only yes/no is shown, never the key)

It uses only the Python standard library, so it runs even with the wrong Python.

Run it from anywhere:
    python <project folder>\\scripts\\doctor.py
or, after installing the shortcut, type:  cig doctor
Exit code 0 = no FAIL (warnings are advice), 1 = at least one FAIL.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "README.md", "requirements.txt", ".gitignore", ".env.example",
    "ingestion/collectors/cisa_kev/collector.py", "ingestion/collectors/nvd/collector.py",
    "ingestion/collectors/mitre_attack/collector.py", "ingestion/collectors/cwe/collector.py",
    "ingestion/collectors/advisories/collector.py", "ingestion/validation/audit_raw_data.py",
    "scripts/check_all_outputs.py", "config/dataset_targets.json",
]
REQUIRED_PACKAGES = {"requests": "requests", "bs4": "beautifulsoup4"}
RAW_AND_PROCESSED = {
    "CISA KEV": ("data/raw/cisa_kev", "data/processed/cisa_kev_normalized.json"),
    "NVD": ("data/raw/nvd", "data/processed/nvd_normalized.json"),
    "MITRE ATT&CK": ("data/raw/mitre_attack", "data/processed/attack_objects_normalized.json"),
    "CWE": ("data/raw/cwe", "data/processed/cwe_normalized.json"),
    "CISA advisories": ("data/raw/advisories", "data/processed/advisories_normalized.json"),
}


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, level: str, title: str, message: str) -> None:
        self.rows.append((level, title, message))

    def count(self, level: str) -> int:
        return sum(1 for r in self.rows if r[0] == level)


def venv_python(root: Path) -> Path:
    return root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def collect(root: Path, cwd: Path, env: dict, sys_prefix: str, sys_exe: str, py_version: tuple,
            free_bytes: int | None = None, git_info: tuple | None = None) -> Report:
    r = Report()

    # 1. is this a project folder, and where is it?
    missing_core = [f for f in ("README.md", "ingestion", "scripts") if not (root / f).exists()]
    if missing_core:
        r.add("FAIL", "Project folder", f"{root} does not look like the project (missing {missing_core})")
    else:
        r.add("OK", "Project folder", str(root))

    # 2. is the terminal inside it?
    try:
        cwd.resolve().relative_to(root.resolve())
        r.add("OK", "Terminal location", f"inside the project ({cwd})")
    except ValueError:
        r.add("WARN", "Terminal location", f"the terminal is in {cwd}, not in the project. Type 'cig' (or: cd \"{root}\") first, "
                                             "otherwise relative commands like python ingestion\\... cannot find their files")

    # 3. OneDrive / spaces / disk
    if "onedrive" in str(root).lower():
        r.add("WARN", "OneDrive", "the project is inside a OneDrive folder: OneDrive tries to sync the virtual environment and the data "
                                  "(thousands of files, hundreds of MB). A folder outside OneDrive, such as C:\\CyberIntelGraph, avoids that. "
                                  "See docs/PROJECT_LOCATION.md")
    if " " in str(root):
        r.add("INFO", "Path", "the path contains spaces: fine, but always put it in quotes in PowerShell")
    if free_bytes is not None:
        gb = free_bytes / 1024 ** 3
        r.add("WARN" if gb < 3 else "OK", "Disk space", f"{gb:.1f} GB free on the drive of the project" + (" (low: large installs such as Docling need several GB)" if gb < 3 else ""))

    # 4. Python and virtual environment
    wanted = (3, 12)
    r.add("OK" if tuple(py_version[:2]) == wanted else "WARN", "Python",
          f"{py_version[0]}.{py_version[1]} at {sys_exe}" + ("" if tuple(py_version[:2]) == wanted else " (the project is built for 3.12)"))
    expected_venv = (root / ".venv")
    if not expected_venv.is_dir():
        r.add("FAIL", "Virtual environment", f"{expected_venv} does not exist. Run: .\\scripts\\setup_env.ps1")
    elif Path(sys_prefix).resolve() == expected_venv.resolve():
        r.add("OK", "Virtual environment", "the project's .venv is the Python that is running")
    else:
        r.add("WARN", "Virtual environment", f"this Python is NOT the project's .venv (it is {sys_exe}). Activate it: .\\.venv\\Scripts\\Activate.ps1 (or type cig)")

    # 5. packages
    for module, package in REQUIRED_PACKAGES.items():
        if importlib.util.find_spec(module) is None:
            r.add("FAIL", f"Package {package}", f"not installed in this Python. Activate the .venv, then: python -m pip install -r requirements.txt")
        else:
            r.add("OK", f"Package {package}", "installed")

    # 6. files, tests
    missing = [f for f in REQUIRED_FILES if not (root / f).is_file()]
    r.add("FAIL" if missing else "OK", "Project files", f"missing: {missing}" if missing else f"all {len(REQUIRED_FILES)} key files present")
    tests = list((root / "tests" / "unit").glob("test_*.py")) if (root / "tests" / "unit").is_dir() else []
    r.add("OK" if tests else "FAIL", "Unit tests", f"{len(tests)} test file(s)" if tests else "tests\\unit has no test files (wrong folder, or the update was not extracted here?)")

    # 7. data
    for label, (raw, processed) in RAW_AND_PROCESSED.items():
        raw_dir, processed_file = root / raw, root / processed
        has_raw = raw_dir.is_dir() and any(p.name != ".gitkeep" for p in raw_dir.iterdir())
        if has_raw and processed_file.is_file():
            r.add("OK", f"Data: {label}", "raw and processed data present")
        elif has_raw:
            r.add("WARN", f"Data: {label}", "raw data present but the processed file is missing: run its collector again")
        else:
            r.add("INFO", f"Data: {label}", "no data yet: run its collector (data is not stored in Git, so a fresh clone starts empty)")

    # 8. .env (yes/no only)
    env_file = root / ".env"
    if not env_file.is_file():
        r.add("INFO", ".env", "not created yet (Copy-Item .env.example .env). Needed for the NVD API key")
    else:
        key_set = any(line.strip().startswith("NVD_API_KEY=") and line.strip() != "NVD_API_KEY=" and line.split("=", 1)[1].strip().strip("\"'")
                      for line in env_file.read_text(encoding="utf-8-sig").splitlines())
        r.add("OK" if key_set else "INFO", ".env", "present, NVD_API_KEY is set" if key_set else "present, NVD_API_KEY is empty (NVD still works, about 10x slower)")

    # 9. shortcut variable
    home = env.get("CYBERINTELGRAPH_HOME")
    if not home:
        r.add("INFO", "Shortcut 'cig'", "not installed. Run: .\\scripts\\install_shortcut.ps1 (then type cig in any new terminal)")
    elif Path(home).resolve() == root.resolve():
        r.add("OK", "Shortcut 'cig'", "CYBERINTELGRAPH_HOME points to this project")
    else:
        r.add("WARN", "Shortcut 'cig'", f"CYBERINTELGRAPH_HOME points to a DIFFERENT folder ({home}). Run .\\scripts\\install_shortcut.ps1 from this project to update it")

    # 10. git
    if git_info is None:
        r.add("INFO", "Git", "not a Git repository here (or git is not installed)")
    else:
        branch, changed = git_info
        r.add("OK", "Git", f"branch {branch}; {changed} uncommitted change(s)")
    return r


def gather_git(root: Path) -> tuple | None:
    if not (root / ".git").exists() or shutil.which("git") is None:
        return None
    try:
        branch = subprocess.run(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        changed = len(subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True, check=True).stdout.splitlines())
        return branch, changed
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    try:
        free = shutil.disk_usage(ROOT).free
    except OSError:
        free = None
    report = collect(ROOT, Path.cwd(), dict(os.environ), sys.prefix, sys.executable, sys.version_info[:3], free, gather_git(ROOT))
    print("Project doctor\n" + "-" * 70)
    for level, title, message in report.rows:
        print(f"  [{level:<4}] {title}: {message}")
    print("-" * 70)
    print(f"{report.count('FAIL')} FAIL, {report.count('WARN')} WARN, {report.count('INFO')} INFO, {report.count('OK')} OK")
    if report.count("FAIL"):
        print("RESULT: PROBLEMS FOUND (fix the FAIL lines first)")
        return 1
    print("RESULT: OK" + (" (read the WARN lines)" if report.count("WARN") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
