"""Milestone 3 gate: run the five independent check scripts and print one summary table.

Each check re-reads the files on disk (it does not trust the collectors' own summaries). Milestone 3 is complete only
when all five say ALL CHECKS PASSED on your PC.

Run from the project root (venv active):
    python scripts\\check_all_outputs.py
Exit code 0 = all five passed, 1 = at least one failed or could not run.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = [
    ("CISA KEV", "check_kev_output.py", "python ingestion\\collectors\\cisa_kev\\collector.py"),
    ("NVD", "check_nvd_output.py", "python ingestion\\collectors\\nvd\\collector.py"),
    ("MITRE ATT&CK", "check_attack_output.py", "python ingestion\\collectors\\mitre_attack\\collector.py"),
    ("CWE", "check_cwe_output.py", "python ingestion\\collectors\\cwe\\collector.py"),
    ("CISA advisories", "check_advisories_output.py", "python ingestion\\collectors\\advisories\\collector.py"),
]


def main() -> int:
    rows = []
    for name, script, collector in CHECKS:
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=ROOT, capture_output=True, text=True)
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        passed = sum(1 for ln in lines if ln.startswith("[PASS]"))
        failed = [ln for ln in lines if ln.startswith("[FAIL]")]
        result = next((ln for ln in reversed(lines) if ln.startswith("RESULT:")), "")
        ok = proc.returncode == 0 and "ALL CHECKS PASSED" in result
        rows.append((name, ok, passed, failed, collector, proc.stderr.strip()))

    print("Milestone 3 gate\n" + "-" * 60)
    for name, ok, passed, failed, collector, stderr in rows:
        print(f"  {name:<16} {'PASS' if ok else 'FAIL'}   ({passed} checks passed, {len(failed)} failed)")
        for ln in failed[:3]:
            print(f"      {ln}")
        if not ok and not passed and not failed:
            print(f"      nothing to check yet. Run:  {collector}")
        if stderr:
            print(f"      error output: {stderr.splitlines()[-1]}")
    all_ok = all(ok for _, ok, *_ in rows)
    print("-" * 60)
    print("MILESTONE 3 GATE: " + ("ALL FIVE SOURCES PASSED" if all_ok else "NOT COMPLETE YET"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
