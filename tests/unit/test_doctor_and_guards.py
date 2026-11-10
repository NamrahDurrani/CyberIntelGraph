"""Tests for scripts/doctor.py and for the friendly import guards in the collectors.

All data is synthetic and lives in temporary folders.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("doctor", ROOT / "scripts" / "doctor.py")
doctor = importlib.util.module_from_spec(spec)
sys.modules["doctor"] = doctor
spec.loader.exec_module(doctor)


def make_project(base: Path, with_venv=True, with_tests=True) -> Path:
    root = base / "proj"
    for rel in doctor.REQUIRED_FILES:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x", encoding="utf-8")
    (root / "scripts").mkdir(exist_ok=True)
    if with_venv:
        (root / ".venv").mkdir(exist_ok=True)
    if with_tests:
        (root / "tests/unit").mkdir(parents=True, exist_ok=True)
        (root / "tests/unit/test_x.py").write_text("x", encoding="utf-8")
    return root


def levels(report, title_start):
    return [lvl for lvl, title, _ in report.rows if title.startswith(title_start)]


def run(root, cwd=None, env=None, prefix=None, exe="python", version=(3, 12, 10), free=50 * 1024 ** 3, git=None):
    return doctor.collect(root, cwd or root, env or {}, prefix or str(root / ".venv"), exe, version, free, git)


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_healthy_project(self):
        report = run(make_project(self.base))
        self.assertEqual(levels(report, "Project folder"), ["OK"])
        self.assertEqual(levels(report, "Terminal location"), ["OK"])
        self.assertEqual(levels(report, "Virtual environment"), ["OK"])
        self.assertEqual(levels(report, "Project files"), ["OK"])
        self.assertEqual(levels(report, "Unit tests"), ["OK"])

    def test_terminal_in_another_folder_is_a_warning_with_the_fix(self):
        root = make_project(self.base)
        other = self.base / "elsewhere"
        other.mkdir()
        report = run(root, cwd=other)
        self.assertEqual(levels(report, "Terminal location"), ["WARN"])
        self.assertIn("cig", next(m for l, t, m in report.rows if t == "Terminal location"))

    def test_empty_folder_is_not_a_project(self):
        empty = self.base / "empty"
        empty.mkdir()
        report = run(empty)
        self.assertEqual(levels(report, "Project folder"), ["FAIL"])
        self.assertEqual(levels(report, "Project files"), ["FAIL"])
        self.assertEqual(levels(report, "Unit tests"), ["FAIL"])
        self.assertEqual(levels(report, "Virtual environment"), ["FAIL"])

    def test_global_python_instead_of_the_venv(self):
        report = run(make_project(self.base), prefix=str(self.base / "global_python"))
        self.assertEqual(levels(report, "Virtual environment"), ["WARN"])
        self.assertIn("NOT the project's .venv", next(m for l, t, m in report.rows if t == "Virtual environment"))

    def test_missing_venv_is_a_fail(self):
        report = run(make_project(self.base, with_venv=False))
        self.assertEqual(levels(report, "Virtual environment"), ["FAIL"])

    def test_wrong_python_version_is_a_warning(self):
        self.assertEqual(levels(run(make_project(self.base), version=(3, 13, 1)), "Python"), ["WARN"])
        self.assertEqual(levels(run(make_project(self.base), version=(3, 12, 10)), "Python"), ["OK"])

    def test_onedrive_and_spaces_are_flagged(self):
        root = make_project(self.base / "OneDrive" / "My Projects")
        report = run(root)
        self.assertEqual(levels(report, "OneDrive"), ["WARN"])
        self.assertEqual(levels(report, "Path"), ["INFO"])
        self.assertEqual(levels(run(make_project(self.base / "plain")), "OneDrive"), [])

    def test_low_disk_space(self):
        self.assertEqual(levels(run(make_project(self.base), free=1 * 1024 ** 3), "Disk space"), ["WARN"])

    def test_shortcut_variable_states(self):
        root = make_project(self.base)
        self.assertEqual(levels(run(root, env={}), "Shortcut"), ["INFO"])
        self.assertEqual(levels(run(root, env={"CYBERINTELGRAPH_HOME": str(root)}), "Shortcut"), ["OK"])
        self.assertEqual(levels(run(root, env={"CYBERINTELGRAPH_HOME": str(self.base / "old")}), "Shortcut"), ["WARN"])

    def test_env_file_never_shows_the_key(self):
        root = make_project(self.base)
        (root / ".env").write_text("NVD_API_KEY=super-secret-value\n", encoding="utf-8")
        report = run(root)
        self.assertEqual(levels(report, ".env"), ["OK"])
        self.assertNotIn("super-secret-value", " ".join(m for _, _, m in report.rows))
        (root / ".env").write_text("NVD_API_KEY=\n", encoding="utf-8")
        self.assertEqual(levels(run(root), ".env"), ["INFO"])

    def test_data_states(self):
        root = make_project(self.base)
        (root / "data/raw/cisa_kev").mkdir(parents=True)
        (root / "data/raw/cisa_kev/a.json").write_text("{}", encoding="utf-8")
        (root / "data/raw/nvd").mkdir(parents=True)
        (root / "data/raw/nvd/.gitkeep").write_text("", encoding="utf-8")
        report = run(root)
        self.assertEqual(levels(report, "Data: CISA KEV"), ["WARN"])   # raw without processed
        self.assertEqual(levels(report, "Data: NVD"), ["INFO"])        # only a placeholder
        (root / "data/processed").mkdir(parents=True)
        (root / "data/processed/cisa_kev_normalized.json").write_text("{}", encoding="utf-8")
        self.assertEqual(levels(run(root), "Data: CISA KEV"), ["OK"])

    def test_git_info(self):
        root = make_project(self.base)
        self.assertEqual(levels(run(root, git=("main", 3)), "Git"), ["OK"])
        self.assertEqual(levels(run(root, git=None), "Git"), ["INFO"])


class GuardTests(unittest.TestCase):
    """If requests / bs4 are missing (for example the global Python is used), the collectors must explain, not crash."""

    COLLECTORS = ("cisa_kev", "nvd", "mitre_attack", "cwe", "advisories")

    def load_without(self, name: str, hidden: str):
        spec = importlib.util.spec_from_file_location(f"guard_{name}", ROOT / "ingestion" / "collectors" / name / "collector.py")
        module = importlib.util.module_from_spec(spec)
        saved = {k: sys.modules.get(k) for k in (hidden, f"guard_{name}")}
        sys.modules[hidden] = None            # makes "import <hidden>" raise ImportError
        sys.modules[f"guard_{name}"] = module
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                with self.assertRaises(SystemExit) as ctx:
                    spec.loader.exec_module(module)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        return ctx.exception.code, err.getvalue()

    def test_every_collector_explains_a_missing_requests(self):
        for name in self.COLLECTORS:
            code, message = self.load_without(name, "requests")
            self.assertEqual(code, 2, name)
            self.assertIn("Activate the project environment", message, name)
            self.assertIn("requirements.txt", message, name)

    def test_advisories_also_explains_a_missing_beautifulsoup(self):
        code, message = self.load_without("advisories", "bs4")
        self.assertEqual(code, 2)
        self.assertIn("beautifulsoup4", message)


if __name__ == "__main__":
    unittest.main()
