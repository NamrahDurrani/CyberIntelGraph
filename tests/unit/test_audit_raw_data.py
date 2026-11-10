"""Unit tests for the Milestone 4 raw data audit (ingestion/validation/audit_raw_data.py).

IMPORTANT: all data below is a synthetic TEST FIXTURE written into temporary folders (fake CVE-1999-xxxx ids,
'Fixture' names). It is never written into the real data/ folder.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("audit", ROOT / "ingestion" / "validation" / "audit_raw_data.py")
audit = importlib.util.module_from_spec(spec)
sys.modules["audit"] = audit
spec.loader.exec_module(audit)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


def iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


class TempProject(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        for p in self.root.rglob("*"):  # make sure read-only test files can be removed on any OS
            if p.is_file():
                os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        self.tmp.cleanup()

    def add_kev_raw(self, content=b'{"vulnerabilities": []}', days_ago=1.0, name="kev_raw_a.json", tamper=False, record_sha=None):
        raw = self.root / "data/raw/cisa_kev"
        write(raw / name, content)
        meta = {"raw_file": name, "sha256": record_sha or sha(content), "bytes": len(content), "retrieved_at": iso(days_ago)}
        write(raw / (name[:-5] + ".meta.json"), json.dumps(meta))
        if tamper:
            write(raw / name, content + b" ")


class FileAuditTests(TempProject):
    def test_clean_source_is_verified(self):
        self.add_kev_raw()
        findings = audit.Findings()
        info = audit.audit_files(self.root, "kev", findings)
        self.assertEqual((info["entries"], info["verified_ok"], info["missing"], info["mismatched"], info["orphans"]), (1, 1, [], [], []))
        self.assertEqual(findings.count("FAIL"), 0)
        self.assertLess(info["age_days"], 2)

    def test_changed_file_is_a_fail(self):
        self.add_kev_raw(tamper=True)
        findings = audit.Findings()
        info = audit.audit_files(self.root, "kev", findings)
        self.assertEqual(info["mismatched"], ["kev_raw_a.json"])
        self.assertEqual(findings.count("FAIL"), 1)

    def test_missing_file_is_a_fail(self):
        self.add_kev_raw()
        (self.root / "data/raw/cisa_kev/kev_raw_a.json").unlink()
        findings = audit.Findings()
        info = audit.audit_files(self.root, "kev", findings)
        self.assertEqual(info["missing"], ["kev_raw_a.json"])
        self.assertEqual(findings.count("FAIL"), 1)

    def test_orphan_and_duplicate_content(self):
        self.add_kev_raw(name="kev_raw_a.json")
        self.add_kev_raw(name="kev_raw_b.json")          # same bytes under another name
        write(self.root / "data/raw/cisa_kev/stray.json", "{}")
        write(self.root / "data/raw/cisa_kev/.gitkeep", "")
        findings = audit.Findings()
        info = audit.audit_files(self.root, "kev", findings)
        self.assertEqual(info["orphans"], ["stray.json"])
        self.assertEqual(info["duplicate_content"], [["kev_raw_a.json", "kev_raw_b.json"]])
        self.assertEqual(findings.count("FAIL"), 0)

    def test_read_only_files_are_counted(self):
        self.add_kev_raw()
        os.chmod(self.root / "data/raw/cisa_kev/kev_raw_a.json", stat.S_IREAD)
        info = audit.audit_files(self.root, "kev", audit.Findings())
        if os.name == "nt" or os.geteuid() != 0:  # root ignores permission bits
            self.assertEqual(info["read_only_files"], 1)

    def test_no_downloads_is_a_warning_when_folder_empty(self):
        (self.root / "data/raw/cisa_kev").mkdir(parents=True)
        findings = audit.Findings()
        audit.audit_files(self.root, "kev", findings)
        self.assertEqual((findings.count("WARN"), findings.count("FAIL")), (1, 0))

    def test_manifest_sources_are_verified(self):
        raw = self.root / "data/raw/nvd"
        content = b'{"x": 1}'
        write(raw / "CVE-1999-0001__a.json", content)
        write(raw / "manifest.jsonl", json.dumps({"cve_id": "CVE-1999-0001", "raw_file": "CVE-1999-0001__a.json",
                                                  "sha256": sha(content), "bytes": len(content), "retrieved_at": iso(2), "outcome": "ok"}) + "\n")
        info = audit.audit_files(self.root, "nvd", audit.Findings())
        self.assertEqual((info["entries"], info["verified_ok"], info["orphans"]), (1, 1, []))

    def test_freshness_warning(self):
        self.add_kev_raw(days_ago=45)
        findings = audit.Findings()
        files = {"kev": audit.audit_files(self.root, "kev", findings)}
        audit.freshness_findings(files, 30, findings)
        self.assertEqual(findings.count("WARN"), 1)
        audit.freshness_findings(files, 60, audit.Findings())


class TargetTests(unittest.TestCase):
    def test_status_values(self):
        targets = [{"source": "nvd", "metric": "records", "min": 150, "max": 200, "note": "n"},
                   {"source": "advisories", "metric": "documents", "min": 50, "max": 75, "note": "a"},
                   {"source": "kev", "metric": "initial_subset_records", "min": 50, "max": 75, "note": "k"},
                   {"source": "cwe", "metric": "initial_subset_records", "min": 1, "max": None, "note": "c"},
                   {"source": "attack", "metric": "objects", "min": 1, "max": None, "note": "t"}]
        stats = {"nvd": {"records": 150}, "advisories": {"documents": 46}, "kev": {"initial_subset_records": 80},
                 "cwe": {"initial_subset_records": 9999}}
        rows = {r["source"]: r["status"] for r in audit.evaluate_targets(targets, stats)}
        self.assertEqual(rows, {"nvd": "MET", "advisories": "BELOW", "kev": "ABOVE", "cwe": "MET", "attack": "NO DATA"})

    def test_real_targets_file_is_valid(self):
        doc = json.loads((ROOT / "config" / "dataset_targets.json").read_text(encoding="utf-8"))
        for t in doc["targets"]:
            self.assertIn(t["source"], audit.SOURCES)
            self.assertIsInstance(t["min"], int)


class CrossCheckTests(unittest.TestCase):
    def data(self, **over):
        base = {"kev_ids": {"CVE-1999-0001", "CVE-1999-0002", "CVE-1999-0003"}, "kev_subset_ids": {"CVE-1999-0001", "CVE-1999-0002"},
                "nvd_ids": {"CVE-1999-0001", "CVE-1999-0002"}, "cwe_ids": {"CWE-20", "CWE-79"},
                "nvd_cwe_ids": {"CWE-20", "CWE-264"}, "kev_cwe_ids": {"CWE-79"}, "adv_cwe_ids": {"CWE-20"},
                "adv_cve_ids": {"CVE-1999-0001", "CVE-1999-0003", "CVE-1999-0099"},
                "adv_attack_ids": {"T1190", "T9999"}, "attack_technique_ids": {"T1190"},
                "nvd_cisa_vs_kev": [("CVE-1999-0001", "2024-01-01", "2024-01-01", "2024-02-01", "2024-02-01"),
                                    ("CVE-1999-0002", "2024-03-01", "2024-03-05", None, "2024-04-01"),
                                    ("CVE-1999-0003", None, "2024-05-01", None, "2024-06-01")]}
        base.update(over)
        return base

    def test_numbers(self):
        out = audit.cross_checks(self.data())
        self.assertEqual(out["nvd_in_kev"], {"matched": 2, "total": 2})
        self.assertEqual(out["kev_subset_in_nvd"], {"matched": 2, "total": 2})
        self.assertEqual(out["nvd_cwe_in_catalog"]["missing"], ["CWE-264"])
        self.assertEqual(out["advisory_cves"], {"total": 3, "in_kev": 2, "in_nvd_set": 1, "in_neither": 1,
                                                "not_in_kev_examples": ["CVE-1999-0099"]})
        self.assertEqual(out["advisory_attack_ids"]["unknown"], ["T9999"])
        self.assertEqual(out["advisory_attack_ids"]["ics_matrix_count"], 0)
        self.assertEqual(out["nvd_cisa_dates"]["compared"], 2)
        self.assertEqual(out["nvd_cisa_dates"]["records_without_field"], 1)
        self.assertEqual(out["nvd_cisa_dates"]["added_mismatch"], [("CVE-1999-0002", "2024-03-01", "2024-03-05")])

    def test_ics_ids_are_classified_not_flagged(self):
        out = audit.cross_checks(self.data(adv_attack_ids={"T1190", "T0801", "T0812"}))
        c = out["advisory_attack_ids"]
        self.assertEqual((c["ics_matrix"], c["ics_matrix_count"], c["unknown_count"]), (["T0801", "T0812"], 2, 0))
        findings = audit.Findings()
        audit.cross_findings({"advisory_attack_ids": c}, findings)
        self.assertEqual([f["severity"] for f in findings.items], ["INFO"])

    def test_findings_have_the_right_severity(self):
        findings = audit.Findings()
        audit.cross_findings(audit.cross_checks(self.data()), findings)
        severities = Counter(f["severity"] for f in findings.items)
        self.assertEqual(severities["FAIL"], 0)
        self.assertGreaterEqual(severities["WARN"], 3)  # missing CWE id, unknown ATT&CK id, NVD/KEV date mismatch

    def test_missing_sources_are_tolerated(self):
        empty = {k: (set() if k != "nvd_cisa_vs_kev" else []) for k in self.data()}
        self.assertEqual(audit.cross_checks(empty), {})


class FieldInventoryTests(unittest.TestCase):
    def test_diff_fields(self):
        d = audit.diff_fields(Counter({"a": 5, "b": 3, "cisaX": 2, "z": 1}), {"a", "q"}, "cisa")
        self.assertEqual(d["used"], ["a", "cisaX"])
        self.assertEqual(d["ignored"], {"b": 3, "z": 1})
        self.assertEqual(d["used_but_never_seen"], ["q"])

    def test_inventory_kev_from_raw(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        content = json.dumps({"title": "t", "catalogVersion": "v", "dateReleased": "d", "count": 1,
                              "vulnerabilities": [{"cveID": "CVE-1999-0001", "vendorProject": "v", "extraField": 1}]}).encode()
        write(root / "data/raw/cisa_kev/a.json", content)
        write(root / "data/raw/cisa_kev/a.meta.json", json.dumps({"raw_file": "a.json", "sha256": sha(content), "bytes": len(content), "retrieved_at": iso(1)}))
        inv = audit.inventory_kev(root)
        self.assertEqual(inv["records"], 1)
        self.assertEqual(inv["record"]["ignored"], {"extraField": 1})
        self.assertIn("dateAdded", inv["record"]["used_but_never_seen"])
        tmp.cleanup()

    def test_never_seen_only_counts_fields_missing_everywhere(self):
        self.assertEqual(audit.never_seen({"a", "b", "c"}, {"a", "c"}), ["b"])

    def test_cwe_inventory_reports_only_source_wide_gaps(self):
        import io, zipfile
        xml = (b'<Weakness_Catalog xmlns="urn:x" Name="n" Version="1"><Weaknesses>'
               b'<Weakness ID="1" Name="w" Status="Draft"><Description>d</Description></Weakness></Weaknesses>'
               b'<Categories><Category ID="2" Name="c" Status="Draft"><Summary>s</Summary></Category></Categories></Weakness_Catalog>')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("cwec_v1.xml", xml)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "data/raw/cwe/a.zip", buf.getvalue())
            write(root / "data/raw/cwe/a.meta.json", json.dumps({"raw_file": "a.zip", "sha256": sha(buf.getvalue()),
                                                                 "bytes": len(buf.getvalue()), "retrieved_at": iso(1)}))
            inv = audit.inventory_cwe(root)
        gaps = inv["never_seen_anywhere"]
        self.assertIn("Abstraction", gaps)            # no entry has it
        self.assertIn("Extended_Description", gaps)   # no entry has it
        self.assertNotIn("Description", gaps)         # seen on weaknesses
        self.assertNotIn("Summary", gaps)             # seen on categories (not on weaknesses: that is normal)

    def test_attack_inventory_unions_the_types(self):
        def obj(t, n, **extra):
            return {"type": t, "id": f"{t}--{n}", "name": "x", **extra}
        bundle = json.dumps({"type": "bundle", "objects": [
            obj("malware", 1, x_mitre_aliases=["a"]), obj("intrusion-set", 2, aliases=["b"]),
            obj("malware", 3, revoked=True, x_mitre_platforms=["Windows"])]}).encode()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "data/raw/mitre_attack/b.json", bundle)
            write(root / "data/raw/mitre_attack/b.meta.json", json.dumps({"raw_file": "b.json", "sha256": sha(bundle), "bytes": len(bundle),
                                                                          "retrieved_at": iso(1), "kind": "bundle", "attack_version": "1.0"}))
            inv = audit.inventory_attack(root)
        gaps = inv["never_seen_anywhere"]
        self.assertNotIn("aliases", gaps)             # seen on intrusion-set
        self.assertNotIn("x_mitre_aliases", gaps)     # seen on malware
        self.assertIn("x_mitre_platforms", gaps)      # only on a revoked object, which is not normalized
        self.assertIn("kill_chain_phases", gaps)


class StorageHygieneTests(TempProject):
    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                              capture_output=True, text=True, check=True)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_tracked_data_file_is_a_fail_and_clean_repo_passes(self):
        self.git("init", "-q")
        write(self.root / ".gitignore", ".env\ndata/**\n!data/**/\n!data/**/.gitkeep\n")
        write(self.root / "data/raw/.gitkeep", "")
        write(self.root / "data/raw/secret.json", "{}")
        self.git("add", "-A")
        self.git("add", "-f", "data/raw/secret.json")      # simulates a forced add of data
        findings = audit.Findings()
        info = audit.git_hygiene(self.root, findings)
        self.assertEqual(info["tracked_data_files"], ["data/raw/secret.json"])
        self.assertEqual(findings.count("FAIL"), 1)
        self.git("rm", "--cached", "-q", "data/raw/secret.json")
        findings = audit.Findings()
        info = audit.git_hygiene(self.root, findings)
        self.assertEqual((info["tracked_data_files"], info["env_ignored"], findings.count("FAIL")), ([], True, 0))

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_env_not_ignored_is_a_fail(self):
        self.git("init", "-q")
        write(self.root / ".gitignore", "data/**\n")
        findings = audit.Findings()
        audit.git_hygiene(self.root, findings)
        self.assertTrue(any(".env is not ignored" in f["message"] for f in findings.items))

    def test_not_a_repository_is_info(self):
        findings = audit.Findings()
        audit.git_hygiene(self.root, findings)
        self.assertEqual((findings.count("FAIL"), findings.count("INFO")), (0, 1))


class DocsStatusTests(TempProject):
    def test_not_verified_marker_is_detected(self):
        doc = self.root / "docs/data_dictionary"
        write(doc / "cisa_kev.md", "| Verified on your PC? | **NO - update later** |\n")
        write(doc / "nvd.md", "| Verified on your PC? | **YES** (collector and checks) |\n")
        findings = audit.Findings()
        status = audit.docs_status(self.root, findings)
        self.assertEqual((status["kev"], status["nvd"], status["cwe"]), ("not verified", "ok", "missing"))


class EndToEndTests(TempProject):
    def test_audit_on_a_tiny_project_and_markdown_output(self):
        self.add_kev_raw(content=json.dumps({"vulnerabilities": [{"cveID": "CVE-1999-0001"}]}).encode())
        write(self.root / "config/dataset_targets.json", json.dumps({"targets": [
            {"source": "kev", "metric": "initial_subset_records", "min": 1, "max": 5, "note": "k"}]}))
        record = {"cve_id": "CVE-1999-0001", "date_added": "2024-01-01", "due_date": "2024-02-01", "cwes": []}
        write(self.root / "data/processed/cisa_kev_normalized.json", json.dumps({"metadata": {"catalog_version": "v1", "catalog_date_released": "2024"}, "records": [record]}))
        write(self.root / "data/processed/cisa_kev_initial_subset.json", json.dumps({"metadata": {}, "records": [record]}))
        report = audit.run_audit(self.root, fast=True, skip_checks=True)
        self.assertEqual(report["summary"]["fail"], 0)
        self.assertEqual(report["processed"]["kev"]["records"], 1)
        self.assertEqual(report["targets"][0]["status"], "MET")
        self.assertIn("kev", report["fields"])
        text = audit.render_markdown(report)
        for heading in ("# Raw Data Audit", "## 1. Raw files per source", "## 5. Field inventory", "## 8. Findings"):
            self.assertIn(heading, text)
        json.dumps(report)  # must be serializable

    def test_main_writes_report_and_doc_and_sets_exit_code(self):
        self.add_kev_raw(tamper=True)
        code = audit.main(["--root", str(self.root), "--fast", "--skip-checks", "--write-doc"])
        self.assertEqual(code, 1)  # a changed raw file is a FAIL
        self.assertTrue(list((self.root / "outputs/reports").glob("raw_data_audit_*.json")))
        self.assertTrue((self.root / "docs/data_dictionary/RAW_DATA_AUDIT.md").is_file())


if __name__ == "__main__":
    unittest.main()
