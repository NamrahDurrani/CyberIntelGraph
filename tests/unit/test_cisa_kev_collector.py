"""Unit tests for the CISA KEV collector's validation and normalization logic.

IMPORTANT: the records below are synthetic TEST FIXTURES (obviously fake CVE-1999-000x IDs).
They exist only to prove the validator works. They are never written to data/ and never
used as project data.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "kev_collector", ROOT / "ingestion" / "collectors" / "cisa_kev" / "collector.py")
kev = importlib.util.module_from_spec(spec)
sys.modules["kev_collector"] = kev  # required so @dataclass can resolve the module
spec.loader.exec_module(kev)

CTX = {"source_url": "https://example.test/kev.json", "retrieved_at": "2000-01-01T00:00:00+00:00",
       "raw_ref": "data/raw/cisa_kev/fixture.json"}


def fixture(cve="CVE-1999-0001", **overrides):
    record = {
        "cveID": cve, "vendorProject": "FixtureVendor", "product": "FixtureProduct",
        "vulnerabilityName": "Fixture vulnerability", "dateAdded": "2024-01-31",
        "shortDescription": "Synthetic test record.", "requiredAction": "None (test).",
        "dueDate": "2024-02-21", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-20"],
    }
    record.update(overrides)
    return record


class EnvelopeTests(unittest.TestCase):
    def test_valid_envelope(self):
        doc = {"title": "t", "catalogVersion": "v", "dateReleased": "d", "count": 1,
               "vulnerabilities": [fixture()]}
        errors, _ = kev.validate_envelope(doc)
        self.assertEqual(errors, [])

    def test_count_mismatch_is_error(self):
        doc = {"catalogVersion": "v", "dateReleased": "d", "count": 5, "vulnerabilities": [fixture()]}
        errors, _ = kev.validate_envelope(doc)
        self.assertTrue(any("Declared count" in e for e in errors))

    def test_missing_keys_and_empty_list(self):
        errors, _ = kev.validate_envelope({"vulnerabilities": []})
        self.assertTrue(any("catalogVersion" in e for e in errors))
        self.assertTrue(any("zero vulnerabilities" in e for e in errors))

    def test_not_an_object(self):
        errors, _ = kev.validate_envelope([])
        self.assertTrue(errors)


class RecordTests(unittest.TestCase):
    def test_valid_record_is_normalized_with_provenance(self):
        records, errors, warnings, dupes = kev.validate_and_normalize([fixture(cve=" cve-1999-0001 ")], CTX)
        self.assertEqual((errors, warnings, dupes), ([], [], 0))
        rec = records[0]
        self.assertEqual(rec["cve_id"], "CVE-1999-0001")
        self.assertIs(rec["known_ransomware_campaign_use"], True)
        self.assertEqual(rec["source_record_id"], "CVE-1999-0001")
        self.assertEqual(rec["raw_file_reference"], CTX["raw_ref"])
        self.assertEqual(rec["cwes"], ["CWE-20"])

    def test_bad_cve_format_rejected(self):
        records, errors, _, _ = kev.validate_and_normalize([fixture(cve="CVE-99-1")], CTX)
        self.assertEqual(records, [])
        self.assertTrue(any("invalid CVE ID" in e for e in errors))

    def test_missing_required_field_rejected(self):
        item = fixture()
        del item["product"]
        records, errors, _, _ = kev.validate_and_normalize([item], CTX)
        self.assertEqual(records, [])
        self.assertTrue(any("product" in e for e in errors))

    def test_bad_date_rejected(self):
        records, errors, _, _ = kev.validate_and_normalize([fixture(dateAdded="31/01/2024")], CTX)
        self.assertEqual(records, [])
        self.assertTrue(any("dateAdded" in e for e in errors))

    def test_duplicate_detected_first_kept(self):
        records, errors, _, dupes = kev.validate_and_normalize([fixture(), fixture()], CTX)
        self.assertEqual(len(records), 1)
        self.assertEqual(dupes, 1)
        self.assertTrue(any("duplicate" in e for e in errors))

    def test_missing_expected_field_is_warning_not_error(self):
        records, errors, warnings, _ = kev.validate_and_normalize([fixture(requiredAction="")], CTX)
        self.assertEqual(len(records), 1)
        self.assertEqual(errors, [])
        self.assertTrue(any("requiredAction" in w for w in warnings))

    def test_missing_cwes_key_gives_empty_list(self):
        item = fixture()
        del item["cwes"]
        records, errors, _, _ = kev.validate_and_normalize([item], CTX)
        self.assertEqual(errors, [])
        self.assertEqual(records[0]["cwes"], [])


class SubsetTests(unittest.TestCase):
    def test_ransomware_first_then_newest(self):
        items = [
            fixture("CVE-1999-0001", dateAdded="2024-01-01", knownRansomwareCampaignUse="Unknown"),
            fixture("CVE-1999-0002", dateAdded="2023-01-01", knownRansomwareCampaignUse="Known"),
            fixture("CVE-1999-0003", dateAdded="2024-06-01", knownRansomwareCampaignUse="Known"),
            fixture("CVE-1999-0004", dateAdded="2024-09-01", knownRansomwareCampaignUse="Unknown"),
        ]
        records, errors, _, _ = kev.validate_and_normalize(items, CTX)
        self.assertEqual(errors, [])
        subset, rule = kev.select_subset(records, 3)
        self.assertEqual([r["cve_id"] for r in subset], ["CVE-1999-0003", "CVE-1999-0002", "CVE-1999-0004"])
        self.assertIn("newest first", rule)

    def test_size_zero_disables(self):
        self.assertEqual(kev.select_subset([], 0)[0], [])


if __name__ == "__main__":
    unittest.main()
