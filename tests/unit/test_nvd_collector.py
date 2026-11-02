"""Unit tests for the NVD collector's validation and normalization logic.

IMPORTANT: the records below are synthetic TEST FIXTURES (obviously fake CVE-1999-000x IDs, fake vendor).
They only prove the code handles the documented NVD CVE API 2.0 structure. They are never written to data/.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("nvd_collector", ROOT / "ingestion" / "collectors" / "nvd" / "collector.py")
nvd = importlib.util.module_from_spec(spec)
sys.modules["nvd_collector"] = nvd  # required so @dataclass can resolve the module
spec.loader.exec_module(nvd)


def cve_fixture(cve_id="CVE-1999-0001"):
    return {
        "id": cve_id, "sourceIdentifier": "fixture@example.test", "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000", "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "es", "value": "descripcion"}, {"lang": "en", "value": "  Fixture description.  "}],
        "metrics": {
            "cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                               "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                                            "vectorString": "CVSS:3.1/AV:N"}}],
            "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
                              "cvssData": {"version": "2.0", "baseScore": 7.5, "vectorString": "AV:N"}}],
        },
        "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-20"}]}],
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:fixture_vendor:fixture_product:1.0:*:*:*:*:*:*:*",
             "matchCriteriaId": "AAAA"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:fixture_vendor:fixture_product:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "2.0", "matchCriteriaId": "BBBB"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:other_vendor:other_os:-:*:*:*:*:*:*:*",
             "matchCriteriaId": "CCCC"},
        ]}]}],
        "references": [{"url": "https://example.test/advisory", "source": "fixture@example.test", "tags": ["Vendor Advisory"]}],
    }


def response_fixture(cve=None, total=1):
    vulns = [{"cve": cve}] if cve else []
    return {"resultsPerPage": len(vulns), "startIndex": 0, "totalResults": total, "format": "NVD_CVE",
            "version": "2.0", "timestamp": "2024-01-01T00:00:00.000", "vulnerabilities": vulns}


ENTRY = {"request_url": "https://example.test/api?cveId=CVE-1999-0001", "retrieved_at": "2024-01-01T00:00:00+00:00",
         "raw_file": "CVE-1999-0001__fixture.json"}


class ValidationTests(unittest.TestCase):
    def test_valid_response(self):
        outcome, cve, errors, warnings = nvd.validate_response(response_fixture(cve_fixture()), "CVE-1999-0001")
        self.assertEqual((outcome, errors, warnings), ("ok", [], []))
        self.assertEqual(cve["id"], "CVE-1999-0001")

    def test_zero_results_is_no_record_not_an_error(self):
        outcome, cve, errors, _ = nvd.validate_response(response_fixture(None, total=0), "CVE-1999-0001")
        self.assertEqual((outcome, cve, errors), ("no_record", None, []))

    def test_envelope_key_missing_is_invalid(self):
        doc = response_fixture(cve_fixture())
        del doc["totalResults"]
        outcome, _, errors, _ = nvd.validate_response(doc, "CVE-1999-0001")
        self.assertEqual(outcome, "invalid")
        self.assertTrue(any("totalResults" in e for e in errors))

    def test_wrong_id_returned_is_invalid(self):
        outcome, _, errors, _ = nvd.validate_response(response_fixture(cve_fixture("CVE-1999-0002")), "CVE-1999-0001")
        self.assertEqual(outcome, "invalid")
        self.assertTrue(any("requested" in e for e in errors))

    def test_missing_published_is_invalid(self):
        cve = cve_fixture()
        del cve["published"]
        outcome, _, errors, _ = nvd.validate_response(response_fixture(cve), "CVE-1999-0001")
        self.assertEqual(outcome, "invalid")
        self.assertTrue(any("published" in e for e in errors))

    def test_no_english_description_is_warning(self):
        cve = cve_fixture()
        cve["descriptions"] = [{"lang": "es", "value": "solo espanol"}]
        outcome, _, _, warnings = nvd.validate_response(response_fixture(cve), "CVE-1999-0001")
        self.assertEqual(outcome, "ok")
        self.assertTrue(any("English" in w for w in warnings))

    def test_not_an_object(self):
        self.assertEqual(nvd.validate_response([], "CVE-1999-0001")[0], "invalid")


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.rec = nvd.normalize_record(cve_fixture(), ENTRY)

    def test_description_and_provenance(self):
        self.assertEqual(self.rec["description_en"], "Fixture description.")
        self.assertEqual(self.rec["source_record_id"], "CVE-1999-0001")
        self.assertEqual(self.rec["published_at"], "2024-01-01T00:00:00.000")
        self.assertEqual(self.rec["last_modified_at"], "2024-02-01T00:00:00.000")
        self.assertEqual(self.rec["raw_file_reference"], "data/raw/nvd/CVE-1999-0001__fixture.json")

    def test_cvss_primary_prefers_newest_version_and_keeps_all(self):
        self.assertEqual(self.rec["cvss_primary"]["version"], "3.1")
        self.assertEqual(self.rec["cvss_primary"]["base_score"], 9.8)
        self.assertEqual(len(self.rec["cvss_metrics_all"]), 2)

    def test_cvss_v2_severity_comes_from_item(self):
        v2 = [m for m in self.rec["cvss_metrics_all"] if m["version"] == "2.0"][0]
        self.assertEqual(v2["severity"], "HIGH")

    def test_no_metrics_gives_none(self):
        cve = cve_fixture()
        cve["metrics"] = {}
        self.assertIsNone(nvd.normalize_record(cve, ENTRY)["cvss_primary"])

    def test_weaknesses(self):
        self.assertEqual(self.rec["weaknesses"], [{"cwe_id": "CWE-20", "source": "nvd@nist.gov", "type": "Primary"}])

    def test_only_vulnerable_cpe_matches_become_affected_products(self):
        products = self.rec["affected_products"]
        self.assertEqual(len(products), 2)
        self.assertEqual({p["vendor"] for p in products}, {"fixture_vendor"})
        ranged = [p for p in products if p["version_end_excluding"]][0]
        self.assertEqual(ranged["version_end_excluding"], "2.0")

    def test_cpe_split_respects_escaped_colons(self):
        parts = nvd.split_cpe(r"cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:*:*:*")
        self.assertEqual(parts[3], r"ven\:dor")
        self.assertEqual(parts[4], "prod")

    def test_cisa_fields_passed_through_only_when_present(self):
        self.assertEqual(self.rec["nvd_cisa_fields"], {})
        cve = cve_fixture()
        cve["cisaExploitAdd"] = "2024-03-01"
        self.assertEqual(nvd.normalize_record(cve, ENTRY)["nvd_cisa_fields"], {"cisaExploitAdd": "2024-03-01"})

    def test_input_not_mutated(self):
        cve = cve_fixture()
        before = copy.deepcopy(cve)
        nvd.normalize_record(cve, ENTRY)
        self.assertEqual(cve, before)


class TargetListTests(unittest.TestCase):
    def test_dedupe_uppercase_and_invalid(self):
        targets, invalid = nvd.build_target_list(0, ["cve-1999-0001", "CVE-1999-0001", "CVE-1999-0002", "nope"], use_kev=False)
        self.assertEqual(targets, ["CVE-1999-0001", "CVE-1999-0002"])
        self.assertEqual(invalid, ["NOPE"])


if __name__ == "__main__":
    unittest.main()
