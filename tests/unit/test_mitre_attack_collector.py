"""Unit tests for the MITRE ATT&CK collector's validation and normalization logic.

IMPORTANT: everything below is a synthetic TEST FIXTURE (fake STIX ids, fake ATT&CK ids like T9001, names
starting with 'Fixture'). It only proves the code handles the STIX 2.1 structure. It is never written to data/.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "attack_collector", ROOT / "ingestion" / "collectors" / "mitre_attack" / "collector.py")
atk = importlib.util.module_from_spec(spec)
sys.modules["attack_collector"] = atk  # required so @dataclass can resolve the module
spec.loader.exec_module(atk)

CTX = {"bundle_url": "https://example.test/bundle.json", "retrieved_at": "2000-01-01T00:00:00+00:00",
       "raw_ref": "data/raw/mitre_attack/fixture.json", "version": "0.0"}


def sid(kind, n):
    return f"{kind}--00000000-0000-0000-0000-{n:012d}"


def stix(kind, n, name, ext_id, **extra):
    obj = {"type": kind, "id": sid(kind, n), "name": name, "description": f"  {name} description  ",
           "created": "2020-01-01T00:00:00.000Z", "modified": "2021-01-01T00:00:00.000Z", "x_mitre_version": "1.0",
           "x_mitre_domains": ["enterprise-attack"],
           "external_references": [{"source_name": "mitre-attack", "external_id": ext_id,
                                    "url": f"https://example.test/{ext_id}"},
                                   {"source_name": "Fixture paper", "description": "Fixture citation",
                                    "url": "https://example.test/paper"}]}
    obj.update(extra)
    return obj


def rel(n, kind, src, dst, **extra):
    obj = {"type": "relationship", "id": sid("relationship", n), "relationship_type": kind,
           "source_ref": src, "target_ref": dst, "description": "fixture rel",
           "created": "2020-01-01T00:00:00.000Z", "modified": "2021-01-01T00:00:00.000Z"}
    obj.update(extra)
    return obj


def bundle_objects():
    tactic = stix("x-mitre-tactic", 1, "Fixture Tactic", "TA9001", x_mitre_shortname="fixture-tactic")
    tech = stix("attack-pattern", 2, "Fixture Technique", "T9001", x_mitre_is_subtechnique=False,
                kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "fixture-tactic"}])
    sub = stix("attack-pattern", 3, "Fixture Sub", "T9001.001", x_mitre_is_subtechnique=True,
               kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "fixture-tactic"}])
    old = stix("attack-pattern", 4, "Fixture Revoked", "T9002", revoked=True, x_mitre_is_subtechnique=False,
               kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "fixture-tactic"}])
    group = stix("intrusion-set", 5, "Fixture Group", "G9001", aliases=["Fixture Group", "FG"])
    dep_group = stix("intrusion-set", 6, "Fixture Deprecated Group", "G9002", x_mitre_deprecated=True)
    mal = stix("malware", 7, "Fixture Malware", "S9001", is_family=True, x_mitre_aliases=["FM"])
    tool = stix("tool", 8, "Fixture Tool", "S9002")
    camp = stix("campaign", 9, "Fixture Campaign", "C9001", first_seen="2019-01-01T00:00:00.000Z",
                last_seen="2020-01-01T00:00:00.000Z")
    mit = stix("course-of-action", 10, "Fixture Mitigation", "M9001")
    detect = stix("x-mitre-detection-strategy", 11, "Fixture Detection", "DET9001")
    rels = [
        rel(1, "uses", group["id"], tech["id"]),
        rel(2, "subtechnique-of", sub["id"], tech["id"]),
        rel(3, "uses", mal["id"], sub["id"]),
        rel(4, "attributed-to", camp["id"], group["id"]),
        rel(5, "mitigates", mit["id"], tech["id"]),
        rel(6, "revoked-by", old["id"], tech["id"]),                      # replacement pointer -> excluded
        rel(7, "detects", detect["id"], tech["id"]),                      # detection content -> excluded
        rel(8, "uses", dep_group["id"], tech["id"]),                      # deprecated endpoint -> excluded
        rel(9, "uses", tool["id"], tech["id"], revoked=True),             # revoked relationship -> excluded
    ]
    return [tactic, tech, sub, old, group, dep_group, mal, tool, camp, mit, detect] + rels


def run_normalize(objects):
    result = atk.IngestionResult()
    records, relationships = atk.normalize(objects, CTX, result)
    return records, relationships, result


class BundleValidationTests(unittest.TestCase):
    def test_not_a_bundle(self):
        self.assertTrue(atk.validate_bundle({"type": "other"})[1])

    def test_empty_objects(self):
        self.assertTrue(atk.validate_bundle({"type": "bundle", "objects": []})[1])

    def test_duplicate_id_and_type_mismatch(self):
        a = stix("malware", 1, "A", "S9001")
        _, errors, _ = atk.validate_bundle({"type": "bundle", "objects": [a, dict(a)]})
        self.assertTrue(any("duplicate STIX id" in e for e in errors))
        bad = dict(a, id=sid("tool", 1))
        _, errors, _ = atk.validate_bundle({"type": "bundle", "objects": [bad]})
        self.assertTrue(any("does not match type" in e for e in errors))

    def test_valid_bundle(self):
        _, errors, _ = atk.validate_bundle({"type": "bundle", "objects": bundle_objects()})
        self.assertEqual(errors, [])


class ReleaseChoiceTests(unittest.TestCase):
    INDEX = {"collections": [{"name": "Enterprise ATT&CK", "versions": [
        {"version": "9.0", "url": "u9"}, {"version": "19.2", "url": "u192"}, {"version": "20.0", "url": "u20"}]}]}

    def test_latest_uses_numeric_not_text_order(self):
        self.assertEqual(atk.choose_release(self.INDEX, "Enterprise ATT&CK", None), ("20.0", "u20"))

    def test_pin(self):
        self.assertEqual(atk.choose_release(self.INDEX, "Enterprise ATT&CK", "9.0"), ("9.0", "u9"))

    def test_unknown_pin_or_collection(self):
        with self.assertRaises(atk.CollectionError):
            atk.choose_release(self.INDEX, "Enterprise ATT&CK", "1.0")
        with self.assertRaises(atk.CollectionError):
            atk.choose_release(self.INDEX, "Nope", None)


class NormalizationTests(unittest.TestCase):
    def setUp(self):
        self.records, self.rels, self.result = run_normalize(bundle_objects())
        self.by_id = {r["attack_id"]: r for r in self.records}

    def test_only_active_in_scope_objects_kept(self):
        self.assertEqual(sorted(self.by_id), ["C9001", "G9001", "M9001", "S9001", "S9002", "T9001", "T9001.001", "TA9001"])
        self.assertEqual(self.result.excluded_revoked_or_deprecated, 2)
        self.assertEqual(self.result.errors, [])

    def test_relationships_filtered_and_counted(self):
        self.assertEqual(self.result.relationships_by_type,
                         {"attributed-to": 1, "mitigates": 1, "subtechnique-of": 1, "uses": 2})
        self.assertEqual(len(self.rels), 5)
        reasons = " | ".join(self.result.relationships_excluded)
        for expected in ("revoked-by", "detects", "endpoint is revoked/deprecated", "relationship revoked/deprecated"):
            self.assertIn(expected, reasons)

    def test_technique_fields(self):
        sub = self.by_id["T9001.001"]
        self.assertTrue(sub["is_subtechnique"])
        self.assertEqual(sub["parent_attack_id"], "T9001")
        self.assertEqual(sub["tactics"], ["fixture-tactic"])
        self.assertIsNone(self.by_id["T9001"]["parent_attack_id"])

    def test_other_type_fields(self):
        self.assertEqual(self.by_id["TA9001"]["shortname"], "fixture-tactic")
        self.assertIs(self.by_id["S9001"]["is_family"], True)
        self.assertEqual(self.by_id["S9001"]["aliases"], ["FM"])
        self.assertEqual(self.by_id["G9001"]["aliases"], ["Fixture Group", "FG"])
        self.assertEqual(self.by_id["C9001"]["first_seen"], "2019-01-01T00:00:00.000Z")

    def test_provenance_and_cleaning(self):
        rec = self.by_id["G9001"]
        self.assertEqual(rec["description"], "Fixture Group description")
        self.assertEqual(rec["source_record_id"], "G9001")
        self.assertEqual(rec["raw_file_reference"], CTX["raw_ref"])
        self.assertEqual(rec["evidence_type"], "structured_authoritative_record")
        self.assertEqual(rec["attack_url"], "https://example.test/G9001")
        self.assertEqual(len(rec["external_references"]), 2)

    def test_relationship_keeps_stix_direction_and_ids(self):
        attributed = [r for r in self.rels if r["relationship_type"] == "attributed-to"][0]
        self.assertEqual((attributed["source_attack_id"], attributed["target_attack_id"]), ("C9001", "G9001"))
        self.assertEqual(attributed["source_stix_type"], "campaign")


class ProblemDetectionTests(unittest.TestCase):
    def test_missing_attack_id_is_error(self):
        broken = stix("malware", 20, "Fixture NoId", "S9100")
        broken["external_references"] = [{"source_name": "Fixture paper"}]
        _, _, result = run_normalize([broken])
        self.assertTrue(any("no 'mitre-attack' external id" in e for e in result.errors))

    def test_bad_id_format_is_error(self):
        _, _, result = run_normalize([stix("malware", 21, "Fixture BadFormat", "X1")])
        self.assertTrue(any("unexpected ATT&CK id format" in e for e in result.errors))

    def test_duplicate_attack_id_is_error(self):
        _, _, result = run_normalize([stix("malware", 22, "A", "S9200"), stix("malware", 23, "B", "S9200")])
        self.assertTrue(any("duplicate ATT&CK id" in e for e in result.errors))

    def test_relationship_with_endpoint_missing_from_bundle_is_error(self):
        mal = stix("malware", 24, "Fixture M", "S9300")
        _, _, result = run_normalize([mal, rel(30, "uses", mal["id"], sid("attack-pattern", 999))])
        self.assertTrue(any("endpoint missing from bundle" in e for e in result.errors))

    def test_subtechnique_without_parent_is_error(self):
        tactic = stix("x-mitre-tactic", 25, "T", "TA9301", x_mitre_shortname="fx")
        sub = stix("attack-pattern", 26, "Sub", "T9301.001", x_mitre_is_subtechnique=True,
                   kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "fx"}])
        _, _, result = run_normalize([tactic, sub])
        self.assertTrue(any("0 parent(s)" in e for e in result.errors))

    def test_unknown_tactic_is_error_and_no_tactic_is_warning(self):
        tech = stix("attack-pattern", 27, "Tech", "T9302", x_mitre_is_subtechnique=False,
                    kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "nope"}])
        none = stix("attack-pattern", 28, "NoTactic", "T9303", x_mitre_is_subtechnique=False, kill_chain_phases=[])
        _, _, result = run_normalize([tech, none])
        self.assertTrue(any("unknown tactic" in e for e in result.errors))
        self.assertTrue(any("has no tactic" in w for w in result.warnings))


if __name__ == "__main__":
    unittest.main()
