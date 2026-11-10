import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from canonical.build import build                       # noqa: E402
from canonical.ids import norm_cwe, software_key, slug  # noqa: E402
from canonical.models import (Evidence, EvidenceType, Relationship,  # noqa: E402
                              Vulnerability)
from pydantic import ValidationError                    # noqa: E402


def dump(d, name, recs):
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        json.dump({"records": recs}, fh)


class IdTests(unittest.TestCase):
    def test_software_resolution(self):
        self.assertEqual(software_key("Palo Alto Networks", "PAN-OS"),
                         software_key("paloaltonetworks", "pan-os"))

    def test_cwe_normalisation(self):
        self.assertEqual(norm_cwe("79"), "CWE-79")
        self.assertEqual(norm_cwe("cwe-79"), "CWE-79")
        self.assertIsNone(norm_cwe("NVD-CWE-noinfo"))
        self.assertEqual(slug("A b-C"), "abc")


class ModelTests(unittest.TestCase):
    def test_id_prefix_must_match_type(self):
        with self.assertRaises(ValidationError):
            Vulnerability(canonical_id="Weakness:CVE-1", name="x", cve_id="CVE-1")

    def test_extra_fields_rejected(self):
        with self.assertRaises(ValidationError):
            Evidence(source="x", evidence_type=EvidenceType.INFERRED, bogus=1)

    def test_rel_id_format(self):
        with self.assertRaises(ValidationError):
            Relationship(rel_id="bad", rel_type="USES", source_id="A:1", target_id="B:2",
                         evidence_type=EvidenceType.INFERRED)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = self.tmp
        dump(p, "cwe_normalized.json", [
            {"id": "CWE-79", "name": "XSS", "element_type": "weakness",
             "related_weaknesses": [{"nature": "ChildOf", "cwe_id": "CWE-74"}]},
            {"id": "CWE-74", "name": "Injection", "element_type": "weakness"}])
        dump(p, "cisa_kev_normalized.json", [
            {"cve_id": "CVE-2024-3400", "vendor_project": "Palo Alto Networks",
             "product": "PAN-OS", "date_added": "2024-04-12",
             "known_ransomware_campaign_use": "Unknown"},
            {"cve_id": "CVE-2021-0002", "vendor_project": "Acme", "product": "Widget",
             "date_added": 20210101, "known_ransomware_use": False}])
        dump(p, "nvd_normalized.json", [
            {"cve_id": "CVE-2024-3400", "description": "Command injection",
             "cvss_primary": {"score": 10.0, "severity": "CRITICAL"},
             "cwe_ids": ["CWE-79", "NVD-CWE-noinfo", "CWE-999"],
             "affected_products": [{"vendor": "paloaltonetworks", "product": "pan-os"}]}])
        dump(p, "attack_objects_normalized.json", [
            {"stix_type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "attack_id": "TA0001",
             "name": "Initial Access", "shortname": "initial-access"},
            {"stix_type": "attack-pattern", "id": "attack-pattern--1", "attack_id": "T1566",
             "name": "Phishing", "tactics": ["initial-access"], "is_subtechnique": False},
            {"stix_type": "attack-pattern", "id": "attack-pattern--2", "attack_id": "T1566.001",
             "name": "Spearphishing Attachment", "tactics": ["initial-access"],
             "is_subtechnique": True},
            {"stix_type": "intrusion-set", "id": "intrusion-set--1", "attack_id": "G0001", "name": "Grp"},
            {"stix_type": "campaign", "id": "campaign--1", "attack_id": "C0001", "name": "Camp"}])
        dump(p, "attack_relationships_normalized.json", [
            {"relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
            {"relationship_type": "subtechnique-of", "source_ref": "attack-pattern--2", "target_ref": "attack-pattern--1"},
            {"relationship_type": "attributed-to", "source_ref": "campaign--1", "target_ref": "intrusion-set--1"},
            {"relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "gone--9"}])
        dump(p, "advisories_normalized.json", [
            {"url": "https://x/adv1", "title": "Adv 1",
             "text": "Exploits CVE-2024-3400 and CVE-2023-0001 using T1566.001, T0801, T1451."}])
        self.out = os.path.join(self.tmp, "out")
        self.s = build(p, self.out)
        self.ents = {e["canonical_id"]: e for e in self._load(self.out, "entities.json")}
        self.rels = {r["rel_id"] for r in self._load(self.out, "relationships.json")}
        self.assertIn("MENTIONS|IntelligenceReport:httpsxadv1|Vulnerability:CVE-2024-3400", self.rels)

    @staticmethod
    def _load(d, f):
        with open(os.path.join(d, f), encoding="utf-8") as fh:
            return json.load(fh)["records"]

    def test_one_vulnerability_two_sources(self):
        v = self.ents["Vulnerability:CVE-2024-3400"]
        self.assertEqual(sorted(v["sources"]), ["cisa_kev", "nvd"])  # advisories only MENTION it
        self.assertTrue(v["in_kev"])
        self.assertEqual(v["description"], "Command injection")
        self.assertEqual(v["severity"], "CRITICAL")

    def test_real_world_types_do_not_crash(self):
        v = self.ents["Vulnerability:CVE-2021-0002"]
        self.assertIs(v["kev_ransomware_use"], False)
        self.assertEqual(v["kev_date_added"], "20210101")

    def test_software_merged_across_kev_and_nvd(self):
        self.assertEqual([k for k in self.ents if k.startswith("Software:")],
                         ["Software:acme/widget", "Software:paloaltonetworks/panos"])

    def test_cwe_placeholders_and_missing(self):
        self.assertIn("HAS_WEAKNESS|Vulnerability:CVE-2024-3400|Weakness:CWE-79", self.rels)
        self.assertEqual(self.s["skipped"]["nvd:placeholder_NVD-CWE-noinfo"], 1)
        self.assertIn("cwe_not_in_catalog:", self.s["unresolved_by_kind"])

    def test_hierarchy_and_tactics(self):
        self.assertIn("CHILD_OF|Weakness:CWE-79|Weakness:CWE-74", self.rels)
        self.assertIn("PART_OF_TACTIC|AttackTechnique:T1566|AttackTactic:TA0001", self.rels)
        self.assertIn("SUBTECHNIQUE_OF|AttackTechnique:T1566.001|AttackTechnique:T1566", self.rels)

    def test_attributed_to_is_reversed(self):
        self.assertIn("CONDUCTS|ThreatActor:G0001|Campaign:C0001", self.rels)
        self.assertIn("USES|ThreatActor:G0001|AttackTechnique:T1566", self.rels)
        self.assertEqual(self.s["skipped"]["attack_rel:endpoint_not_active"], 1)

    def test_advisory_stub_and_unresolved_techniques(self):
        self.assertTrue(self.ents["Vulnerability:CVE-2023-0001"]["stub"])
        self.assertEqual(self.s["advisory_only_vulnerability_stubs"], 1)
        self.assertIn("technique_reference:ics_matrix_not_collected", self.s["unresolved_by_kind"])
        self.assertIn("technique_reference:not_active_enterprise_technique", self.s["unresolved_by_kind"])

    def test_idempotent(self):
        out2 = os.path.join(self.tmp, "out2")
        build(self.tmp, out2)
        for f in ("entities.json", "relationships.json"):
            self.assertEqual(self._load(self.out, f), self._load(out2, f))


if __name__ == "__main__":
    unittest.main()
