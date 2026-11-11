"""Milestone 5.1 - HAS_WEAKNESS from KEV `cwes` and NVD, combined without duplicates."""
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from canonical.build import Builder, build  # noqa: E402


def dump(d, name, recs):
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        json.dump({"records": recs}, fh)


def load(d, name):
    with open(os.path.join(d, name), encoding="utf-8") as fh:
        return json.load(fh)["records"]


def kev(cve, cwes):
    return {"cve_id": cve, "vendor_project": "V", "product": "P", "cwes": cwes}


def nvd(cve, cwes):
    return {"cve_id": cve, "description": "d", "cwe_ids": cwes}


class KevCweTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        p = self.tmp
        dump(p, "cwe_normalized.json", [
            {"id": "CWE-79", "name": "XSS", "element_type": "weakness"},
            {"id": "CWE-74", "name": "Injection", "element_type": "weakness"},
            {"id": "CWE-22", "name": "Path", "element_type": "weakness"}])
        dump(p, "cisa_kev_normalized.json", [
            kev("CVE-2020-0001", ["CWE-79"]),                       # A: KEV only
            kev("CVE-2020-0003", ["CWE-79", "CWE-74"]),             # C: overlap + KEV extra
            kev("CVE-2020-0004", ["CWE-99999"]),                    # D: unknown in KEV
            kev("CVE-2020-0005", "CWE-22, cwe-79"),                 # E: comma string
            kev("CVE-2020-0006", [{"cwe_id": "CWE-74"}]),           # F: dict items
            kev("CVE-2020-0007", ["garbage", "NVD-CWE-noinfo"]),    # G: invalid + placeholder
            kev("CVE-2020-0008", None),                             # H: missing
            kev("CVE-2020-0009", []),                               # I: empty
            kev("CVE-2020-0010", ""),                               # J: empty string
            {"cve_id": "CVE-2020-0011", "vendor_project": "V", "product": "P"}])  # K: no field
        dump(p, "nvd_normalized.json", [
            nvd("CVE-2020-0002", ["CWE-74"]),                       # B: NVD only
            nvd("CVE-2020-0003", ["CWE-79"]),                       # C: overlap with KEV
            nvd("CVE-2020-0004", ["CWE-99999"])])                   # D: unknown in NVD too
        self.hashes = {f: self._sha(os.path.join(p, f)) for f in os.listdir(p)}
        self.out = os.path.join(p, "out")
        self.summary = build(p, self.out)
        self.rels = {r["rel_id"]: r for r in load(self.out, "relationships.json")}
        self.unres = load(self.out, "unresolved_references.json")

    @staticmethod
    def _sha(path):
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()

    def hw(self, cve, cwe):
        return self.rels.get(f"HAS_WEAKNESS|Vulnerability:{cve}|Weakness:{cwe}")

    def test_kev_only(self):
        r = self.hw("CVE-2020-0001", "CWE-79")
        self.assertIsNotNone(r)
        self.assertEqual({e["source"] for e in r["evidence"]}, {"cisa_kev"})

    def test_nvd_only(self):
        r = self.hw("CVE-2020-0002", "CWE-74")
        self.assertIsNotNone(r)
        self.assertEqual({e["source"] for e in r["evidence"]}, {"nvd"})

    def test_overlap_is_one_edge_with_two_evidence(self):
        edges = [k for k in self.rels
                 if k.startswith("HAS_WEAKNESS|Vulnerability:CVE-2020-0003|Weakness:CWE-79")]
        self.assertEqual(len(edges), 1)
        self.assertEqual({e["source"] for e in self.rels[edges[0]]["evidence"]},
                         {"cisa_kev", "nvd"})
        # the KEV-only extra CWE on the same CVE is still added
        self.assertEqual({e["source"] for e in self.hw("CVE-2020-0003", "CWE-74")["evidence"]},
                         {"cisa_kev"})

    def test_unknown_cwe_creates_no_edge_and_is_logged_once(self):
        self.assertFalse([k for k in self.rels if "CVE-2020-0004" in k and "HAS_WEAKNESS" in k])
        mine = [u for u in self.unres if u["kind"] == "cwe_not_in_catalog"
                and u["from"] == "Vulnerability:CVE-2020-0004"]
        self.assertEqual(len(mine), 1)          # KEV + NVD both listed it; logged once

    def test_string_and_dict_formats_parse(self):
        self.assertIsNotNone(self.hw("CVE-2020-0005", "CWE-22"))
        self.assertIsNotNone(self.hw("CVE-2020-0005", "CWE-79"))   # 'cwe-79' normalised
        self.assertIsNotNone(self.hw("CVE-2020-0006", "CWE-74"))

    def test_invalid_placeholder_and_empty_are_skipped_safely(self):
        self.assertFalse([k for k in self.rels if "CVE-2020-0007" in k and "HAS_WEAKNESS" in k])
        sk = self.summary["skipped"]
        self.assertEqual(sk["kev:cwe_unparsable"], 1)
        self.assertEqual(sk["kev:placeholder_NVD-CWE-noinfo"], 1)
        for cve in ("0008", "0009", "0010", "0011"):
            self.assertFalse([k for k in self.rels if f"CVE-2020-{cve}" in k and "HAS_WEAKNESS" in k])

    def test_every_edge_targets_a_catalog_weakness(self):
        ents = {e["canonical_id"] for e in load(self.out, "entities.json")}
        for r in self.rels.values():
            if r["rel_type"] == "HAS_WEAKNESS":
                self.assertIn(r["target_id"], ents)
                self.assertTrue(r["target_id"].startswith("Weakness:CWE-"))

    def test_provenance_counts(self):
        p = self.summary["has_weakness_provenance"]
        self.assertEqual(p["both"], 1)                       # CVE-0003/CWE-79
        self.assertEqual(p["nvd_only"], 1)                   # CVE-0002/CWE-74
        self.assertEqual(p["total"], len([r for r in self.rels.values() if r["rel_type"] == "HAS_WEAKNESS"]))

    def test_entity_ids_unchanged_and_inputs_untouched(self):
        self.assertIn("Vulnerability:CVE-2020-0003", {e["canonical_id"] for e in load(self.out, "entities.json")})
        for f, h in self.hashes.items():
            self.assertEqual(self._sha(os.path.join(self.tmp, f)), h, f)

    def test_rebuild_is_identical(self):
        out2 = os.path.join(self.tmp, "out2")
        build(self.tmp, out2)
        for f in ("entities.json", "relationships.json", "unresolved_references.json"):
            self.assertEqual(load(self.out, f), load(out2, f))


class TokenTests(unittest.TestCase):
    def test_tokens(self):
        t = Builder._cwe_tokens
        self.assertEqual(t(None), [])
        self.assertEqual(t(""), [])
        self.assertEqual(t("CWE-1; CWE-2 | CWE-3"), ["CWE-1", "CWE-2", "CWE-3"])
        self.assertEqual(t(["CWE-1", {"id": "CWE-2"}, ["CWE-3"]]), ["CWE-1", "CWE-2", "CWE-3"])


if __name__ == "__main__":
    unittest.main()
