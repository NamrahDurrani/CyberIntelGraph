"""Unit tests for the CWE collector's parsing, validation and subset logic.

IMPORTANT: the XML below is a synthetic TEST FIXTURE shaped like the official CWE schema (made-up ids 90001..,
names starting with 'Fixture'). It only proves the code handles the documented structure. It is never written to data/.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cwe_collector", ROOT / "ingestion" / "collectors" / "cwe" / "collector.py")
cwe = importlib.util.module_from_spec(spec)
sys.modules["cwe_collector"] = cwe  # required so @dataclass can resolve the module
spec.loader.exec_module(cwe)

NS = "http://cwe.mitre.org/cwe-7"
XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="{NS}" xmlns:xhtml="http://www.w3.org/1999/xhtml" Name="Fixture CWE" Version="0.0" Date="2000-01-01">
  <Weaknesses>
    <Weakness ID="90001" Name="Fixture Pillar" Abstraction="Pillar" Structure="Simple" Status="Draft">
      <Description>Top level fixture weakness.</Description>
    </Weakness>
    <Weakness ID="90002" Name="Fixture Class" Abstraction="Class" Structure="Simple" Status="Incomplete">
      <Description>A class below the pillar.</Description>
      <Extended_Description><xhtml:p>First paragraph.</xhtml:p><xhtml:ul><xhtml:li>item one</xhtml:li></xhtml:ul></Extended_Description>
      <Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="90001" View_ID="1000" Ordinal="Primary"/></Related_Weaknesses>
    </Weakness>
    <Weakness ID="90003" Name="Fixture Base" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>A base weakness.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="90002" View_ID="1000" Ordinal="Primary"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="90005" View_ID="2000"/>
        <Related_Weakness Nature="PeerOf" CWE_ID="99999" View_ID="1000"/>
      </Related_Weaknesses>
      <Applicable_Platforms><Language Class="Not Language-Specific" Prevalence="Undetermined"/><Technology Name="Fixture Tech" Prevalence="Often"/></Applicable_Platforms>
      <Related_Attack_Patterns><Related_Attack_Pattern CAPEC_ID="9001"/></Related_Attack_Patterns>
      <Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="FIXTURE"><Entry_ID>F-1</Entry_ID><Entry_Name>Fixture entry</Entry_Name></Taxonomy_Mapping></Taxonomy_Mappings>
      <Mapping_Notes><Usage>Allowed</Usage><Rationale>Fixture rationale.</Rationale><Comments>Fixture comment.</Comments></Mapping_Notes>
      <Content_History>
        <Submission><Submission_Date>2001-02-03</Submission_Date></Submission>
        <Modification><Modification_Date>2010-01-01</Modification_Date></Modification>
        <Modification><Modification_Date>2020-05-06</Modification_Date></Modification>
      </Content_History>
    </Weakness>
    <Weakness ID="90004" Name="Fixture Unreferenced" Abstraction="Base" Structure="Simple" Status="Deprecated">
      <Description>Nobody references this.</Description>
    </Weakness>
    <Weakness ID="90005" Name="Fixture Other-View Parent" Abstraction="Class" Structure="Simple" Status="Draft"><Description>x</Description></Weakness>
  </Weaknesses>
  <Categories>
    <Category ID="90100" Name="Fixture Category" Status="Draft">
      <Summary>Fixture category summary.</Summary>
      <Relationships><Has_Member CWE_ID="90003" View_ID="999"/></Relationships>
    </Category>
  </Categories>
  <Views><View ID="1000" Name="Fixture Research View" Type="Graph" Status="Draft"><Objective>Fixture objective.</Objective></View></Views>
</Weakness_Catalog>
""".encode("utf-8")

CTX = {"source_url": "https://example.test/cwec.zip", "retrieved_at": "2000-01-01T00:00:00+00:00",
       "raw_ref": "data/raw/cwe/fixture.zip", "version": "0.0"}


def parse(xml=XML):
    result = cwe.IngestionResult()
    records, views = cwe.parse_catalog(xml, CTX, result)
    return records, views, result


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


class ZipTests(unittest.TestCase):
    def test_reads_xml_member(self):
        name, data = cwe.read_xml_from_zip(make_zip({"cwec_v0.0.xml": XML}))
        self.assertEqual(name, "cwec_v0.0.xml")
        self.assertEqual(data, XML)

    def test_prefers_cwec_named_member(self):
        name, _ = cwe.read_xml_from_zip(make_zip({"other.xml": b"<a/>", "cwec_v1.xml": XML}))
        self.assertEqual(name, "cwec_v1.xml")

    def test_not_a_zip(self):
        with self.assertRaises(cwe.CollectionError):
            cwe.read_xml_from_zip(b"<html>error page</html>")

    def test_no_xml_inside(self):
        with self.assertRaises(cwe.CollectionError):
            cwe.read_xml_from_zip(make_zip({"readme.txt": b"hi"}))

    def test_size_guard(self):
        old = cwe.MAX_XML_BYTES
        cwe.MAX_XML_BYTES = 10
        try:
            with self.assertRaises(cwe.CollectionError):
                cwe.read_xml_from_zip(make_zip({"cwec.xml": XML}))
        finally:
            cwe.MAX_XML_BYTES = old


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.records, self.views, self.result = parse()
        self.by_id = {r["cwe_id"]: r for r in self.records}

    def test_counts_and_catalog_info(self):
        self.assertEqual((self.result.weaknesses, self.result.categories, self.result.views), (5, 1, 1))
        self.assertEqual((self.result.catalog_name, self.result.catalog_version, self.result.catalog_date),
                         ("Fixture CWE", "0.0", "2000-01-01"))
        self.assertEqual(self.result.errors, [])

    def test_basic_fields(self):
        base = self.by_id["CWE-90003"]
        self.assertEqual((base["abstraction"], base["structure"], base["status"]), ("Base", "Simple", "Stable"))
        self.assertEqual(base["definition_url"], "https://cwe.mitre.org/data/definitions/90003.html")
        self.assertEqual(base["record_id"], "cwe:CWE-90003")

    def test_nested_xhtml_is_flattened(self):
        text = self.by_id["CWE-90002"]["extended_description"]
        self.assertIn("First paragraph.", text)
        self.assertIn("item one", text)
        self.assertNotIn("<", text)

    def test_relationships_platforms_capec_taxonomy_notes(self):
        base = self.by_id["CWE-90003"]
        self.assertEqual([(r["nature"], r["cwe_id"], r["view_id"]) for r in base["related_weaknesses"]],
                         [("ChildOf", "CWE-90002", "1000"), ("ChildOf", "CWE-90005", "2000"), ("PeerOf", "CWE-99999", "1000")])
        self.assertEqual([p["kind"] for p in base["applicable_platforms"]], ["Language", "Technology"])
        self.assertEqual(base["applicable_platforms"][1]["name"], "Fixture Tech")
        self.assertEqual(base["related_attack_patterns"], ["CAPEC-9001"])
        self.assertEqual(base["taxonomy_mappings"][0]["entry_id"], "F-1")
        self.assertEqual(base["mapping_notes"]["usage"], "Allowed")

    def test_dates_use_latest_modification(self):
        base = self.by_id["CWE-90003"]
        self.assertEqual((base["submission_date"], base["last_modified"]), ("2001-02-03", "2020-05-06"))
        self.assertEqual((base["published_at"], base["last_modified_at"]), ("2001-02-03", "2020-05-06"))

    def test_category_members_and_view(self):
        cat = self.by_id["CWE-90100"]
        self.assertEqual(cat["element_type"], "category")
        self.assertEqual(cat["description"], "Fixture category summary.")
        self.assertEqual(cat["members"], [{"cwe_id": "CWE-90003", "view_id": "999"}])
        self.assertEqual(self.views[0]["cwe_id"], "CWE-1000")
        self.assertEqual(self.views[0]["view_type"], "Graph")

    def test_provenance(self):
        rec = self.by_id["CWE-90001"]
        for key in ("source_name", "source_url", "source_record_id", "retrieved_at", "raw_file_reference",
                    "collection_method", "catalog_version", "evidence_type"):
            self.assertTrue(rec[key], key)

    def test_dangling_related_target_is_warning(self):
        self.assertTrue(any("not in this catalog" in w for w in self.result.warnings))


class StructureTests(unittest.TestCase):
    def test_sections_are_reported(self):
        _, _, result = parse()
        self.assertEqual(result.catalog_sections,
                         {"Weaknesses": {"Weakness": 5}, "Categories": {"Category": 1}, "Views": {"View": 1}})
        self.assertFalse(any("no Category entries" in w for w in result.warnings))

    def test_categories_are_found_wherever_they_sit_and_unknown_kinds_are_kept(self):
        xml = (f'<Weakness_Catalog xmlns="{NS}" Name="n" Version="1"><Weaknesses>'
               '<Weakness ID="1" Name="w" Status="Draft"><Description>d</Description></Weakness>'
               '<Category ID="2" Name="category in the weaknesses section" Status="Draft"><Summary>cat summary</Summary></Category>'
               '</Weaknesses><Taxonomies>'
               '<Grouping ID="3" Name="an unknown kind" Status="Draft"><Description>group text</Description></Grouping>'
               '</Taxonomies><External_References><External_Reference Reference_ID="REF-1"/></External_References>'
               '</Weakness_Catalog>').encode()
        records, _, result = parse(xml)
        by_id = {r["cwe_id"]: r for r in records}
        self.assertEqual((result.weaknesses, result.categories), (1, 1))
        self.assertEqual(result.other_kinds, {"grouping": 1})
        self.assertEqual(by_id["CWE-2"]["description"], "cat summary")
        self.assertEqual(by_id["CWE-3"]["element_type"], "grouping")
        self.assertEqual(by_id["CWE-3"]["description"], "group text")
        self.assertEqual(result.errors, [])

    def test_other_kinds_instead_of_categories_get_an_explanatory_note_not_the_alarm(self):
        xml = (f'<Weakness_Catalog xmlns="{NS}" Name="n" Version="1"><Weaknesses>'
               '<Weakness ID="1" Name="w" Status="Draft"/></Weaknesses><Groupings>'
               '<Grouping ID="2" Name="g" Status="Draft"/></Groupings></Weakness_Catalog>').encode()
        _, _, result = parse(xml)
        self.assertEqual(result.other_kinds, {"grouping": 1})
        self.assertTrue(any("no elements named Category" in w for w in result.warnings))
        self.assertFalse(any("no Category entries and no other entry kinds" in w for w in result.warnings))

    def test_zero_categories_is_a_visible_warning_with_the_structure(self):
        xml = (f'<Weakness_Catalog xmlns="{NS}" Name="n" Version="1"><Weaknesses>'
               '<Weakness ID="1" Name="w" Status="Draft"/></Weaknesses></Weakness_Catalog>').encode()
        _, _, result = parse(xml)
        warning = next(w for w in result.warnings if "no Category entries" in w)
        self.assertIn("Weaknesses", warning)


class ProblemTests(unittest.TestCase):
    def test_malformed_xml(self):
        _, _, result = parse(b"<Weakness_Catalog><Weaknesses>")
        self.assertTrue(any("not well-formed" in e for e in result.errors))

    def test_wrong_root(self):
        _, _, result = parse(b"<Something/>")
        self.assertTrue(any("unexpected XML root" in e for e in result.errors))

    def test_bad_id_and_empty_name(self):
        xml = (f'<Weakness_Catalog xmlns="{NS}" Name="n" Version="1"><Weaknesses>'
               '<Weakness ID="abc" Name="x" Status="Draft"/><Weakness ID="5" Name="" Status="Draft"/>'
               '</Weaknesses></Weakness_Catalog>').encode()
        _, _, result = parse(xml)
        self.assertEqual(len([e for e in result.errors if "bad ID or empty name" in e]), 2)

    def test_duplicate_id_is_error(self):
        xml = (f'<Weakness_Catalog xmlns="{NS}" Name="n" Version="1"><Weaknesses>'
               '<Weakness ID="5" Name="a" Status="Draft"/><Weakness ID="5" Name="b" Status="Draft"/>'
               '</Weaknesses></Weakness_Catalog>').encode()
        _, _, result = parse(xml)
        self.assertTrue(any("duplicate id CWE-5" in e for e in result.errors))

    def test_works_with_a_different_namespace_version(self):
        xml = XML.replace(NS.encode(), b"http://cwe.mitre.org/cwe-9")
        records, _, result = parse(xml)
        self.assertEqual(len(records), 6)
        self.assertEqual(result.errors, [])


class SubsetTests(unittest.TestCase):
    def test_referenced_plus_ancestors_in_view_1000_only(self):
        records, _, result = parse()
        subset, rule = cwe.select_subset(records, Counter({"CWE-90003": 4}), Counter({"CWE-90003": 1}), result)
        self.assertEqual([r["cwe_id"] for r in subset], ["CWE-90001", "CWE-90002", "CWE-90003"])  # not 90005 (view 2000)
        self.assertIn("view 1000", rule)
        self.assertEqual((result.referenced_ids_total, result.referenced_ids_found, result.referenced_ids_missing), (1, 1, []))

    def test_missing_referenced_ids_are_reported(self):
        records, _, result = parse()
        subset, _ = cwe.select_subset(records, Counter({"CWE-90001": 1, "CWE-12345": 2}), Counter(), result)
        self.assertEqual([r["cwe_id"] for r in subset], ["CWE-90001"])
        self.assertEqual(result.referenced_ids_missing, ["CWE-12345"])
        self.assertTrue(any("not in the catalog" in w for w in result.warnings))


class ReferencedIdsTests(unittest.TestCase):
    def test_counts_per_record_and_placeholders(self):
        with tempfile.TemporaryDirectory() as tmp:
            nvd, kev = Path(tmp) / "nvd.json", Path(tmp) / "kev.json"
            nvd.write_text(json.dumps({"records": [
                {"weaknesses": [{"cwe_id": "CWE-79"}, {"cwe_id": "CWE-79"}, {"cwe_id": "NVD-CWE-Other"}]},
                {"weaknesses": [{"cwe_id": "CWE-79"}, {"cwe_id": "CWE-20"}]}]}), encoding="utf-8")
            kev.write_text(json.dumps({"records": [{"cwes": ["CWE-20", "CWE-20"]}, {"cwes": []}]}), encoding="utf-8")
            old = cwe.NVD_NORMALIZED, cwe.KEV_NORMALIZED, cwe.PROJECT_ROOT
            cwe.NVD_NORMALIZED, cwe.KEV_NORMALIZED, cwe.PROJECT_ROOT = nvd, kev, Path(tmp)
            try:
                result = cwe.IngestionResult()
                n, k = cwe.load_referenced_ids(result)
            finally:
                cwe.NVD_NORMALIZED, cwe.KEV_NORMALIZED, cwe.PROJECT_ROOT = old
        self.assertEqual(dict(n), {"CWE-79": 2, "CWE-20": 1})
        self.assertEqual(dict(k), {"CWE-20": 1})
        self.assertEqual(result.nvd_placeholders_seen, {"NVD-CWE-Other": 1})


if __name__ == "__main__":
    unittest.main()
