import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from documents.build_chunks import build_chunks, make_doc_id, resolve_raw  # noqa: E402
from documents.chunking import Block                                        # noqa: E402
from documents.parse import docling_to_blocks                               # noqa: E402

BODY = "Threat actors exploited CVE-2024-3400 and used T1566.001 for initial access to the network. " * 2


class FakeParser:
    name, version = "fake", "0"
    last_skipped = {"page_footer": 2}

    def parse(self, path):
        with open(path, encoding="utf-8") as fh:
            if "BOOM" in fh.read():
                raise ValueError("cannot parse")
        return [Block("heading", "Advisory", 0), Block("heading", "Summary", 1), Block("text", BODY)]


class Label:
    def __init__(self, v):
        self.value = v


class Item:
    def __init__(self, label, text="", level=None, page=None, md=None):
        self.label, self.text, self.level, self._md = Label(label), text, level, md
        self.prov = [type("P", (), {"page_no": page})()] if page else []

    def export_to_markdown(self, doc=None):
        return self._md


class FakeDoc:
    def __init__(self, items):
        self._items = items

    def iterate_items(self):
        return iter([(i, 0) for i in self._items])


class AdapterTests(unittest.TestCase):
    def test_docling_item_mapping(self):
        doc = FakeDoc([Item("title", "T"), Item("section_header", "S", level=2),
                       Item("text", "para"), Item("list_item", "point"),
                       Item("table", md="| a |\n|---|\n| 1 |"), Item("page_footer", "f"),
                       Item("list", "")])
        blocks, skipped = docling_to_blocks(doc)
        self.assertEqual([(b.kind, b.level, b.text) for b in blocks],
                         [("heading", 0, "T"), ("heading", 2, "S"), ("text", 0, "para"),
                          ("text", 0, "- point"), ("table", 0, "| a |\n|---|\n| 1 |")])
        self.assertEqual(skipped["page_footer"], 1)


class DocIdTests(unittest.TestCase):
    def test_url_and_collisions(self):
        used = set()
        a = make_doc_id("https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a", used)
        b = make_doc_id("https://other.example/x/aa24-131a/", used)
        self.assertEqual(a, "advisory_aa24-131a")
        self.assertNotEqual(a, b)
        self.assertTrue(b.startswith("advisory_aa24-131a-"))


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.proc = os.path.join(self.tmp, "processed")
        self.raw = os.path.join(self.tmp, "raw", "advisories")
        os.makedirs(self.proc)
        os.makedirs(self.raw)
        for name, body in (("a.html", "<h1>A</h1>"), ("b.html", "<h1>B</h1>"), ("c.html", "BOOM")):
            with open(os.path.join(self.raw, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        recs = [
            {"advisory_id": "AA24-001A", "title": "First", "source_url": "https://x/aa24-001a",
             "published_at": "2024-01-01", "raw_file_reference": "data\\raw\\advisories\\a.html"},
            {"advisory_id": "AA24-002A", "title": "Second", "source_url": "https://x/aa24-002a",
             "raw_file_reference": os.path.join(self.raw, "b.html")},
            {"advisory_id": "AA24-003A", "raw_file_reference": os.path.join(self.raw, "c.html")},
            {"advisory_id": "AA24-004A", "raw_file_reference": "data/raw/advisories/missing.html"}]
        with open(os.path.join(self.proc, "advisories_normalized.json"), "w", encoding="utf-8") as fh:
            json.dump({"records": recs}, fh)
        self.out = os.path.join(self.proc, "advisory_chunks.jsonl")
        self.m = build_chunks(self.proc, self.raw, self.out, FakeParser())
        with open(self.out, encoding="utf-8") as fh:
            self.rows = [json.loads(line) for line in fh]

    def test_counts_and_failures(self):
        self.assertEqual(self.m["documents_chunked"], 2)
        self.assertEqual(self.m["status"], "PARTIAL")
        reasons = {f["reason"] for f in self.m["failed_documents"]}
        self.assertEqual(reasons, {"parse_error", "raw_file_not_found"})
        self.assertEqual(self.m["skipped_item_labels"], {"page_footer": 4})

    def test_chunk_ids_and_traceability(self):
        r = self.rows[0]
        self.assertEqual(r["chunk_id"], "advisory_aa24-001a_chunk_001")
        self.assertEqual(r["report_id"], "IntelligenceReport:aa24001a")
        self.assertEqual(r["heading_path"], ["Advisory", "Summary"])
        self.assertEqual(r["source_url"], "https://x/aa24-001a")
        self.assertEqual(r["published_at"], "2024-01-01")
        self.assertEqual(r["cve_ids"], ["CVE-2024-3400"])
        self.assertEqual(r["technique_ids"], ["T1566.001"])
        self.assertEqual(len(r["raw_sha256"]), 64)
        self.assertTrue(r["embedding_text"].startswith("Advisory > Summary\n"))
        self.assertEqual(len({x["chunk_id"] for x in self.rows}), len(self.rows))

    def test_deterministic_rebuild_and_inputs_untouched(self):
        raw_a = os.path.join(self.raw, "a.html")
        before, raw_before = read_bytes(self.out), read_bytes(raw_a)
        build_chunks(self.proc, self.raw, self.out, FakeParser())
        self.assertEqual(read_bytes(self.out), before)
        self.assertEqual(read_bytes(raw_a), raw_before)

    def test_resolve_raw_variants(self):
        self.assertTrue(resolve_raw("data\\raw\\advisories\\a.html", self.raw).endswith("a.html"))
        self.assertIsNone(resolve_raw("nope.html", self.raw))
        self.assertIsNone(resolve_raw(None, self.raw))

    def test_missing_processed_file_reported(self):
        m = build_chunks(os.path.join(self.tmp, "empty"), self.raw, self.out, FakeParser())
        self.assertEqual(m["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
