"""Runs only where docling is installed: converts a small HTML page with the REAL
Docling and checks the adapter + chunker end to end."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    import docling  # noqa: F401
    HAVE = True
except Exception:
    HAVE = False

HTML = """<html><head><title>AA00-001A Test Advisory</title></head><body>
<h1>Test Advisory</h1>
<h2>Summary</h2>
<p>Threat actors exploited CVE-2024-3400 against exposed firewalls and used T1566.001 for initial access to many networks.</p>
<h2>Recommended actions</h2>
<ul><li>Apply the vendor patch for the affected product immediately.</li><li>Review authentication logs for suspicious activity.</li></ul>
<h2>Techniques</h2>
<table><tr><th>ID</th><th>Name</th></tr><tr><td>T1566</td><td>Phishing used to gain a foothold</td></tr></table>
</body></html>"""


@unittest.skipUnless(HAVE, "docling not installed")
class RealDoclingTests(unittest.TestCase):
    def test_html_end_to_end(self):
        from documents.chunking import chunk_blocks
        from documents.parse import DoclingParser
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.html")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(HTML)
            parser = DoclingParser()
            blocks = parser.parse(p)
            kinds = {b.kind for b in blocks}
            self.assertIn("heading", kinds, [(b.kind, b.text[:30]) for b in blocks])
            self.assertIn("text", kinds)
            self.assertTrue(any(b.kind == "table" and "T1566" in b.text for b in blocks),
                            [(b.kind, b.text[:40]) for b in blocks])
            chunks, _ = chunk_blocks(blocks, min_words=3)
            joined = " ".join(c.text for c in chunks)
            self.assertIn("CVE-2024-3400", joined)
            self.assertTrue(any("Summary" in " ".join(c.heading_path) for c in chunks),
                            [c.heading_path for c in chunks])


if __name__ == "__main__":
    unittest.main()
