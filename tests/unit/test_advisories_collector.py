"""Unit tests for the advisories collector: URL handling, RSS parsing, robots, text extraction.

IMPORTANT: the HTML and RSS below are synthetic TEST FIXTURES (fake advisory code AA00-001A, fake CVE-1999-0001,
'Fixture' names). They imitate the general layout of an advisory page; they are not copies of real pages and are
never written to data/. The real layout is confirmed by the first real run on your PC.

Run from the project root (venv active):
    python -m unittest discover -s tests\\unit -v
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "adv_collector", ROOT / "ingestion" / "collectors" / "advisories" / "collector.py")
adv = importlib.util.module_from_spec(spec)
sys.modules["adv_collector"] = adv  # required so @dataclass can resolve the module
spec.loader.exec_module(adv)

FILLER = " ".join(["The fixture actors gained access and moved laterally across the fixture network."] * 8)
PAGE = f"""<html><head><title>AA00-001A Fixture Advisory | CISA</title>
<meta property="og:title" content="Fixture Ransomware Advisory | CISA">
<meta property="article:modified_time" content="2024-06-01T10:00:00-04:00"></head>
<body><header><nav>SITE NAVIGATION Report a cyber issue</nav></header>
<main>
 <div>Cybersecurity Advisory</div>
 <h1>Fixture Ransomware Advisory</h1>
 <div>Release Date</div><div>February 19, 2025</div>
 <div>Alert Code</div><div>AA00-001A</div>
 <div>Last Revised</div><div>March 3, 2025</div>
 <h2>Summary</h2><p>Actors exploited CVE-1999-0001 and then used T1190. See also cwe-79. {FILLER}</p>
 <h2>Technical Details</h2><h3>Initial Access</h3>
 <ul><li>Item one with <b>bold</b> text</li><li>Item two</li></ul>
 <table><tr><th>Tool</th><th>Purpose</th></tr><tr><td><p>FixtureTool</p></td><td>Exfiltration</td></tr></table>
 <a href="/sites/default/files/aa00-001a.pdf#page=2">Download PDF</a> <a href="/other-page">Not an attachment</a>
 <script>var tracking = "SCRIPT TEXT";</script>
</main><footer>FOOTER CHROME</footer></body></html>""".encode("utf-8")

URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-001a"

RSS = b"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Fixture feed</title>
<item><title>Older advisory</title><link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-002a</link>
<pubDate>Mon, 05 Feb 2024 10:00:00 -0500</pubDate><category>Cybersecurity Advisory</category></item>
<item><title>Newer advisory</title><link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-003a</link>
<pubDate>Wed, 20 Mar 2024 10:00:00 -0400</pubDate></item>
<item><title>No link here</title></item>
</channel></rss>"""


class DateAndUrlTests(unittest.TestCase):
    def test_parse_any_date_formats(self):
        for value, expected in [("February 19, 2025", "2025-02-19"), ("Feb 19, 2025", "2025-02-19"),
                                ("2025-02-19", "2025-02-19"), ("2024-06-01T10:00:00-04:00", "2024-06-01"),
                                ("2024-06-01T10:00:00Z", "2024-06-01"),
                                ("Wed, 20 Mar 2024 10:00:00 -0400", "2024-03-20")]:
            self.assertEqual(adv.parse_any_date(value), expected, value)
        for bad in ("", None, "not a date", "13/45/2020"):
            self.assertIsNone(adv.parse_any_date(bad), bad)

    def test_canonical_url(self):
        c = lambda u: adv.canonical_url(u, adv.ALLOWED_HOST)
        self.assertEqual(c("http://cisa.gov/news-events/x/?utm=1#top"), "https://www.cisa.gov/news-events/x")
        self.assertEqual(c("https://www.cisa.gov/a/b/"), "https://www.cisa.gov/a/b")
        self.assertIsNone(c("https://example.com/a"))
        self.assertIsNone(c("https://www.cisa.gov.evil.example/a"))
        self.assertIsNone(c("ftp://www.cisa.gov/a"))
        self.assertIsNone(c("not a url"))

    def test_slug(self):
        self.assertEqual(adv.slug_of(URL + "/"), "aa00-001a")


class FeedAndCandidateTests(unittest.TestCase):
    def test_parse_feed(self):
        items = adv.parse_feed(RSS)
        self.assertEqual(len(items), 2)  # the item without a link is dropped
        self.assertEqual(items[0]["pub_date"], "2024-02-05")
        self.assertEqual(items[0]["categories"], ["Cybersecurity Advisory"])

    def test_parse_feed_errors(self):
        with self.assertRaises(ValueError):
            adv.parse_feed(b"<html><body>Access denied</body>")
        with self.assertRaises(ValueError):
            adv.parse_feed(b"<notrss><x/></notrss>")
        self.assertEqual(adv.parse_feed(b'<rss version="2.0"><channel/></rss>'), [])

    def test_build_candidates_order_dedupe_reject_limit(self):
        feed = adv.parse_feed(RSS)
        manual = ["https://cisa.gov/news-events/cybersecurity-advisories/aa00-009a/", "https://example.com/x"]
        seed = ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-003a",   # duplicate of a feed item
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-004a"]
        cands, rejected = adv.build_candidates(manual, feed, seed, adv.ALLOWED_HOST, 10)
        self.assertEqual([c["url"].rsplit("/", 1)[-1] for c in cands], ["aa00-009a", "aa00-003a", "aa00-002a", "aa00-004a"])
        self.assertEqual([c["source"] for c in cands], ["manual", "feed", "feed", "seed"])
        self.assertEqual(rejected, ["https://example.com/x"])
        self.assertEqual(cands[1]["feed_pub_date"], "2024-03-20")
        limited, _ = adv.build_candidates(manual, feed, seed, adv.ALLOWED_HOST, 2)
        self.assertEqual(len(limited), 2)

    def test_read_url_file_ignores_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "urls.txt"
            f.write_text("# header\n\nhttps://a.example/1  # trailing comment\n  https://a.example/2\n", encoding="utf-8")
            self.assertEqual(adv.read_url_file(f), ["https://a.example/1", "https://a.example/2"])
            self.assertEqual(adv.read_url_file(Path(tmp) / "missing.txt"), [])


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.page = adv.extract_page(PAGE, URL, feed_title="Feed title", feed_pub_date="2024-01-01")

    def test_title_and_labels(self):
        self.assertEqual(self.page["title"], "Fixture Ransomware Advisory")
        self.assertEqual(self.page["alert_code"], "AA00-001A")
        self.assertEqual(self.page["release_date"], "2025-02-19")
        self.assertEqual(self.page["last_revised"], "2025-03-03")
        self.assertEqual(self.page["published_at"], "2025-02-19")
        self.assertEqual(self.page["published_at_source"], "page label 'Release Date'")
        self.assertEqual(self.page["problems"], [])
        # the fixture's fake code AA00-001A implies 2000-01-01, so the label/code disagreement warning is expected
        self.assertEqual(len(self.page["warnings"]), 1)
        self.assertIn("differs from the date implied", self.page["warnings"][0])

    def test_chrome_and_scripts_removed(self):
        for noise in ("SITE NAVIGATION", "FOOTER CHROME", "SCRIPT TEXT", "tracking"):
            self.assertNotIn(noise, self.page["text"])

    def test_structure_is_kept(self):
        text = self.page["text"]
        self.assertIn("## Summary", text)
        self.assertIn("### Initial Access", text)
        self.assertIn("- Item one with bold text", text)
        self.assertIn("| Tool | Purpose |", text)
        self.assertIn("| FixtureTool | Exfiltration |", text)
        self.assertEqual(text.count("FixtureTool"), 1)  # not duplicated by the <p> inside the cell
        headings = [s["heading"] for s in self.page["sections"]]
        self.assertIn("Summary", headings)
        self.assertIn("Technical Details", headings)

    def test_mentions_are_normalized(self):
        self.assertEqual(self.page["mentioned_cve_ids"], ["CVE-1999-0001"])
        self.assertEqual(self.page["mentioned_attack_ids"], ["T1190"])
        self.assertEqual(self.page["mentioned_cwe_ids"], ["CWE-79"])

    def test_attachments_resolved_and_fragment_removed(self):
        self.assertEqual(self.page["attachments"],
                         [{"url": "https://www.cisa.gov/sites/default/files/aa00-001a.pdf", "text": "Download PDF"}])

    def test_word_count_matches_text(self):
        self.assertEqual(self.page["word_count"], len(self.page["text"].split()))

    def test_falls_back_to_meta_then_feed_date(self):
        no_label = PAGE.replace(b"Release Date", b"Something Else")
        page = adv.extract_page(no_label, URL, feed_pub_date="2024-01-01")
        self.assertEqual((page["published_at"], page["published_at_source"]), ("2024-01-01", "RSS pubDate"))
        meta = adv.extract_page(no_label.replace(b"</head>", b'<meta property="article:published_time" content="2024-05-05T00:00:00Z"></head>'), URL)
        self.assertEqual((meta["published_at"], meta["published_at_source"]), ("2024-05-05", "page meta tag"))

    def test_no_date_anywhere_is_warning(self):
        no_code = PAGE.replace(b"Release Date", b"Something Else").replace(b"AA00-001A", b"NOCODE")
        page = adv.extract_page(no_code, "https://www.cisa.gov/news-events/cybersecurity-advisories/fixture-page")
        self.assertIsNone(page["published_at"])
        self.assertTrue(any("no publication date" in w for w in page["warnings"]))

    def test_alert_code_falls_back_to_url_or_title(self):
        page = adv.extract_page(PAGE.replace(b"Alert Code", b"Other"), URL)
        self.assertEqual(page["alert_code"], "AA00-001A")

    def test_short_page_is_warned(self):
        page = adv.extract_page(b"<html><body><main><h1>Tiny</h1><p>Short.</p></main></body></html>", URL)
        self.assertTrue(any("very little text" in w for w in page["warnings"]))

    def test_missing_title_is_a_problem(self):
        page = adv.extract_page(b"<html><body><main><p>text only</p></main></body></html>", URL)
        self.assertTrue(any("no title" in p for p in page["problems"]))

    def test_page_without_main_drops_site_header_and_footer(self):
        html = (b"<html><body><header>HEADER CHROME</header><h1>Plain Page</h1>"
                b"<p>Body text of the plain page.</p><footer>FOOTER CHROME</footer></body></html>")
        page = adv.extract_page(html, URL)
        self.assertIn("Body text of the plain page.", page["text"])
        self.assertNotIn("CHROME", page["text"])

    def test_text_in_plain_divs_is_kept_once(self):
        html = (b"<html><body><main><h1>Div Page</h1><div>Free text in a div.</div>"
                b"<ul><li><div>Item inside li div</div></li></ul></main></body></html>")
        text = adv.extract_page(html, URL)["text"]
        self.assertEqual(text.count("Free text in a div."), 1)
        self.assertEqual(text.count("Item inside li div"), 1)


ARCHIVED = f"""<html><head><title>x</title></head><body><main>
 <h3>Archived Content</h3>
 <div>Cybersecurity Advisory</div>
 <h1>Fixture Archived Advisory</h1>
 <div>Last Revised</div><div>July 08, 2021</div>
 <div>Alert Code</div><div>AA21-131A</div>
 <h2>Summary</h2><p>Body text. {FILLER}</p>
</main></body></html>""".encode("utf-8")


class DerivedDateAndMetadataTests(unittest.TestCase):
    def test_date_from_alert_code(self):
        for code, expected in [("AA21-131A", "2021-05-11"), ("AA23-075A", "2023-03-16"), ("AA25-203A", "2025-07-22"),
                               ("aa00-001a", "2000-01-01"), ("AA24-366B", "2024-12-31")]:
            self.assertEqual(adv.date_from_alert_code(code), expected, code)
        for bad in ("AA21-000A", "AA21-400A", "AA23-366A", "ICSA-21-131-01", "", None):  # 2023 has no day 366
            self.assertIsNone(adv.date_from_alert_code(bad), bad)

    def test_archived_page_uses_a_clearly_marked_derived_date(self):
        page = adv.extract_page(ARCHIVED, "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a")
        self.assertIsNone(page["release_date"])
        self.assertEqual(page["last_revised"], "2021-07-08")
        self.assertEqual(page["published_at"], "2021-05-11")
        self.assertTrue(page["published_at_is_derived"])
        self.assertIn("DERIVED", page["published_at_source"])
        self.assertTrue(page["archived"])
        self.assertEqual(page["advisory_type"], "Cybersecurity Advisory")
        self.assertEqual(page["warnings"], [])

    def test_metadata_lines_are_not_in_the_text(self):
        page = adv.extract_page(ARCHIVED, "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a")
        for noise in ("Archived Content", "Last Revised", "Alert Code", "July 08, 2021", "AA21-131A", "Cybersecurity Advisory"):
            self.assertNotIn(noise, page["text"], noise)
        self.assertIn("## Summary", page["text"])
        self.assertIn("# Fixture Archived Advisory", page["text"])

    def test_label_date_beats_derived_and_agreement_is_recorded(self):
        page = adv.extract_page(PAGE, URL)  # label says 2025-02-19, code AA00-001A implies 2000-01-01
        self.assertEqual(page["published_at"], "2025-02-19")
        self.assertFalse(page["published_at_is_derived"])
        self.assertIs(page["release_date_matches_alert_code"], False)
        self.assertTrue(any("differs from the date implied" in w for w in page["warnings"]))
        agreeing = PAGE.replace(b"February 19, 2025", b"January 1, 2000")
        self.assertIs(adv.extract_page(agreeing, URL)["release_date_matches_alert_code"], True)

    def test_feed_date_beats_derived(self):
        page = adv.extract_page(ARCHIVED, "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a", feed_pub_date="2021-05-12")
        self.assertEqual((page["published_at"], page["published_at_is_derived"]), ("2021-05-12", False))


LISTING = b"""<html><body><main>
<a href="/news-events/cybersecurity-advisories/aa25-203a">Interlock</a>
<a href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a/">duplicate</a>
<a href="https://cisa.gov/news-events/cybersecurity-advisories/aa24-109a?utm=1">Akira</a>
<a href="/news-events/analysis-reports/ar25-100a">analysis report</a>
<a href="/news-events/alerts/2025/01/01/some-alert">alert (not followed)</a>
<a href="/news-events/ics-advisories/icsa-25-100-01">ICS (not followed)</a>
<a href="/news-events/cybersecurity-advisories?page=2">next page (not an advisory)</a>
<a href="https://example.com/news-events/cybersecurity-advisories/aa25-999a">off-site</a>
</main></body></html>"""


class DiscoveryTests(unittest.TestCase):
    def test_extract_links(self):
        links = adv.extract_links(LISTING, "https://www.cisa.gov/news-events/cybersecurity-advisories", adv.ALLOWED_HOST)
        self.assertEqual([l.rsplit("/", 1)[-1] for l in links], ["aa25-203a", "aa24-109a", "ar25-100a"])

    def test_discovered_candidates_sit_between_feed_and_seed(self):
        feed = adv.parse_feed(RSS)
        cands, _ = adv.build_candidates(
            ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-009a"], feed,
            ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-004a"], adv.ALLOWED_HOST, 10,
            discovered=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-003a",   # also in the feed
                        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa00-007a"])
        self.assertEqual([(c["url"].rsplit("/", 1)[-1], c["source"]) for c in cands],
                         [("aa00-009a", "manual"), ("aa00-003a", "feed"), ("aa00-002a", "feed"),
                          ("aa00-007a", "discovered"), ("aa00-004a", "seed")])


class RecordTests(unittest.TestCase):
    def test_normalize_record_fields_and_provenance(self):
        extracted = adv.extract_page(PAGE, URL)
        entry = {"url": URL, "final_url": URL, "raw_file": "aa00-001a__x.html", "retrieved_at": "2000-01-01T00:00:00+00:00",
                 "sha256": "abc", "feed_title": "Feed", "feed_pub_date": "2024-01-01", "feed_categories": []}
        rec = adv.normalize_record(extracted, entry)
        self.assertEqual((rec["doc_id"], rec["record_id"], rec["slug"]), ("cisa-advisory:aa00-001a",) * 2 + ("aa00-001a",))
        self.assertEqual(rec["raw_file_reference"], "data/raw/advisories/aa00-001a__x.html")
        self.assertEqual(rec["evidence_type"], "stated_in_source")
        for key in ("source_name", "source_url", "source_record_id", "retrieved_at", "published_at", "original_format",
                    "raw_sha256", "collection_method"):
            self.assertTrue(rec[key], key)
        self.assertIn("NOT verified", rec["mentions_note"])


class FakeResponse:
    def __init__(self, status=200, text="", reason=""):
        self.status_code, self.text, self.reason, self.headers = status, text, reason, {}


class FakeSession:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, timeout=None):
        self.calls.append(url)
        return self.responses.pop(0)


class RobotsAndFetchTests(unittest.TestCase):
    def test_robots_loaded_and_applied(self):
        session = FakeSession([FakeResponse(200, "User-agent: *\nDisallow: /private\n")])
        robots = adv.Robots(session, "CyberIntelGraph/0.1", 5)
        self.assertFalse(robots.allowed("https://www.cisa.gov/private/page"))
        self.assertTrue(robots.allowed("https://www.cisa.gov/news-events/x"))
        self.assertEqual(len(session.calls), 1)  # robots.txt loaded once per site
        self.assertIn("loaded", robots.status())

    def test_robots_404_means_allowed_and_403_is_noted(self):
        for code, note in ((404, "no robots.txt"), (403, "not retrievable")):
            robots = adv.Robots(FakeSession([FakeResponse(code)]), "CyberIntelGraph/0.1", 5)
            self.assertTrue(robots.allowed("https://www.cisa.gov/x"))
            self.assertIn(note, robots.status())

    def test_403_is_not_retried_or_bypassed(self):
        session = FakeSession([FakeResponse(403, reason="Forbidden")])
        with self.assertRaises(adv.CollectionError) as ctx:
            adv.fetch(session, "https://www.cisa.gov/x", 5, 4)
        self.assertEqual(len(session.calls), 1)
        self.assertIn("does not try to bypass", str(ctx.exception))

    def test_404_is_not_retried(self):
        session = FakeSession([FakeResponse(404, reason="Not Found")])
        with self.assertRaises(adv.CollectionError):
            adv.fetch(session, "https://www.cisa.gov/x", 5, 4)
        self.assertEqual(len(session.calls), 1)


if __name__ == "__main__":
    unittest.main()
