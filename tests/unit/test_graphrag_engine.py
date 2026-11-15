import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from canonical.models import Evidence, Relationship                            # noqa: E402
from graphrag_engine.indexing import extract as ex                              # noqa: E402
from graphrag_engine.indexing import reports as rp                              # noqa: E402
from graphrag_engine.indexing import run_index                                  # noqa: E402
from graphrag_engine.indexing.communities import build_graph, community_table, detect_communities  # noqa: E402
from graphrag_engine.indexing.llm_cache import CachedLLM, CallBudgetExceeded    # noqa: E402
from graphrag_engine.indexing.resolve import build_canonical_index, merge       # noqa: E402
from graphrag_engine.indexing.select import doc_stats, select_docs              # noqa: E402
from graphrag_engine.retrieval.global_search import global_search, rank_reports  # noqa: E402
from rag.llm import LLMError, LLMResult                                         # noqa: E402

NAMES = {"TrickBot": "Malware", "Ryuk": "Malware", "Conti": "Malware", "Wizard Spider": "ThreatActor",
         "CVE-2020-1472": "Vulnerability", "T1059.001": "AttackTechnique", "healthcare": "Sector"}
RULES = [("Wizard Spider", "USES", "TrickBot"), ("TrickBot", "DELIVERS", "Ryuk"),
         ("Wizard Spider", "EXPLOITS", "CVE-2020-1472"), ("Ryuk", "TARGETS", "healthcare"),
         ("Wizard Spider", "USES", "T1059.001")]


class FakeLLM:
    """Rule-based stand-in for Groq: reads the prompt, answers deterministically."""
    def __init__(self, fail=None):
        self.calls, self.fail = 0, fail

    def complete(self, system, user):
        self.calls += 1
        if self.fail:
            raise LLMError(self.fail)
        if system.startswith("You extract"):
            text = user
            ents = [{"name": n, "type": t, "description": f"{n} in the advisory"} for n, t in NAMES.items() if n in text]
            rels, chunk = [], None
            for part in re.split(r"(\[advisory_[^\]]+\])", text):
                if part.startswith("[advisory_"):
                    chunk = part.strip("[]")
                    continue
                for sent in re.split(r"(?<=\.)\s+", part):
                    for a, t, b in RULES:
                        if a in sent and b in sent:
                            rels.append({"source": a, "target": b, "type": t, "description": f"{a} {t} {b}",
                                         "quote": sent.strip(), "chunk": chunk})
            body = json.dumps({"entities": ents, "relationships": rels})
        elif system.startswith("You write short"):
            ids = re.findall(r"\[(advisory_[^\]]+)\]", user)
            body = json.dumps({"title": "Ryuk delivery chain", "summary": "Wizard Spider uses TrickBot to deliver Ryuk.",
                               "findings": [{"finding": "TrickBot delivers Ryuk", "support": ids[:1] + ["bogus_chunk"]}]})
        elif system.startswith("You answer a question"):
            q = user.split("\n")[0].lower()
            hit = "ryuk" in user.split("REPORT", 1)[1].lower() and "ryuk" in q
            body = json.dumps({"answer": "TrickBot delivers Ryuk." if hit else "", "score": 80 if hit else 0})
        else:
            body = "Wizard Spider chains TrickBot into Ryuk [C000]. Also see [C099]."
        return LLMResult(text=body, model="fake", finish_reason="stop", usage={"total_tokens": 10})


def mk(doc, i, text, cves=(), techs=()):
    return {"chunk_id": f"advisory_{doc}_chunk_{i:03d}", "doc_id": f"advisory_{doc}", "report_id": f"IntelligenceReport:{doc}",
            "chunk_index": i, "text": text, "embedding_text": text, "title": f"Title {doc}", "source_url": f"https://x/{doc}",
            "cve_ids": list(cves), "technique_ids": list(techs)}


def corpus():
    filler = "This sentence is ordinary filler text used to pad the chunk to a sensible size for testing. " * 2
    rows = []
    for doc, extra in (("aa20-302a", "Wizard Spider uses TrickBot for access. TrickBot delivers Ryuk in healthcare."),
                       ("aa99-001a", "Wizard Spider exploits CVE-2020-1472 and uses T1059.001 for execution. Conti also appears.")):
        rows += [mk(doc, 1, filler + extra, cves=["CVE-2020-1472"] if "CVE" in extra else [])]
        rows += [mk(doc, i, filler + f" Section {i} Ryuk TrickBot detail.") for i in range(2, 7)]
    rows += [mk("big-doc", i, filler) for i in range(1, 100)]                # 99 chunks: too large for auto-select
    return rows


def write_corpus(tmp):
    p = os.path.join(tmp, "chunks.jsonl")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for r in corpus():
            fh.write(json.dumps(r) + "\n")
    return p


class SelectTests(unittest.TestCase):
    def setUp(self):
        self.by_doc = {}
        for r in corpus():
            self.by_doc.setdefault(r["doc_id"], []).append(r)

    def test_auto_select_skips_oversized_and_orders_by_id_density(self):
        sel = select_docs(self.by_doc, n=5)
        self.assertEqual({d["doc_id"] for d in sel}, {"advisory_aa20-302a", "advisory_aa99-001a"})
        self.assertGreaterEqual(sel[0]["id_density"], sel[1]["id_density"])

    def test_explicit_pick_and_errors(self):
        self.assertEqual(select_docs(self.by_doc, explicit=["AA99-001A"])[0]["doc_id"], "advisory_aa99-001a")
        with self.assertRaises(ValueError):
            select_docs(self.by_doc, explicit=["nope"])
        with self.assertRaises(ValueError):
            select_docs(self.by_doc, explicit=["advisory_aa"])        # ambiguous

    def test_stats(self):
        s = {d["doc_id"]: d for d in doc_stats(self.by_doc)}
        self.assertEqual(s["advisory_aa99-001a"]["chunks"], 6)


class WindowTests(unittest.TestCase):
    def test_windows_pack_in_order_and_skip_boilerplate(self):
        rows = [mk("d", i, "word " * 100) for i in range(1, 8)] + [mk("d", 8, "Last Revised: today")]
        ws = ex.make_windows(rows, max_words=250)
        self.assertEqual([len(w.chunk_ids) for w in ws], [2, 2, 2, 1])
        self.assertNotIn("advisory_d_chunk_008", sum((w.chunk_ids for w in ws), []))
        self.assertTrue(ws[0].text.startswith("[advisory_d_chunk_001]"))
        self.assertEqual(ws[1].window_id, "advisory_d_w02")

    def test_single_huge_chunk_is_capped(self):
        w = ex.make_windows([mk("d", 1, "word " * 5000)], max_words=100, hard_cap_words=300)[0]
        self.assertEqual(w.words, 300)


class SplitTests(unittest.TestCase):
    def window(self, n_chunks, words=100):
        rows = [mk("d", i, " ".join(f"w{i}x{j}" for j in range(words))) for i in range(1, n_chunks + 1)]
        return ex.make_windows(rows, max_words=10_000)[0]

    def test_multi_chunk_split_is_balanced_ordered_and_lossless(self):
        w = self.window(5)
        a, b = ex.split_window(w)
        self.assertEqual(a.chunk_ids + b.chunk_ids, w.chunk_ids)
        self.assertEqual((a.window_id, b.window_id), (w.window_id + "a", w.window_id + "b"))
        self.assertEqual(a.words + b.words, w.words)
        self.assertLessEqual(abs(a.words - b.words), 100)
        self.assertEqual(ex.split_window(a)[0].window_id, w.window_id + "aa")

    def test_single_chunk_split_halves_the_text_and_tiny_chunk_cannot_split(self):
        w = self.window(1, words=200)
        a, b = ex.split_window(w)
        self.assertEqual(a.chunk_ids, b.chunk_ids)
        self.assertEqual(a.words + b.words, 200)
        self.assertNotEqual(a.text, b.text)
        self.assertIsNone(ex.split_window(self.window(1, words=40)))


class ParsingTests(unittest.TestCase):
    def test_parse_variants(self):
        self.assertEqual(ex.parse_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(ex.parse_json('Sure! {"a": [1, 2,],} Hope that helps'), {"a": [1, 2]})
        self.assertIsNone(ex.parse_json("no json here"))
        self.assertIsNone(ex.parse_json("[1, 2]"))
        self.assertIsNone(ex.parse_json(""))

    def test_quote_grounding(self):
        text = "The actors used TrickBot to deliver Ryuk ransomware."
        self.assertTrue(ex.quote_grounded("used TrickBot to deliver Ryuk", text))
        self.assertTrue(ex.quote_grounded("used TrickBot to deliver Ryuk ransomware widely", text, 0.8))
        self.assertFalse(ex.quote_grounded("completely different invented sentence here", text))
        self.assertFalse(ex.quote_grounded("TrickBot", text))                    # too short to count


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.w = ex.make_windows([mk("d", 1, "Wizard Spider uses TrickBot to deliver Ryuk ransomware. "
                                              "Exploited CVE-2020-1472 and technique T1059.001 (PowerShell) were seen. " * 2)])[0]

    def test_ungrounded_and_malformed_items_are_dropped_and_counted(self):
        raw = {"entities": [{"name": "TrickBot", "type": "malware"}, {"name": "Emotet", "type": "Malware"},
                            {"name": "Wizard Spider", "type": "banana"}, {"name": "", "type": "Tool"}, "junk",
                            {"name": "CVE-2020-1472", "type": "Vulnerability"}, {"name": "T1059.001 (PowerShell)", "type": "technique"}],
               "relationships": [
                   {"source": "Wizard Spider", "target": "TrickBot", "type": "USES", "quote": "Wizard Spider uses TrickBot", "chunk": "x"},
                   {"source": "TrickBot", "target": "Ryuk", "type": "DELIVERS", "quote": "TrickBot to deliver Ryuk ransomware"},
                   {"source": "TrickBot", "target": "CVE-2020-1472", "type": "EXPLOITS", "quote": "TrickBot exploits CVE-2020-1472 widely in the wild"},
                   {"source": "TrickBot", "target": "TrickBot", "type": "USES", "quote": "TrickBot uses TrickBot"}]}
        out = ex.validate_extraction(raw, self.w)
        names = {e["name"]: e for e in out["entities"]}
        self.assertEqual(set(names), {"TrickBot", "CVE-2020-1472", "T1059.001 (PowerShell)"})
        self.assertEqual(names["CVE-2020-1472"]["cve_id"], "CVE-2020-1472")
        self.assertEqual(names["T1059.001 (PowerShell)"]["attack_id"], "T1059.001")
        self.assertEqual(out["dropped"]["entity_not_in_text"], 1)
        self.assertEqual(out["dropped"]["entity_bad_type"], 1)
        self.assertEqual(out["dropped"]["entity_no_name"], 1)
        self.assertEqual(out["dropped"]["entity_not_object"], 1)
        # "Wizard Spider" was dropped (bad type) so its relationship has an unknown endpoint;
        # TrickBot->Ryuk lost Ryuk? no: Ryuk was never extracted as an entity -> unknown endpoint too
        self.assertEqual(out["relationships"], [])
        self.assertGreaterEqual(out["dropped"]["rel_unknown_endpoint"], 2)

    def test_good_relationship_kept_with_chunk_repair_and_type_fallback(self):
        raw = {"entities": [{"name": "TrickBot", "type": "Malware"}, {"name": "Ryuk", "type": "Malware"}],
               "relationships": [{"source": "TrickBot", "target": "Ryuk", "type": "drops", "description": "d",
                                  "quote": "uses TrickBot to deliver Ryuk ransomware", "chunk": "wrong-id"}]}
        out = ex.validate_extraction(raw, self.w)
        r = out["relationships"][0]
        self.assertEqual((r["type"], r["chunk"]), ("RELATED_TO", "advisory_d_chunk_001"))
        self.assertEqual(out["dropped"]["rel_type_fallback"], 1)

    def test_hallucinated_quote_dropped(self):
        raw = {"entities": [{"name": "TrickBot", "type": "Malware"}, {"name": "Ryuk", "type": "Malware"}],
               "relationships": [{"source": "TrickBot", "target": "Ryuk", "type": "DELIVERS",
                                  "quote": "completely invented sentence about something else entirely"}]}
        out = ex.validate_extraction(raw, self.w)
        self.assertEqual(out["relationships"], [])
        self.assertEqual(out["dropped"]["rel_quote_not_in_text"], 1)


class CacheTests(unittest.TestCase):
    def make(self, **kw):
        self.t = [0.0]
        self.slept = []
        self.llm = FakeLLM()
        return CachedLLM(self.llm, tempfile.mkdtemp(), "fake", min_interval=2.5,
                         sleep=lambda s: (self.slept.append(s), self.t.__setitem__(0, self.t[0] + s)),
                         clock=lambda: self.t[0], **kw)

    def test_second_identical_call_is_free_and_tokens_counted(self):
        c = self.make()
        a = c.complete("k", "You answer a question", "q\nREPORT x")
        b = c.complete("k", "You answer a question", "q\nREPORT x")
        self.assertFalse(a["from_cache"])
        self.assertTrue(b["from_cache"])
        self.assertEqual((c.calls, c.cache_hits, c.tokens, self.llm.calls), (1, 1, 10, 1))

    def test_budget_and_pacing(self):
        c = self.make(max_calls=2)
        c.complete("k", "s", "one")
        c.complete("k", "s", "two")
        self.assertEqual(len(self.slept), 1)
        self.assertAlmostEqual(self.slept[0], 2.5)
        with self.assertRaises(CallBudgetExceeded):
            c.complete("k", "s", "three")
        c.complete("k", "s", "one")                       # cached calls never hit the budget

    def test_different_kind_or_model_misses_cache(self):
        c = self.make()
        c.complete("a", "s", "u")
        c.complete("b", "s", "u")
        self.assertEqual(c.calls, 2)


class ExtractWindowTests(unittest.TestCase):
    def setUp(self):
        self.w = ex.make_windows([mk("d", 1, "Wizard Spider uses TrickBot to deliver Ryuk. " * 3)])[0]

    def cached(self, llm):
        return CachedLLM(llm, tempfile.mkdtemp(), "fake", min_interval=0, sleep=lambda s: None)

    def test_repair_retry_then_success(self):
        replies = iter(["not json at all", json.dumps({"entities": [{"name": "TrickBot", "type": "Malware"}], "relationships": []})])

        class Seq:
            calls = 0

            def complete(s, system, user):
                s.calls += 1
                return LLMResult(text=next(replies), model="m")
        llm = Seq()
        out = ex.extract_window(self.cached(llm), self.w)
        self.assertEqual(len(out["entities"]), 1)
        self.assertEqual(llm.calls, 2)

    def test_two_bad_replies_and_llm_errors_become_error_records(self):
        class Bad:
            def complete(s, system, user):
                return LLMResult(text="nope", model="m")
        self.assertIn("error", ex.extract_window(self.cached(Bad()), self.w))
        self.assertIn("llm:", ex.extract_window(self.cached(FakeLLM(fail="HTTP 429")), self.w)["error"])


class MergeTests(unittest.TestCase):
    def results(self):
        llm = CachedLLM(FakeLLM(), tempfile.mkdtemp(), "fake", min_interval=0, sleep=lambda s: None)
        rows = corpus()
        res, meta = [], {}
        for doc in ("advisory_aa20-302a", "advisory_aa99-001a"):
            for w in ex.make_windows([r for r in rows if r["doc_id"] == doc], 1400):
                res.append(ex.extract_window(llm, w))
                for cid, t in w.chunk_texts.items():
                    meta[cid] = {"source_url": w.source_url, "_text_l": t.lower(), "_window": w.window_id}
        return res, meta

    def test_merge_dedupes_links_ids_and_builds_valid_evidence(self):
        res, meta = self.results()
        canonical = build_canonical_index([
            {"canonical_id": "Malware:S0266", "entity_type": "Malware", "name": "TrickBot", "aliases": ["Trickbot"]},
            {"canonical_id": "ThreatActor:G0102", "entity_type": "ThreatActor", "name": "Wizard Spider", "aliases": []},
            {"canonical_id": "Malware:S0446", "entity_type": "Malware", "name": "Ryuk", "aliases": []},
            {"canonical_id": "Tool:S0446b", "entity_type": "Tool", "name": "Ryuk", "aliases": []},
            {"canonical_id": "Vulnerability:CVE-2020-1472", "entity_type": "Vulnerability", "name": "Zerologon", "aliases": []}])
        ents, rels = merge(res, meta, canonical)
        by_name = {e["name"]: e for e in ents}
        self.assertEqual(by_name["TrickBot"]["node_id"], "Malware:S0266")
        self.assertTrue(by_name["TrickBot"]["linked"])
        self.assertEqual(by_name["TrickBot"]["mentions"], len([r for r in res for e in r["entities"] if e["name"] == "TrickBot"]))
        self.assertEqual(by_name["Wizard Spider"]["node_id"], "ThreatActor:G0102")
        self.assertEqual(sorted(by_name["TrickBot"]["doc_ids"]), ["advisory_aa20-302a", "advisory_aa99-001a"][:len(by_name["TrickBot"]["doc_ids"])])
        # Ryuk matches two compatible canonical entities (Malware + Tool) -> ambiguous, stays a candidate
        self.assertFalse(by_name["Ryuk"]["linked"])
        self.assertEqual(by_name["Ryuk"]["ambiguous_with"], ["Malware:S0446", "Tool:S0446b"])
        self.assertEqual(by_name["Ryuk"]["node_id"], "Malware:cand-ryuk")
        self.assertEqual(by_name["CVE-2020-1472"]["node_id"], "Vulnerability:CVE-2020-1472")
        self.assertTrue(by_name["CVE-2020-1472"]["in_canonical"])
        self.assertEqual(by_name["T1059.001"]["node_id"], "AttackTechnique:T1059.001")
        self.assertFalse(by_name["T1059.001"]["in_canonical"])
        self.assertEqual(by_name["healthcare"]["node_id"], "Sector:cand-healthcare")
        ids = [e["node_id"] for e in ents]
        self.assertEqual(len(ids), len(set(ids)))
        for r in rels:                                       # canonical pydantic models accept every record
            Relationship(**r)
            self.assertEqual(r["evidence_type"], "llm_extracted_candidate")
            self.assertTrue(r["evidence"])
            self.assertIn(r["source_id"], ids)
            self.assertIn(r["target_id"], ids)
            for ev in r["evidence"]:
                Evidence(**ev)
        for e in ents:
            for ev in e["evidence"]:
                Evidence(**ev)
        uses = next(r for r in rels if r["rel_type"] == "USES" and r["target_id"] == "Malware:S0266")
        self.assertEqual(uses["rel_id"], "USES|ThreatActor:G0102|Malware:S0266")

    def test_without_canonical_everything_nonid_is_candidate(self):
        res, meta = self.results()
        ents, _ = merge(res, meta, None)
        self.assertTrue(all(not e["linked"] for e in ents if e["type"] not in ("Vulnerability", "AttackTechnique")))
        self.assertIsNone(next(e for e in ents if e["name"] == "CVE-2020-1472")["in_canonical"])

    def test_type_conflict_resolved_by_majority(self):
        mkres = lambda wid, t: {"window_id": wid, "doc_id": "d", "entities": [{"name": "Conti", "type": t, "description": ""}],   # noqa: E731
                                "relationships": [], "dropped": {}, "raw_counts": {"entities": 1, "relationships": 0}}
        ents, _ = merge([mkres("w1", "Malware"), mkres("w2", "Malware"), mkres("w3", "ThreatActor")], {}, None)
        self.assertEqual((ents[0]["type"], ents[0]["type_conflict"]), ("Malware", ["ThreatActor"]))

    def test_error_windows_are_skipped(self):
        ents, rels = merge([{"window_id": "w", "doc_id": "d", "error": "x"}], {}, None)
        self.assertEqual((ents, rels), ([], []))


class CommunityTests(unittest.TestCase):
    def graph(self):
        def e(i):
            return {"node_id": f"Malware:{i}", "name": i, "type": "Malware", "description": "", "doc_ids": ["d"], "evidence": []}

        def r(a, b):
            return {"rel_id": f"USES|Malware:{a}|Malware:{b}", "rel_type": "USES", "source_id": f"Malware:{a}",
                    "target_id": f"Malware:{b}", "evidence": [{"record_ref": f"c_{a}"}],
                    "properties": {"weight": 1, "description": ""}}
        ents = [e(x) for x in "abcdefg"]
        rels = [r("a", "b"), r("b", "c"), r("a", "c"), r("d", "e"), r("e", "f"), r("d", "f"), r("c", "d")]
        return ents, rels

    def test_two_triangles_make_two_communities_numbered_by_size_and_stable(self):
        ents, rels = self.graph()
        g = build_graph(ents, rels)
        c1, c2 = detect_communities(g), detect_communities(g)
        self.assertEqual(c1, c2)
        sizes = [len(c) for c in c1]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertIn(1, sizes)                              # isolated 'g'
        table = community_table(g, c1, ents, rels)
        self.assertEqual([t["community_id"] for t in table], [f"C{i:03d}" for i in range(len(table))])
        self.assertEqual(sorted(n for t in table for n in t["node_ids"]), sorted(e["node_id"] for e in ents))

    def test_empty_graph(self):
        self.assertEqual(detect_communities(build_graph([], [])), [])


class ReportTests(unittest.TestCase):
    def test_validate_filters_unknown_support(self):
        out = rp.validate_report({"title": "T", "summary": "S", "findings": [
            {"finding": "a", "support": ["c1", "bogus"]}, {"finding": "b", "support": ["bogus"]}, {"finding": ""}, "x"]}, ["c1"])
        self.assertEqual([f["support"] for f in out["findings"]], [["c1"], []])
        self.assertEqual(out["unsupported_findings"], 1)
        self.assertIsNone(rp.validate_report({"title": "", "summary": "S"}, []))

    def test_write_report_end_to_end(self):
        ents = {"Malware:a": {"node_id": "Malware:a", "name": "A", "type": "Malware", "description": "d"},
                "Malware:b": {"node_id": "Malware:b", "name": "B", "type": "Malware", "description": "d"}}
        rels = [{"rel_id": "USES|Malware:a|Malware:b", "rel_type": "USES", "source_id": "Malware:a", "target_id": "Malware:b",
                 "properties": {"weight": 2, "description": "A uses B"}, "evidence": [{"record_ref": "advisory_x_chunk_001"}]}]
        comm = {"community_id": "C000", "size": 2, "node_ids": ["Malware:a", "Malware:b"], "top_entities": ["A", "B"], "doc_ids": ["x"]}
        c = CachedLLM(FakeLLM(), tempfile.mkdtemp(), "fake", min_interval=0, sleep=lambda s: None)
        rep = rp.write_report(c, comm, ents, rels)
        self.assertEqual(rep["title"], "Ryuk delivery chain")
        self.assertEqual(rep["findings"][0]["support"], ["advisory_x_chunk_001"])      # 'bogus_chunk' removed


class GlobalSearchTests(unittest.TestCase):
    REPORTS = [{"community_id": "C000", "title": "Ryuk chain", "summary": "TrickBot delivers Ryuk", "findings": [], "top_entities": ["Ryuk"]},
               {"community_id": "C001", "title": "Phishing", "summary": "Emails with loaders", "findings": [], "top_entities": ["Emotet"]},
               {"community_id": "C002", "title": "Broken", "error": "x"}]

    def llm(self):
        return CachedLLM(FakeLLM(), tempfile.mkdtemp(), "fake", min_interval=0, sleep=lambda s: None)

    def test_rank_pads_to_k(self):
        self.assertEqual(rank_reports("ryuk", self.REPORTS[:2], 2)[0]["community_id"], "C000")
        self.assertEqual(len(rank_reports("zzz", self.REPORTS[:2], 2)), 2)

    def test_map_reduce_flags_unknown_citation(self):
        out = global_search("Which ransomware does TrickBot deliver ryuk?", self.REPORTS, self.llm(), top_reports=2)
        self.assertEqual([p["community_id"] for p in out["partials"]], ["C000"])
        self.assertEqual(out["cited"], ["C000", "C099"])
        self.assertEqual(out["unknown_citations"], ["C099"])

    def test_no_useful_report_skips_reduce(self):
        llm = self.llm()
        out = global_search("something unrelated", self.REPORTS, llm, top_reports=2)
        self.assertEqual(out["partials"], [])
        self.assertIn("do not contain", out["answer"])
        self.assertEqual(llm.llm.calls, 2)                   # only the two map calls


class RunIndexTests(unittest.TestCase):
    def args(self, tmp, **kw):
        base = dict(chunks=write_corpus(tmp), out_dir=os.path.join(tmp, "g"), canonical=os.path.join(tmp, "none.json"),
                    docs=5, pick="", window_words=1400, model="fake", max_tokens=100, effort="low", min_interval=0,
                    max_calls=100, min_community_size=2, max_communities=5, seed=42, skip_reports=False,
                    allow_partial=False, dry_run=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def setUp(self):
        self.cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)                                   # run() writes outputs/reports relative to cwd
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def tearDown(self):
        os.chdir(self.cwd)

    def test_dry_run_makes_no_calls_and_writes_nothing(self):
        llm = FakeLLM()
        out = run_index.run(self.args(self.tmp, dry_run=True), llm=llm)
        self.assertTrue(out["dry_run"])
        self.assertEqual(llm.calls, 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "g")))
        self.assertEqual(len(out["selected"]), 2)

    def test_full_run_outputs_then_rerun_is_free(self):
        a = self.args(self.tmp)
        llm = FakeLLM()
        s = run_index.run(a, llm=llm, sleep=lambda x: None)
        self.assertEqual(s["windows_failed"], 0)
        self.assertGreater(s["entities"], 5)
        self.assertGreater(s["communities_reported"], 0)
        for name in ("entities", "relationships", "communities", "community_reports", "run_summary", "selection"):
            with open(os.path.join(a.out_dir, f"{name}.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["metadata"]["evidence_type"], "llm_extracted_candidate")
            self.assertEqual(doc["metadata"]["count"], len(doc["records"]))
        first_calls = llm.calls
        s2 = run_index.run(a, llm=llm, sleep=lambda x: None)
        self.assertEqual(llm.calls, first_calls)             # everything came from the cache
        self.assertEqual(s2["llm_calls"], 0)
        self.assertEqual((s2["entities"], s2["relationships"]), (s["entities"], s["relationships"]))

    def test_budget_stop_is_resumable(self):
        a = self.args(self.tmp, max_calls=1)
        out = run_index.run(a, llm=FakeLLM(), sleep=lambda x: None)
        self.assertIn("call budget", out["stopped"])
        self.assertFalse(os.path.exists(os.path.join(a.out_dir, "entities.json")))
        a2 = self.args(self.tmp, max_calls=100)
        self.assertEqual(run_index.run(a2, llm=FakeLLM(), sleep=lambda x: None)["windows_failed"], 0)

    def test_three_failures_in_a_row_stop_the_run(self):
        out = run_index.run(self.args(self.tmp, window_words=100), llm=FakeLLM(fail="HTTP 429"), sleep=lambda x: None)
        self.assertIn("3 failures", out["stopped"])

    def test_http_413_splits_the_window_and_the_run_completes(self):
        class Big413(FakeLLM):
            def complete(self, system, user):
                if system.startswith("You extract") and len(user) > 900:
                    self.calls += 1
                    raise LLMError('Groq HTTP 413: {"error":{"message":"Request too large for model"}}')
                return super().complete(system, user)
        s = run_index.run(self.args(self.tmp, skip_reports=True), llm=Big413(), sleep=lambda x: None)
        self.assertEqual(s["windows_failed"], 0)
        self.assertGreater(s["windows_split"], 0)
        self.assertGreater(s["windows_ok"], s["windows"])                      # more leaf windows than planned
        with open(os.path.join(self.tmp, "g", "entities.json"), encoding="utf-8") as fh:
            ents = json.load(fh)["records"]
        trick = next(e for e in ents if e["name"] == "TrickBot")
        self.assertTrue(trick["evidence"])                                      # evidence survives split windows

    def test_unsplittable_413_is_a_failure_not_a_loop(self):
        class Always413(FakeLLM):
            def complete(self, system, user):
                self.calls += 1
                raise LLMError("Groq HTTP 413: Request too large")
        out = run_index.run(self.args(self.tmp, window_words=100), llm=Always413(), sleep=lambda x: None)
        self.assertIn("no window could be extracted", out["stopped"])           # ends, no recursion, no empty graph written
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "g", "entities.json")))

    def test_truncated_replies_are_counted(self):
        class Cut(FakeLLM):
            def complete(self, system, user):
                r = super().complete(system, user)
                return LLMResult(text=r.text, model=r.model, finish_reason="length", usage=r.usage)
        s = run_index.run(self.args(self.tmp, skip_reports=True), llm=Cut(), sleep=lambda x: None)
        self.assertGreater(s["truncated_replies"], 0)

    def test_skip_reports_and_pick(self):
        s = run_index.run(self.args(self.tmp, skip_reports=True, pick="aa99-001a"), llm=FakeLLM(), sleep=lambda x: None)
        self.assertEqual((s["advisories"], s["communities_reported"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
