import json
import os
import random
import sys
import tempfile
import unittest
import zlib

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from rag.answer import answer_question                                    # noqa: E402
from rag.bm25 import BM25Index, tokenize                                  # noqa: E402
from rag.compare import baseline_check, load_titles                       # noqa: E402
from rag.evaluate import evaluate, make_identifier_probes                 # noqa: E402
from rag.hybrid import MODES, HybridRetriever, extract_identifiers        # noqa: E402
from rag.index import VectorIndex, build_index, load_chunks               # noqa: E402
from rag.retrieve import Retriever                                        # noqa: E402


class FakeEmbedder:
    """Bag-of-words hashing; `fixed_query_text` makes every query look like that text."""
    name, DIM = "fake-bow", 128

    def __init__(self, fixed_query_text=None):
        self.fixed = fixed_query_text

    def _vec(self, text):
        v = np.zeros(self.DIM, dtype=np.float32)
        for tok in text.lower().replace(">", " ").split():
            v[zlib.crc32(tok.strip(".,?:[]").encode()) % self.DIM] += 1
        return v

    def embed_documents(self, texts):
        return np.stack([self._vec(t) for t in texts])

    def embed_query(self, text):
        return self._vec(self.fixed if self.fixed else text)


def chunk(doc, n, text, cves=(), techs=()):
    return {"chunk_id": f"advisory_{doc}_chunk_{n:03d}", "doc_id": f"advisory_{doc}", "chunk_index": n,
            "text": text, "embedding_text": f"Title {doc}\n{text}", "heading_path": ["Title"],
            "title": f"Title {doc}", "source_url": f"https://x/{doc}", "cve_ids": list(cves),
            "technique_ids": list(techs)}


CHUNKS = [
    chunk("cisa-advisory-aa20-302a", 1, "Ransomware actors targeted hospitals using TrickBot malware T1566", techs=["T1566"]),
    chunk("cisa-advisory-aa20-302a", 2, "Apply patches and segment networks to reduce ransomware exposure"),
    chunk("cisa-advisory-aa24-001a", 1, "Firewall exploitation of CVE-2024-3400 allowed remote command execution", cves=["CVE-2024-3400"]),
    chunk("cisa-advisory-aa24-001a", 2, "Firewall vendors released patches for exploited vulnerabilities"),
    chunk("cisa-advisory-aa25-002a", 1, "Exploited vulnerabilities such as CVE-2025-0001 in firewall appliances were chained together", cves=["CVE-2025-0001"]),
    chunk("cisa-advisory-aa25-002a", 2, "PowerShell T1059.001 was used for execution of scripts", techs=["T1059.001"]),
    chunk("cisa-advisory-aa25-002a", 3, "Command and scripting interpreter T1059 activity observed", techs=["T1059"]),
    chunk("cisa-advisory-aa26-003a", 1, "Phishing attachments T1566 and T1204 delivered loaders", techs=["T1566", "T1204"]),
]


def build(tmp, chunks=CHUNKS):
    cp = os.path.join(tmp, "chunks.jsonl")
    with open(cp, "w", encoding="utf-8", newline="\n") as fh:
        for c in chunks:
            fh.write(json.dumps(c) + "\n")
    out = os.path.join(tmp, "idx")
    build_index(cp, FakeEmbedder(), out)
    return VectorIndex.load(out), load_chunks(cp)


class TokenizerTests(unittest.TestCase):
    def test_identifiers_stay_whole(self):
        toks = tokenize("Exploited CVE\u20112024\u20113400 via T1059.001 and CWE-79 in AA20-302A")
        for want in ("cve-2024-3400", "t1059.001", "t1059", "cwe-79", "aa20-302a"):
            self.assertIn(want, toks)
        self.assertNotIn("2024", toks)

    def test_stopwords_dropped_and_words_kept(self):
        self.assertEqual(tokenize("Which advisory is the firewall one"), ["advisory", "firewall", "one"])

    def test_no_false_technique_inside_words(self):
        self.assertNotIn("t1234", tokenize("part t1234abc"))


class Bm25Tests(unittest.TestCase):
    def test_rare_identifier_wins(self):
        idx = BM25Index([c["embedding_text"] for c in CHUNKS])
        top = idx.search("Which advisory discusses CVE-2024-3400?", 3)
        self.assertEqual(top[0][0], 2)
        self.assertTrue(all(s > 0 for _, s in top))

    def test_no_match_returns_empty_and_deterministic(self):
        idx = BM25Index([c["embedding_text"] for c in CHUNKS])
        self.assertEqual(idx.search("zzzzqqq", 5), [])
        self.assertEqual(idx.search("firewall patches", 5), idx.search("firewall patches", 5))

    def test_empty_corpus(self):
        self.assertEqual(BM25Index([]).search("anything"), [])


class IdentifierExtractionTests(unittest.TestCase):
    def test_extract(self):
        ids = extract_identifiers("cve-2024-3400, T1059.001 and t1566 plus AA20-302A (not T12345)")
        self.assertEqual(ids["cve"], ["CVE-2024-3400"])
        self.assertEqual(ids["technique"], ["T1059.001", "T1566"])
        self.assertEqual(ids["advisory"], ["aa20-302a"])

    def test_none(self):
        self.assertEqual(extract_identifiers("what is ransomware?"), {"cve": [], "technique": [], "advisory": []})


class IndexTieTests(unittest.TestCase):
    def test_duplicates_always_return_lowest_row(self):
        rng = np.random.default_rng(1)
        vecs = rng.random((300, 16)).astype(np.float32)
        vecs[200] = vecs[40]                    # identical twins
        idx = VectorIndex(vecs, [f"id{i}" for i in range(300)], {})
        for _ in range(20):
            self.assertEqual(idx.search(vecs[40], 1)[0][0], 40)
        self.assertEqual([r for r, _ in idx.search(vecs[40], 2)], [40, 200])


class HybridRetrieverTests(unittest.TestCase):
    def setUp(self):
        self.idx, self.chunks = build(tempfile.mkdtemp())
        self.emb = FakeEmbedder()

    def r(self, mode, emb=None):
        return HybridRetriever(self.idx, self.chunks, emb if emb is not None else self.emb, mode=mode)

    def test_dense_mode_equals_milestone7_retriever(self):
        q = "firewall exploitation patches"
        a = [(h.chunk_id, round(h.score, 6)) for h in self.r("dense").retrieve(q, 5)]
        b = [(h.chunk_id, round(h.score, 6)) for h in Retriever(self.idx, self.chunks, self.emb).retrieve(q, 5)]
        self.assertEqual(a, b)

    def test_bm25_mode_needs_no_embedder(self):
        hits = HybridRetriever(self.idx, self.chunks, None, mode="bm25").retrieve("CVE-2024-3400", 3)
        self.assertEqual(hits[0].chunk_id, "advisory_cisa-advisory-aa24-001a_chunk_001")

    def test_other_modes_require_embedder_and_valid_name(self):
        with self.assertRaises(ValueError):
            HybridRetriever(self.idx, self.chunks, None, mode="hybrid")
        with self.assertRaises(ValueError):
            HybridRetriever(self.idx, self.chunks, self.emb, mode="nope")

    def test_id_lookup_beats_a_misleading_dense_ranking(self):
        # every query "looks like" the phishing chunk, so dense search alone is wrong
        emb = FakeEmbedder(fixed_query_text="Phishing attachments delivered loaders")
        q = "Which advisory discusses CVE-2024-3400?"
        dense_top = self.r("dense", emb).retrieve(q, 1)[0].chunk_id
        self.assertEqual(dense_top, "advisory_cisa-advisory-aa26-003a_chunk_001")
        best = self.r("hybrid_ids", emb).retrieve(q, 3)
        self.assertEqual(best[0].chunk_id, "advisory_cisa-advisory-aa24-001a_chunk_001")
        self.assertEqual(best[0].id_matches, ["CVE-2024-3400"])
        self.assertIn("id:CVE-2024-3400", best[0].via)

    def test_keyword_weight_applies_only_when_cve_or_technique_in_question(self):
        def expected(h, w):
            e = w / (60 + h.bm25_rank) if h.bm25_rank else 0.0
            return e + (1 / (60 + h.dense_rank) if h.dense_rank else 0.0)
        r = HybridRetriever(self.idx, self.chunks, self.emb, mode="hybrid", id_weight=3.0)
        for q, w in (("Which advisory discusses CVE-2024-3400?", 3.0),
                     ("Which advisory describes technique T1566?", 3.0),
                     ("firewall patches", 1.0),
                     ("In AA20-302A which malware was used?", 1.0)):
            for h in r.retrieve(q, 4):
                self.assertAlmostEqual(h.score, expected(h, w), places=9, msg=q)

    def test_id_weight_one_restores_milestone8_scores(self):
        r = HybridRetriever(self.idx, self.chunks, self.emb, mode="hybrid", id_weight=1.0)
        for h in r.retrieve("Which advisory discusses CVE-2024-3400?", 4):
            exp = (1 / (60 + h.bm25_rank) if h.bm25_rank else 0.0) + (1 / (60 + h.dense_rank) if h.dense_rank else 0.0)
            self.assertAlmostEqual(h.score, exp, places=9)

    def test_heavy_keyword_weight_puts_the_id_chunk_first_despite_misleading_dense(self):
        emb = FakeEmbedder(fixed_query_text="Phishing attachments T1566 delivered loaders")
        top = HybridRetriever(self.idx, self.chunks, emb, mode="hybrid", id_weight=50.0).retrieve(
            "Which advisory discusses CVE-2024-3400?", 1)[0]
        self.assertIn("CVE-2024-3400", top.chunk["cve_ids"])

    def test_unknown_identifier_changes_nothing(self):
        q = "Which advisory discusses CVE-2099-9999 firewall?"
        a = [h.chunk_id for h in self.r("hybrid").retrieve(q, 5)]
        b = [h.chunk_id for h in self.r("hybrid_ids").retrieve(q, 5)]
        self.assertEqual(a, b)

    def test_technique_parent_and_child_are_related_not_exact(self):
        hits = self.r("hybrid_ids").retrieve("Which advisory describes technique T1059?", 3)
        ids = [h.chunk_id for h in hits]
        self.assertEqual(ids[0], "advisory_cisa-advisory-aa25-002a_chunk_003")          # exact T1059
        self.assertIn("advisory_cisa-advisory-aa25-002a_chunk_002", ids)                # T1059.001 related
        child = next(h for h in hits if h.chunk_id.endswith("aa25-002a_chunk_002"))
        self.assertIn("T1059.*~", child.id_matches)

    def test_advisory_id_in_question_promotes_that_document(self):
        hits = self.r("hybrid_ids").retrieve("In AA20-302A which malware was used?", 2)
        self.assertTrue(all("aa20-302a" in h.chunk["doc_id"] for h in hits))

    def test_k_larger_than_index_and_ranks_are_consecutive(self):
        hits = self.r("hybrid_ids").retrieve("firewall", 50)
        self.assertEqual([h.rank for h in hits], list(range(1, len(hits) + 1)))
        self.assertLessEqual(len(hits), len(self.chunks))

    def test_index_chunk_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            HybridRetriever(self.idx, self.chunks[:-1], self.emb)

    def test_all_modes_work_inside_the_answer_pipeline(self):
        class LLM:
            def complete(self, system, user):
                from rag.llm import LLMResult
                return LLMResult(text="Answer [advisory_cisa-advisory-aa24-001a_chunk_001]", model="m",
                                 usage={}, latency_s=0.0, finish_reason="stop")
        for mode in MODES:
            emb = None if mode == "bm25" else self.emb
            out = answer_question("CVE-2024-3400 firewall", self.r(mode, emb), LLM(), k=3)
            self.assertIn("via", out["retrieved"][0])
            self.assertFalse(out["citations"]["invalid"] and mode == "hybrid_ids"
                             and out["retrieved"][0]["chunk_id"] not in out["answer"])


class CompareToolTests(unittest.TestCase):
    def test_evaluate_runs_for_every_mode_and_id_tier_helps_needle_hits(self):
        idx, chunks = build(tempfile.mkdtemp())
        probes = make_identifier_probes(chunks)
        emb = FakeEmbedder(fixed_query_text="Phishing attachments delivered loaders")   # sabotaged dense
        res = {m: evaluate(HybridRetriever(idx, chunks, None if m == "bm25" else emb, mode=m), probes)
               for m in MODES}
        for m in MODES:
            self.assertIn("cve", res[m]["kinds"])
        needle = lambda m: res[m]["kinds"]["cve"]["needle_hit@k"]["1"]       # noqa: E731
        self.assertEqual(needle("hybrid_ids"), 1.0)
        self.assertEqual(needle("bm25"), 1.0)
        self.assertLess(needle("dense"), 1.0)

    def test_probe_kinds_without_identifier_have_no_needle_columns(self):
        idx, chunks = build(tempfile.mkdtemp())
        probes = [{"kind": "titles", "question": "firewall patches", "gold_docs": ["advisory_cisa-advisory-aa24-001a"],
                   "needle": None}]
        res = evaluate(HybridRetriever(idx, chunks, FakeEmbedder(), mode="hybrid"), probes)
        self.assertNotIn("needle_hit@k", res["kinds"]["titles"])
        self.assertEqual(res["kinds"]["titles"]["doc_hit@k"]["5"], 1.0)

    def test_load_titles_marks_kind(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"questions": [{"question": "q", "gold_docs": ["advisory_x"]}]}, fh)
        pr = load_titles(p)
        self.assertEqual(pr[0]["kind"], "titles")
        self.assertEqual(load_titles(os.path.join(d, "missing.json")), [])

    def test_baseline_check_pass_warn_and_missing(self):
        d = tempfile.mkdtemp()
        kinds = {"cve": {"doc_hit@k": {"1": 0.5}, "needle_hit@k": {"1": 0.25}}}
        self.assertIn("no Milestone 7 report", baseline_check({"kinds": kinds}, d))
        with open(os.path.join(d, "rag_eval_20260101T000000Z.json"), "w", encoding="utf-8") as fh:
            json.dump({"kinds": kinds}, fh)
        self.assertIn("[PASS]", baseline_check({"kinds": kinds}, d))
        other = {"cve": {"doc_hit@k": {"1": 0.6}, "needle_hit@k": {"1": 0.25}}}
        self.assertIn("[WARN]", baseline_check({"kinds": other}, d))


if __name__ == "__main__":
    random.seed(0)
    unittest.main()
