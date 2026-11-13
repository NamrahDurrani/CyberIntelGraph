import email.message
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import zlib

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from rag.answer import (SYSTEM_PROMPT, answer_question, build_user_prompt,  # noqa: E402
                        check_citations, format_passage)
from rag.evaluate import evaluate, load_curated, make_identifier_probes  # noqa: E402
from rag.index import VectorIndex, build_index, load_chunks              # noqa: E402
from rag.llm import GroqClient, LLMError, LLMResult, load_api_key        # noqa: E402
from rag.retrieve import Retriever                                        # noqa: E402


class FakeEmbedder:
    """Deterministic bag-of-words hashing: texts sharing words are similar."""
    name, DIM = "fake-bow", 128

    def _vec(self, text):
        v = np.zeros(self.DIM, dtype=np.float32)
        for tok in text.lower().replace(">", " ").split():
            v[zlib.crc32(tok.strip(".,?:[]").encode()) % self.DIM] += 1
        return v

    def embed_documents(self, texts):
        return np.stack([self._vec(t) for t in texts])

    def embed_query(self, text):
        return self._vec(text)


def chunk(doc, n, text, cves=(), techs=(), path=("Title",)):
    return {"chunk_id": f"advisory_{doc}_chunk_{n:03d}", "doc_id": f"advisory_{doc}", "chunk_index": n,
            "text": text, "embedding_text": " > ".join(path) + "\n" + text, "heading_path": list(path),
            "title": f"Title {doc}", "source_url": f"https://x/{doc}", "cve_ids": list(cves),
            "technique_ids": list(techs)}


CHUNKS = [
    chunk("aa1", 1, "Ransomware actors targeted hospitals using TrickBot malware", techs=["T1566"]),
    chunk("aa1", 2, "Apply patches and segment networks to reduce ransomware exposure"),
    chunk("aa2", 1, "Firewall exploitation of CVE-2024-3400 allowed remote command execution", cves=["CVE-2024-3400"]),
    chunk("aa3", 1, "Phishing attachments delivered loaders for credential theft", techs=["T1566", "T1204"]),
]


def write_chunks(d, chunks=CHUNKS):
    p = os.path.join(d, "chunks.jsonl")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for c in chunks:
            fh.write(json.dumps(c) + "\n")
    return p


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cp = write_chunks(self.tmp)
        self.out = os.path.join(self.tmp, "idx")
        self.emb = FakeEmbedder()
        self.manifest = build_index(self.cp, self.emb, self.out)
        self.idx = VectorIndex.load(self.out)

    def test_search_finds_relevant_chunk(self):
        top = self.idx.search(self.emb.embed_query("firewall CVE-2024-3400 exploitation"), 2)
        self.assertEqual(self.idx.ids[top[0][0]], "advisory_aa2_chunk_001")
        self.assertGreaterEqual(top[0][1], top[1][1])

    def test_roundtrip_manifest_and_unit_vectors(self):
        self.assertEqual(self.manifest["count"], 4)
        self.assertEqual(self.idx.manifest["model"], "fake-bow")
        self.assertTrue(np.allclose(np.linalg.norm(self.idx.vectors, axis=1), 1.0, atol=1e-5))

    def test_k_larger_than_index_and_self_retrieval(self):
        self.assertEqual(len(self.idx.search(self.idx.vectors[0], 99)), 4)
        for i in range(4):
            self.assertEqual(self.idx.search(self.idx.vectors[i], 1)[0][0], i)

    def test_stale_detection(self):
        self.assertFalse(self.idx.is_stale(self.cp))
        with open(self.cp, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(chunk("aa9", 1, "new chunk")) + "\n")
        self.assertTrue(self.idx.is_stale(self.cp))

    def test_deterministic_ties(self):
        v = np.ones((3, 4), dtype=np.float32)
        idx = VectorIndex(v / 2, ["a", "b", "c"], {})
        self.assertEqual([r for r, _ in idx.search(np.ones(4), 3)], [0, 1, 2])

    def test_empty_chunk_file_rejected(self):
        p = write_chunks(self.tmp, [])
        with self.assertRaises(ValueError):
            build_index(p, self.emb, self.out)


class RetrieverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cp = write_chunks(self.tmp)
        self.emb = FakeEmbedder()
        build_index(cp, self.emb, os.path.join(self.tmp, "i"))
        self.idx = VectorIndex.load(os.path.join(self.tmp, "i"))
        self.r = Retriever(self.idx, load_chunks(cp), self.emb)

    def test_hits_carry_metadata_and_ranks(self):
        hits = self.r.retrieve("TrickBot ransomware hospitals", 3)
        self.assertEqual([h.rank for h in hits], [1, 2, 3])
        self.assertEqual(hits[0].chunk_id, "advisory_aa1_chunk_001")
        self.assertEqual(hits[0].chunk["source_url"], "https://x/aa1")

    def test_index_chunk_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            Retriever(self.idx, CHUNKS[:2], self.emb)


class FakeLLM:
    def __init__(self, text):
        self.text, self.calls = text, []

    def complete(self, system, user):
        self.calls.append((system, user))
        return LLMResult(text=self.text, model="fake", finish_reason="stop", usage={"total_tokens": 9})


class AnswerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cp = write_chunks(self.tmp)
        self.emb = FakeEmbedder()
        build_index(cp, self.emb, os.path.join(self.tmp, "i"))
        self.r = Retriever(VectorIndex.load(os.path.join(self.tmp, "i")), load_chunks(cp), self.emb)

    def test_prompt_contains_ids_sources_and_truncates(self):
        hits = self.r.retrieve("TrickBot", 2)
        p = build_user_prompt("What?", hits)
        self.assertIn("[advisory_aa1_chunk_001]", p)
        self.assertIn("https://x/aa1", p)
        self.assertTrue(p.endswith("Answer with citations:"))
        long = chunk("aa7", 1, "word " * 500)
        h = type("H", (), {"chunk": long, "chunk_id": long["chunk_id"]})()
        self.assertTrue(format_passage(h, 50).endswith("..."))
        self.assertLess(len(format_passage(h, 50).split()), 70)

    def test_citation_checks(self):
        hits = self.r.retrieve("TrickBot", 2)
        got = check_citations("Yes [advisory_aa1_chunk_001] and [advisory_zz_chunk_009].", hits)
        self.assertEqual(got["valid"], ["advisory_aa1_chunk_001"])
        self.assertEqual(got["invalid"], ["advisory_zz_chunk_009"])
        self.assertFalse(got["uncited"])
        self.assertTrue(check_citations("No cites here.", hits)["uncited"])

    def test_answer_pipeline_and_no_llm_mode(self):
        llm = FakeLLM("TrickBot was used [advisory_aa1_chunk_001].")
        out = answer_question("Which malware hit hospitals?", self.r, llm, k=2)
        self.assertEqual(out["citations"]["valid"], ["advisory_aa1_chunk_001"])
        self.assertEqual(llm.calls[0][0], SYSTEM_PROMPT)
        self.assertEqual(len(out["retrieved"]), 2)
        only = answer_question("Which malware hit hospitals?", self.r, None, k=2)
        self.assertNotIn("answer", only)


class FakeResp:
    def __init__(self, data):
        self._d = json.dumps(data).encode()

    def read(self):
        return self._d

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, body="{}", retry_after=None):
    hdrs = email.message.Message()
    if retry_after is not None:
        hdrs["retry-after"] = str(retry_after)
    return urllib.error.HTTPError("u", code, "m", hdrs, io.BytesIO(body.encode()))


GOOD = {"model": "openai/gpt-oss-20b", "usage": {"total_tokens": 42},
        "choices": [{"finish_reason": "stop", "message": {"content": " Answer [x] "}}]}


class GroqTests(unittest.TestCase):
    def client(self, responses, **kw):
        seq, self.requests, self.sleeps = list(responses), [], []

        def fake_open(req, timeout=None):
            self.requests.append(req)
            item = seq.pop(0)
            if isinstance(item, Exception):
                raise item
            return FakeResp(item)
        return GroqClient(api_key="gsk_secret", urlopen=fake_open, sleep=self.sleeps.append, **kw)

    def test_success_and_payload(self):
        c = self.client([GOOD], max_completion_tokens=777, reasoning_effort="low")
        r = c.complete("sys", "user")
        self.assertEqual(r.text, "Answer [x]")
        self.assertEqual(r.usage["total_tokens"], 42)
        payload = json.loads(self.requests[0].data)
        self.assertEqual(payload["model"], "openai/gpt-oss-20b")
        self.assertEqual(payload["max_completion_tokens"], 777)
        self.assertEqual(payload["reasoning_effort"], "low")
        self.assertNotIn("gsk_secret", self.requests[0].data.decode())      # key only in the header
        self.assertEqual(self.requests[0].get_header("Authorization"), "Bearer gsk_secret")
        self.assertIn("CyberIntelGraph", self.requests[0].get_header("User-agent"))

    def test_retries_429_honouring_retry_after(self):
        c = self.client([http_error(429, retry_after=7), http_error(503), GOOD])
        self.assertEqual(c.complete("s", "u").text, "Answer [x]")
        self.assertEqual(self.sleeps, [7.0, 4])                 # retry-after, then 2**1*2

    def test_gives_up_after_max_retries(self):
        c = self.client([http_error(429)] * 3, max_retries=2)
        with self.assertRaises(LLMError):
            c.complete("s", "u")
        self.assertEqual(len(self.requests), 3)

    def test_auth_error_not_retried_and_key_scrubbed(self):
        c = self.client([http_error(401, '{"error":"bad key gsk_secret"}')])
        with self.assertRaises(LLMError) as cm:
            c.complete("s", "u")
        self.assertNotIn("gsk_secret", str(cm.exception))
        self.assertIn("401", str(cm.exception))
        self.assertEqual(len(self.requests), 1)

    def test_empty_answer_hint_on_length(self):
        bad = {"choices": [{"finish_reason": "length", "message": {"content": ""}}]}
        with self.assertRaises(LLMError) as cm:
            self.client([bad]).complete("s", "u")
        self.assertIn("max-tokens", str(cm.exception))

    def test_api_key_loading(self):
        old = os.environ.pop("GROQ_API_KEY", None)
        try:
            d = tempfile.mkdtemp()
            env = os.path.join(d, ".env")
            with self.assertRaises(LLMError):
                load_api_key(env_path=env)
            with open(env, "w", encoding="utf-8") as fh:
                fh.write("# comment\nOTHER=1\nGROQ_API_KEY='abc123'\n")
            self.assertEqual(load_api_key(env_path=env), "abc123")
            os.environ["GROQ_API_KEY"] = " fromenv "
            self.assertEqual(load_api_key(env_path=env), "fromenv")
        finally:
            os.environ.pop("GROQ_API_KEY", None)
            if old is not None:
                os.environ["GROQ_API_KEY"] = old


class EvalTests(unittest.TestCase):
    def test_probes_are_deterministic_and_gold_is_correct(self):
        a = make_identifier_probes(CHUNKS)
        self.assertEqual(a, make_identifier_probes(CHUNKS))
        t = next(p for p in a if p["needle"] == "T1566")
        self.assertEqual(t["gold_docs"], ["advisory_aa1", "advisory_aa3"])
        self.assertEqual({p["kind"] for p in a}, {"cve", "technique"})

    def test_metrics_distinguish_doc_hit_from_needle_hit(self):
        tmp = tempfile.mkdtemp()
        cp = write_chunks(tmp)
        emb = FakeEmbedder()
        build_index(cp, emb, os.path.join(tmp, "i"))
        r = Retriever(VectorIndex.load(os.path.join(tmp, "i")), load_chunks(cp), emb)
        probes = [{"kind": "cve", "question": "firewall remote command execution", "gold_docs": ["advisory_aa2"],
                   "needle": "CVE-2024-3400"},
                  {"kind": "cve", "question": "completely unrelated zebra", "gold_docs": ["advisory_aa2"],
                   "needle": "CVE-2024-3400"}]
        res = evaluate(r, probes, ks=(1,))      # k=1: the tiny corpus makes k=3 cover almost everything
        e = res["kinds"]["cve"]
        self.assertEqual(e["n"], 2)
        self.assertEqual(e["doc_hit@k"]["1"], 0.5)
        self.assertEqual(e["needle_hit@k"]["1"], 0.5)
        self.assertEqual(len(res["misses"]["cve"]), 1)

    def test_curated_loading(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "q.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"questions": [{"question": "q?", "gold_docs": ["advisory_x"]}]}, fh)
        self.assertEqual(load_curated(p)[0]["kind"], "curated")
        self.assertEqual(load_curated(os.path.join(d, "missing.json")), [])


if __name__ == "__main__":
    unittest.main()
