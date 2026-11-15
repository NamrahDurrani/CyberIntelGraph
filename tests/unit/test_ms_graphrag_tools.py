import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import prepare_ms_graphrag_input as prep         # noqa: E402
import serve_local_embeddings as emb              # noqa: E402

try:
    import pandas as pd
    import inspect_graphrag_output as insp        # noqa: E402
except ImportError:                                # pragma: no cover
    pd = None


def chunk(doc, i, text):
    return {"chunk_id": f"{doc}_chunk_{i:03d}", "doc_id": doc, "chunk_index": i, "text": text, "title": f"Title of {doc}",
            "source_url": f"https://x/{doc}", "cve_ids": [], "technique_ids": []}


def write_chunks(tmp, docs=2, per_doc=6):
    p = os.path.join(tmp, "chunks.jsonl")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for d in range(docs):
            for i in range(1, per_doc + 1):
                fh.write(json.dumps(chunk(f"advisory_d{d}", i, f"Chunk {i} of doc {d}: " + "word " * 20)) + "\n")
    return p


class PrepareTests(unittest.TestCase):
    def test_spans_point_exactly_at_chunk_text(self):
        chunks = [chunk("d", 2, "second chunk text"), chunk("d", 1, "first chunk text")]
        text, spans = prep.build_document(chunks)
        self.assertTrue(text.startswith("Title of d\n\n"))
        by_id = {s["chunk_id"]: s for s in spans}
        self.assertEqual(text[by_id["d_chunk_001"]["start"]:by_id["d_chunk_001"]["end"]], "first chunk text")
        self.assertEqual(text[by_id["d_chunk_002"]["start"]:by_id["d_chunk_002"]["end"]], "second chunk text")
        self.assertLess(by_id["d_chunk_001"]["end"], by_id["d_chunk_002"]["start"])

    def test_prepare_writes_files_manifest_and_removes_stale_input(self):
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "g")
        os.makedirs(os.path.join(out, "input"))
        with open(os.path.join(out, "input", "stale.txt"), "w") as fh:
            fh.write("old")
        m = prep.prepare(write_chunks(tmp), out, docs=5)
        self.assertEqual(sorted(os.listdir(os.path.join(out, "input"))), sorted(v["file"] for v in m.values()))
        with open(os.path.join(out, "input_manifest.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh).keys(), m.keys())
        key = next(iter(m))
        with open(os.path.join(out, "input", m[key]["file"]), encoding="utf-8", newline="") as fh:
            body = fh.read()
        self.assertNotIn("\r", body)
        self.assertEqual(len(body), m[key]["chars"])
        c = m[key]["chunks"][0]
        self.assertTrue(body[c["start"]:c["end"]].startswith("Chunk 1 of doc"))

    def test_pick(self):
        tmp = tempfile.mkdtemp()
        m = prep.prepare(write_chunks(tmp), os.path.join(tmp, "g"), pick="d1")
        self.assertEqual(list(m), ["advisory_d1"])


class EmbeddingServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def embed(texts):
            out = []
            for t in texts:
                v = np.zeros(6, dtype=np.float32)
                v[len(t) % 6] = 3.0
                v[(len(t) + 2) % 6] = 4.0
                out.append(v / np.linalg.norm(v))
            return np.stack(out)
        cls.srv = emb.make_server(embed, "bge-small-en-v1.5", "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def post(self, body, path="/v1/embeddings", raw=None):
        req = urllib.request.Request(self.base + path, method="POST", data=raw if raw is not None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_float_list_and_single_string(self):
        s, r = self.post({"model": "m", "input": ["hello", "world!"]})
        self.assertEqual((s, len(r["data"]), len(r["data"][0]["embedding"])), (200, 2, 6))
        self.assertEqual([d["index"] for d in r["data"]], [0, 1])
        self.assertAlmostEqual(sum(x * x for x in r["data"][0]["embedding"]), 1.0, places=5)
        s, r = self.post({"input": "just one"})
        self.assertEqual((s, len(r["data"])), (200, 1))
        self.assertEqual(r["model"], "bge-small-en-v1.5")

    def test_base64_matches_float(self):
        _, f = self.post({"input": ["same text"], "encoding_format": "float"})
        _, b = self.post({"input": ["same text"], "encoding_format": "base64"})
        decoded = np.frombuffer(base64.b64decode(b["data"][0]["embedding"]), dtype="<f4")
        np.testing.assert_allclose(decoded, np.array(f["data"][0]["embedding"], dtype=np.float32), rtol=1e-6)

    def test_bad_requests_are_400_and_unknown_paths_404(self):
        for body in ({"input": []}, {"input": [1, 2]}, {"input": 5}, {"input": ["a"], "encoding_format": "int8"}, {}):
            self.assertEqual(self.post(body)[0], 400, body)
        self.assertEqual(self.post(None, raw=b"not json")[0], 400)
        self.assertEqual(self.post({"input": ["x"] * (emb.MAX_INPUTS + 1)})[0], 400)
        self.assertEqual(self.post({"input": ["a"]}, path="/v2/other")[0], 404)

    def test_health_and_models(self):
        with urllib.request.urlopen(self.base + "/health") as r:
            self.assertEqual(json.load(r)["status"], "ok")
        with urllib.request.urlopen(self.base + "/v1/models") as r:
            self.assertEqual(json.load(r)["data"][0]["id"], "bge-small-en-v1.5")


@unittest.skipIf(pd is None, "pandas not installed")
class InspectTests(unittest.TestCase):
    def test_describe_frame_reports_real_columns_nulls_and_samples(self):
        df = pd.DataFrame({"id": ["a", "b"], "title": ["T1", None], "text_unit_ids": [["u1", "u2"], ["u3"]], "weight": [1.5, 2.0]})
        rows = {r["column"]: r for r in insp.describe_frame(df)}
        self.assertEqual(list(rows), ["id", "title", "text_unit_ids", "weight"])
        self.assertEqual(rows["title"]["nulls"], 1)
        self.assertIn("u1", rows["text_unit_ids"]["sample"])

    def test_text_units_map_back_to_chunk_ids(self):
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "g")
        m = prep.prepare(write_chunks(tmp), out, docs=1)
        key = next(iter(m))
        with open(os.path.join(out, "input", m[key]["file"]), encoding="utf-8") as fh:
            body = fh.read()
        c1, c2 = m[key]["chunks"][0], m[key]["chunks"][1]
        spanning = body[c1["start"] + 5:c2["start"] + 10]                  # overlaps chunks 1 and 2
        tus = pd.DataFrame({"id": ["t1", "t2", "t3"], "document_id": ["D1", "D1", "D9"],
                            "text": [body[c1["start"]:c1["end"]], spanning, "whatever"]})
        docs = pd.DataFrame({"id": ["D1", "D9"], "title": [m[key]["file"], "unknown.txt"]})
        res = insp.map_text_units(m, tus, docs, os.path.join(out, "input"))
        self.assertEqual((res["mapped"], res["unmapped"]), (2, 1))
        self.assertEqual(res["sample"]["chunk_ids"], [c1["chunk_id"]])


class PreflightTests(unittest.TestCase):
    def test_preflight_fails_cleanly_and_never_prints_the_key(self):
        tmp = tempfile.mkdtemp()
        env = dict(os.environ, GROQ_API_KEY="SUPER-SECRET-KEY-VALUE-123")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "check_ms_graphrag_setup.py"), "--root", os.path.join(tmp, "ms"),
                            "--data", os.path.join(tmp, "d"), "--embed-url", "http://127.0.0.1:9/v1"],
                           capture_output=True, text=True, env=env, timeout=60)
        out = p.stdout + p.stderr
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("SUPER-SECRET-KEY-VALUE-123", out)
        self.assertIn("[PASS] GROQ_API_KEY is set", out)
        self.assertIn("settings.yaml exists", out)
        self.assertIn("embeddings server not reachable", out)


if __name__ == "__main__":
    unittest.main()
