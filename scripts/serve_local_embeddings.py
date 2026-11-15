"""Tiny OpenAI-compatible embeddings server around the local bge-small model (Milestone 9).

Microsoft GraphRAG needs an embeddings endpoint; Groq has none. This serves the model you already
use for Milestone 7 on http://127.0.0.1:8008/v1/embeddings - nothing leaves your machine, no new download.

    python scripts/serve_local_embeddings.py            # keep this window open while GraphRAG runs
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np

MAX_BODY = 20_000_000
MAX_INPUTS = 512


def make_server(embed_fn, model_name: str, host: str = "127.0.0.1", port: int = 8008) -> ThreadingHTTPServer:
    """embed_fn(list[str]) -> 2-D array of unit-length vectors."""
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):                       # quiet
            pass

        def _send(self, code: int, body: dict):
            raw = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _error(self, code: int, message: str):
            self._send(code, {"error": {"message": message, "type": "invalid_request_error"}})

        def do_GET(self):
            if self.path.rstrip("/") in ("/health", "/v1/models"):
                self._send(200, {"status": "ok", "object": "list", "data": [{"id": model_name, "object": "model"}]})
            else:
                self._error(404, "not found")

        def do_POST(self):
            if self.path.rstrip("/") != "/v1/embeddings":
                return self._error(404, "not found")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY:
                    return self._error(400, "bad or oversized request body")
                req = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError):
                return self._error(400, "request body is not valid JSON")
            inputs = req.get("input")
            if isinstance(inputs, str):
                inputs = [inputs]
            if not isinstance(inputs, list) or not inputs or not all(isinstance(x, str) for x in inputs):
                return self._error(400, "'input' must be a string or a non-empty list of strings")
            if len(inputs) > MAX_INPUTS:
                return self._error(400, f"at most {MAX_INPUTS} inputs per request")
            fmt = req.get("encoding_format", "float")
            if fmt not in ("float", "base64"):
                return self._error(400, "encoding_format must be 'float' or 'base64'")
            with lock:
                vecs = np.asarray(embed_fn(inputs), dtype=np.float32)
            data = []
            for i, v in enumerate(vecs):
                emb = base64.b64encode(v.astype("<f4").tobytes()).decode("ascii") if fmt == "base64" else v.tolist()
                data.append({"object": "embedding", "index": i, "embedding": emb})
            tokens = sum(len(s.split()) for s in inputs)
            self._send(200, {"object": "list", "data": data, "model": req.get("model") or model_name,
                             "usage": {"prompt_tokens": tokens, "total_tokens": tokens}})

    return ThreadingHTTPServer((host, port), Handler)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="BAAI/bge-small-en-v1.5")
    ap.add_argument("--name", default="bge-small-en-v1.5", help="model name GraphRAG sends (must match settings.yaml)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8008)
    a = ap.parse_args()
    from sentence_transformers import SentenceTransformer
    print(f"loading {a.model} ...", flush=True)
    model = SentenceTransformer(a.model)

    def embed(texts):
        return model.encode(texts, batch_size=32, normalize_embeddings=True, show_progress_bar=False)
    srv = make_server(embed, a.name, a.host, a.port)
    print(f"embeddings server ready: http://{a.host}:{a.port}/v1  (model name '{a.name}', dim {model.get_sentence_embedding_dimension()}). Ctrl+C to stop.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
