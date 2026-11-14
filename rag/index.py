"""A flat (exact, brute-force) vector index stored as plain files.

2,734 chunks x 384 numbers is about 4 MB; an exact dot-product search is instant and
needs no extra install or server. The class API (build / save / load / search) is what
a FAISS or database index would also offer, so it can be swapped later."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

import numpy as np

INDEX_VERSION = "1.0"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_chunks(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _normalise(mat: np.ndarray) -> np.ndarray:
    mat = np.asarray(mat, dtype=np.float32)
    norms = np.linalg.norm(mat, axis=-1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms


class VectorIndex:
    def __init__(self, vectors: np.ndarray, ids: list[str], manifest: dict):
        if len(ids) != len(vectors):
            raise ValueError("ids and vectors differ in length")
        self.vectors, self.ids, self.manifest = vectors, ids, manifest

    def __len__(self):
        return len(self.ids)

    def search(self, qvec, k: int = 5) -> list[tuple[int, float]]:
        """Top-k (row, cosine score), best first; ties are broken by row for determinism."""
        q = _normalise(np.asarray(qvec, dtype=np.float32).reshape(1, -1))[0]
        scores = self.vectors @ q
        k = max(1, min(k, len(scores)))
        # Full ordering (score desc, then row asc). argpartition does NOT break ties
        # deterministically when identical chunks share the boundary score (Milestone 8 fix).
        top = np.lexsort((np.arange(len(scores)), -scores))[:k]
        return [(int(i), float(scores[i])) for i in top]

    def save(self, out_dir: str):
        os.makedirs(out_dir, exist_ok=True)
        np.save(os.path.join(out_dir, "vectors.npy"), self.vectors)
        with open(os.path.join(out_dir, "ids.json"), "w", encoding="utf-8") as fh:
            json.dump(self.ids, fh)
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh, indent=1)

    @classmethod
    def load(cls, index_dir: str) -> "VectorIndex":
        vectors = np.load(os.path.join(index_dir, "vectors.npy"))
        with open(os.path.join(index_dir, "ids.json"), encoding="utf-8") as fh:
            ids = json.load(fh)
        with open(os.path.join(index_dir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        return cls(vectors, ids, manifest)

    def is_stale(self, chunks_path: str) -> bool:
        """True if the chunk file changed since this index was built."""
        return sha256_file(chunks_path) != self.manifest.get("chunks_sha256")


def build_index(chunks_path: str, embedder, out_dir: str, text_field: str = "embedding_text") -> dict:
    chunks = load_chunks(chunks_path)
    if not chunks:
        raise ValueError(f"no chunks in {chunks_path}")
    vectors = _normalise(embedder.embed_documents([c[text_field] for c in chunks]))
    manifest = {
        "index_version": INDEX_VERSION, "model": embedder.name,
        "dim": int(vectors.shape[1]), "count": len(chunks), "normalized": True,
        "text_field": text_field, "chunks_file": os.path.basename(chunks_path),
        "chunks_sha256": sha256_file(chunks_path),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    VectorIndex(vectors, [c["chunk_id"] for c in chunks], manifest).save(out_dir)
    return manifest
