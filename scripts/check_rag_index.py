"""Independent check of data/index/naive_rag (needs no model and no network)."""
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rag import DEFAULT_CHUNKS, DEFAULT_INDEX_DIR  # noqa: E402
from rag.index import VectorIndex, load_chunks, sha256_file  # noqa: E402

fails = 0


def check(ok, msg, level="FAIL"):
    global fails
    print(f"  [{'PASS' if ok else level}] {msg}")
    if not ok and level == "FAIL":
        fails += 1


print("Checking the naive RAG index ...")
idx = VectorIndex.load(DEFAULT_INDEX_DIR)
chunks = load_chunks(DEFAULT_CHUNKS)
m = idx.manifest
check(len(idx) == len(chunks) == m["count"], f"{len(idx)} vectors = {len(chunks)} chunks = manifest count")
check(idx.ids == [c["chunk_id"] for c in chunks], "vector order matches the chunk file order")
check(sha256_file(DEFAULT_CHUNKS) == m["chunks_sha256"], "index is not stale (chunk file unchanged since build)")
check(idx.vectors.shape == (len(idx), m["dim"]), f"vector shape is {idx.vectors.shape}")
check(bool(np.isfinite(idx.vectors).all()), "no NaN or infinite values")
norms = np.linalg.norm(idx.vectors, axis=1)
check(bool(np.allclose(norms, 1.0, atol=1e-3)), "all vectors are unit length (dot product = cosine)")
check(len(set(idx.ids)) == len(idx.ids), "chunk ids unique")
sample = list(range(0, len(idx), max(1, len(idx) // 100)))
bad = [i for i in sample if idx.search(idx.vectors[i], 1)[0][0] != i]
check(not bad, f"{len(sample)} sampled chunks each retrieve themselves first")
dupes = len(idx) - len({tuple(np.round(v, 4)) for v in idx.vectors[:: max(1, len(idx) // 500)]})
check(dupes < 0.1 * len(sample) + 5, f"vectors are not degenerate (near-identical in sample: {dupes})", "WARN")
print(f"  (info) model: {m['model']} | dim {m['dim']} | built {m['created_at']}")
print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
