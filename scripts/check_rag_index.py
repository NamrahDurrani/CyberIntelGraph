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
# A chunk must not be out-scored by any OTHER chunk. Identical twins (same text) tie with it
# and are allowed: they are the same page photocopied, not a defect of the index.
TOL = 1e-4
bad = []
for i in sample:
    s = idx.vectors @ idx.vectors[i]
    if s[i] < s.max() - TOL:
        bad.append(idx.ids[i])
check(not bad, f"{len(sample)} sampled chunks are never out-scored by another chunk (ties allowed)"
      + (f" - failing: {bad[:3]}" if bad else ""))
texts = [c.get("embedding_text") or c.get("text", "") for c in chunks]
twins = len(texts) - len(set(texts))
print(f"  (info) {twins} chunk(s) have text identical to another chunk (duplicate boilerplate)")
sub = idx.vectors[:: max(1, len(idx) // 500)]
dupes = len(sub) - len({tuple(np.round(v, 4)) for v in sub})
check(dupes < 0.1 * len(sub) + 5, f"vectors are not degenerate (identical vectors in a sample of {len(sub)}: {dupes})", "WARN")
print(f"  (info) model: {m['model']} | dim {m['dim']} | built {m['created_at']}")
print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
