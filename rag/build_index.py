"""Embed every advisory chunk and save the vector index.

    python rag/build_index.py
The first run downloads the embedding model (about 130 MB) and takes a few minutes on CPU.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag import DEFAULT_CHUNKS, DEFAULT_EMBEDDING_MODEL, DEFAULT_INDEX_DIR  # noqa: E402
from rag.index import build_index                                          # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks", default=DEFAULT_CHUNKS)
    ap.add_argument("--out", default=DEFAULT_INDEX_DIR)
    ap.add_argument("--model", default=DEFAULT_EMBEDDING_MODEL)
    a = ap.parse_args()
    from rag.embedder import SentenceTransformerEmbedder
    print(f"Loading {a.model} ...")
    m = build_index(a.chunks, SentenceTransformerEmbedder(a.model), a.out)
    print("=== Milestone 7: index built ===")
    print(json.dumps(m, indent=2))


if __name__ == "__main__":
    main()
