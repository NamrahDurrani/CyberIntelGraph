"""Ask a question about the collected advisories.

    python rag/ask.py "Which malware was used against healthcare in AA20-302A?"
    python rag/ask.py "..." --no-llm        (retrieval only, no API call)
    python rag/ask.py "..." --mode dense    (Milestone 7 behaviour; default is hybrid_ids)
Modes: dense | bm25 | hybrid | hybrid_ids   (see rag/hybrid.py)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag import DEFAULT_CHUNKS, DEFAULT_INDEX_DIR   # noqa: E402
from rag.answer import answer_question              # noqa: E402
from rag.index import VectorIndex, load_chunks      # noqa: E402
from rag.hybrid import MODES, HybridRetriever, extract_identifiers  # noqa: E402
from rag.llm import DEFAULT_GROQ_MODEL, GroqClient, LLMError  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("question")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--mode", default="hybrid_ids", choices=MODES)
    ap.add_argument("--model", default=DEFAULT_GROQ_MODEL)
    ap.add_argument("--max-tokens", type=int, default=1500)
    ap.add_argument("--effort", default="low", choices=["low", "medium", "high"])
    ap.add_argument("--chunks", default=DEFAULT_CHUNKS)
    ap.add_argument("--index", default=DEFAULT_INDEX_DIR)
    a = ap.parse_args()

    index = VectorIndex.load(a.index)
    if index.is_stale(a.chunks):
        print("[WARN] the chunk file changed since the index was built - run rag\\build_index.py")
    embedder = None
    if a.mode != "bm25":
        from rag.embedder import SentenceTransformerEmbedder
        embedder = SentenceTransformerEmbedder(index.manifest["model"])
    retriever = HybridRetriever(index, load_chunks(a.chunks), embedder, mode=a.mode)
    ids = {k: v for k, v in extract_identifiers(a.question).items() if v}
    if ids and a.mode == "hybrid_ids":
        print(f"[info] identifiers found in the question: {ids}")
    llm = None if a.no_llm else GroqClient(model=a.model, max_completion_tokens=a.max_tokens,
                                           reasoning_effort=a.effort)
    try:
        r = answer_question(a.question, retriever, llm, k=a.k)
    except LLMError as ex:
        print(f"LLM error: {ex}")
        sys.exit(2)

    if "answer" in r:
        print("\nANSWER\n" + r["answer"])
        c = r["citations"]
        if c["uncited"]:
            print("\n[WARN] the answer cites no passage")
        if c["invalid"]:
            print(f"\n[WARN] cites ids that were NOT retrieved (possible hallucination): {c['invalid']}")
        print(f"\n(model {r['model']}, {r['latency_s']}s, tokens {r['usage']})")
    print("\nSOURCES (retrieved passages)")
    for h in r["retrieved"]:
        print(f"  {h['rank']}. {h['chunk_id']}  score {h['score']}  via {h.get('via', '-')}\n"
              f"     {h['title']}  {h['source_url']}")


if __name__ == "__main__":
    main()
