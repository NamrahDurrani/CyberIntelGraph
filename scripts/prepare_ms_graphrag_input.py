"""Prepare the input for Microsoft GraphRAG (Milestone 9): one text file per advisory.

    python scripts/prepare_ms_graphrag_input.py            # the same 5 advisories as our own pipeline
    python scripts/prepare_ms_graphrag_input.py --pick aa20-302a,aa22-216a

Writes   data/graphrag_outputs/input/<doc_id>.txt          (what GraphRAG reads)
         data/graphrag_outputs/input_manifest.json         (our chunk ids with character spans in each file)
GraphRAG re-chunks the text itself (its "text units"); the manifest lets Milestone 10 map every text unit
back to our own chunk ids, so provenance is kept.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from graphrag_engine.indexing.select import load_chunks_by_doc, select_docs   # noqa: E402


def build_document(chunks: list[dict]) -> tuple[str, list[dict]]:
    """Text of one advisory and the (chunk_id, start, end) span of every chunk inside it."""
    title = (chunks[0].get("title") or chunks[0]["doc_id"]).strip()
    text = title + "\n\n"
    spans = []
    for c in sorted(chunks, key=lambda c: c["chunk_index"]):
        body = (c.get("text") or "").strip()
        if not body:
            continue
        start = len(text)
        text += body
        spans.append({"chunk_id": c["chunk_id"], "start": start, "end": len(text)})
        text += "\n\n"
    return text.rstrip("\n") + "\n", spans


def prepare(chunks_path: str, out_dir: str, docs: int = 5, pick: str = "") -> dict:
    by_doc = load_chunks_by_doc(chunks_path)
    explicit = [x for x in pick.split(",") if x.strip()]
    selected = select_docs(by_doc, n=docs, explicit=explicit or None)
    input_dir = os.path.join(out_dir, "input")
    os.makedirs(input_dir, exist_ok=True)
    for stale in os.listdir(input_dir):
        if stale.endswith(".txt"):
            os.remove(os.path.join(input_dir, stale))          # the folder always matches the current selection
    manifest = {}
    for d in selected:
        chunks = by_doc[d["doc_id"]]
        text, spans = build_document(chunks)
        with open(os.path.join(input_dir, f"{d['doc_id']}.txt"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        manifest[d["doc_id"]] = {"title": chunks[0].get("title", ""), "source_url": chunks[0].get("source_url", ""),
                                 "file": f"{d['doc_id']}.txt", "chars": len(text), "chunks": spans}
    with open(os.path.join(out_dir, "input_manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks", default=os.path.join("data", "processed", "advisory_chunks.jsonl"))
    ap.add_argument("--out-dir", default=os.path.join("data", "graphrag_outputs"))
    ap.add_argument("--docs", type=int, default=5)
    ap.add_argument("--pick", default="")
    a = ap.parse_args()
    if not os.path.isfile(a.chunks):
        sys.exit(f"{a.chunks} not found - run from the project root after Milestone 6")
    m = prepare(a.chunks, a.out_dir, a.docs, a.pick)
    total = sum(v["chars"] for v in m.values())
    print(f"wrote {len(m)} advisory file(s) to {os.path.join(a.out_dir, 'input')} ({total:,} characters, about {total // 4:,} tokens)")
    for k, v in m.items():
        print(f"  {k:<44} {v['chars']:>8,} chars, {len(v['chunks'])} chunks")


if __name__ == "__main__":
    main()
