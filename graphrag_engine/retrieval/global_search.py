"""Global search: answer broad questions from the community reports (map-reduce).

    python graphrag_engine/retrieval/global_search.py "What attack patterns recur across these advisories?"

MAP    each of the top-K reports (ranked by BM25, reusing Milestone 8) answers the question alone
       and scores its own usefulness 0-100.
REDUCE the useful partial answers are combined into one answer that cites reports as [C003].
Calls = K + 1 (cached; repeated questions are free).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from graphrag_engine.indexing.extract import _s, parse_json     # noqa: E402
from rag.bm25 import BM25Index                                    # noqa: E402
from rag.llm import LLMError                                      # noqa: E402

MAP_SYSTEM = """You answer a question using ONLY the community report below.
Reply with ONE JSON object only: {"answer": str, "score": int}
score 0-100 = how much this report helps answer the question (0 = not at all). If it does not help,
return {"answer": "", "score": 0}. Never use outside knowledge."""
REDUCE_SYSTEM = """You combine partial answers (each from one community report) into one answer.
Use ONLY the partial answers. Cite the reports you rely on as [C000]-style ids after each claim.
If the partial answers do not answer the question, say so plainly. Be concise."""


def report_text(r: dict) -> str:
    return " ".join([r.get("title", ""), r.get("summary", "")] + [f["finding"] for f in r.get("findings", [])]
                    + r.get("top_entities", []))


def rank_reports(question: str, reports: list[dict], k: int) -> list[dict]:
    if not reports:
        return []
    hits = BM25Index([report_text(r) for r in reports]).search(question, k)
    ranked = [reports[i] for i, _ in hits]
    for r in reports:                                   # pad with the largest communities if BM25 finds few
        if len(ranked) >= k:
            break
        if r not in ranked:
            ranked.append(r)
    return ranked[:k]


def global_search(question: str, reports: list[dict], cached_llm, top_reports: int = 5) -> dict:
    usable = [r for r in reports if "error" not in r]
    chosen = rank_reports(question, usable, top_reports)
    partials, errors = [], []
    for r in chosen:
        user = (f"QUESTION: {question}\n\nREPORT {r['community_id']}: {r['title']}\n{r['summary']}\n"
                + "\n".join(f"- {f['finding']}" for f in r["findings"]))
        try:
            rec = cached_llm.complete("map", MAP_SYSTEM, user, label=r["community_id"])
        except LLMError as ex:
            errors.append(f"{r['community_id']}: {ex}")
            continue
        parsed = parse_json(rec["text"]) or {}
        try:
            score = int(parsed.get("score", 0))
        except (TypeError, ValueError):
            score = 0
        ans = _s(parsed.get("answer"), 1500)
        if ans and score > 0:
            partials.append({"community_id": r["community_id"], "score": score, "answer": ans})
    partials.sort(key=lambda p: (-p["score"], p["community_id"]))
    if not partials:
        return {"question": question, "answer": "The community reports do not contain an answer to this question.",
                "partials": [], "cited": [], "unknown_citations": [], "reports_read": [r["community_id"] for r in chosen],
                "errors": errors}
    user = f"QUESTION: {question}\n\n" + "\n\n".join(f"[{p['community_id']}] (score {p['score']}) {p['answer']}" for p in partials)
    rec = cached_llm.complete("reduce", REDUCE_SYSTEM, user, label="reduce")
    answer = rec["text"].strip()
    cited = sorted(set(re.findall(r"\[(C\d{3})\]", answer)))
    known = {p["community_id"] for p in partials}
    return {"question": question, "answer": answer, "partials": partials, "cited": cited,
            "unknown_citations": sorted(set(cited) - known), "reports_read": [r["community_id"] for r in chosen],
            "errors": errors}


def main():
    from graphrag_engine.indexing.llm_cache import CachedLLM
    from rag.llm import DEFAULT_GROQ_MODEL, GroqClient
    ap = argparse.ArgumentParser()
    ap.add_argument("question")
    ap.add_argument("--dir", default=os.path.join("data", "graphrag"))
    ap.add_argument("--top-reports", type=int, default=5)
    ap.add_argument("--model", default=DEFAULT_GROQ_MODEL)
    ap.add_argument("--max-tokens", type=int, default=1500)
    ap.add_argument("--min-interval", type=float, default=2.5)
    ap.add_argument("--max-calls", type=int, default=12)
    a = ap.parse_args()
    path = os.path.join(a.dir, "community_reports.json")
    if not os.path.isfile(path):
        sys.exit(f"{path} not found - run graphrag_engine\\indexing\\run_index.py first")
    with open(path, encoding="utf-8") as fh:
        reports = json.load(fh)["records"]
    llm = CachedLLM(GroqClient(model=a.model, max_completion_tokens=a.max_tokens), os.path.join(a.dir, "cache"),
                    a.model, min_interval=a.min_interval, max_calls=a.max_calls)
    out = global_search(a.question, reports, llm, a.top_reports)
    print("\nANSWER\n" + out["answer"])
    if out["unknown_citations"]:
        print(f"\n[WARN] answer cites reports that were not used: {out['unknown_citations']}")
    print(f"\nreports read: {', '.join(out['reports_read'])} | llm calls this run: {llm.calls} (cache hits {llm.cache_hits})")
    for p in out["partials"]:
        print(f"  {p['community_id']} score {p['score']}: {p['answer'][:140]}")


if __name__ == "__main__":
    main()
