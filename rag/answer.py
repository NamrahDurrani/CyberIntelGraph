"""Build the grounded prompt, call the LLM, and verify the citations."""
from __future__ import annotations

import re

from rag.retrieve import Hit, Retriever

SYSTEM_PROMPT = (
    "You are a cyber threat intelligence assistant. Answer the question using ONLY the "
    "numbered passages provided. After every factual statement, cite the passage id in "
    "square brackets, for example [advisory_aa20-302a_chunk_004]. Use only ids that appear "
    "in the passages. If the passages do not contain the answer, say exactly: "
    "\"I cannot find this in the collected advisories.\" Do not use outside knowledge and "
    "do not invent CVE numbers, technique ids or names. Be concise."
)
CITE_ID_RE = re.compile(r"advisory_[a-z0-9-]+_chunk_\d{3,}")


def format_passage(hit: Hit, max_words: int = 300) -> str:
    c = hit.chunk
    words = c["text"].split()
    body = " ".join(words[:max_words]) + (" ..." if len(words) > max_words else "")
    path = " > ".join(c.get("heading_path") or [])
    meta = " | ".join(x for x in (c.get("title"), path, c.get("source_url")) if x)
    return f"[{c['chunk_id']}] {meta}\n{body}"


def build_user_prompt(question: str, hits: list[Hit], max_words: int = 300) -> str:
    passages = "\n\n".join(format_passage(h, max_words) for h in hits)
    return f"Passages:\n\n{passages}\n\nQuestion: {question}\n\nAnswer with citations:"


def check_citations(answer: str, hits: list[Hit]) -> dict:
    retrieved = {h.chunk_id for h in hits}
    cited = list(dict.fromkeys(CITE_ID_RE.findall(answer)))
    return {"valid": [c for c in cited if c in retrieved],
            "invalid": [c for c in cited if c not in retrieved],
            "uncited": not cited}


def answer_question(question: str, retriever: Retriever, llm, k: int = 5,
                    max_words_per_chunk: int = 300) -> dict:
    hits = retriever.retrieve(question, k)
    out = {"question": question,
           "retrieved": [{"rank": h.rank, "score": round(h.score, 4), "chunk_id": h.chunk_id,
                          "title": h.chunk.get("title"), "heading_path": h.chunk.get("heading_path"),
                          "source_url": h.chunk.get("source_url"),
                          "via": getattr(h, "via", "-")} for h in hits]}
    if llm is None:
        return out
    res = llm.complete(SYSTEM_PROMPT, build_user_prompt(question, hits, max_words_per_chunk))
    out.update(answer=res.text, model=res.model, usage=res.usage, latency_s=res.latency_s,
               finish_reason=res.finish_reason, citations=check_citations(res.text, hits))
    return out
