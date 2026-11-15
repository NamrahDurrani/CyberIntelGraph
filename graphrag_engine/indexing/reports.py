"""Community reports: an LLM summarises each community from its entities and relationships.

These reports are what makes GraphRAG good at broad questions ("what patterns recur?"):
global search reads reports instead of thousands of raw chunks.
"""
from __future__ import annotations

from graphrag_engine.indexing.extract import _s, parse_json
from rag.llm import LLMError

SYSTEM = """You write short threat-intelligence community reports from a list of entities and relationships.
Reply with ONE JSON object only (no prose, no fences):
{"title": str, "summary": str, "findings": [{"finding": str, "support": [chunk ids]}]}
Rules: use only the listed entities and relationships; summary at most 120 words; 3 to 6 findings;
"support" lists chunk ids copied from the [brackets] after relationships; do not invent ids."""


def community_prompt(comm: dict, entities_by_id: dict, rels: list[dict], max_entities: int = 40, max_rels: int = 60):
    mset = set(comm["node_ids"])
    ents = [entities_by_id[n] for n in comm["node_ids"]][:max_entities]
    inside = sorted((r for r in rels if r["source_id"] in mset and r["target_id"] in mset),
                    key=lambda r: (-r["properties"]["weight"], r["rel_id"]))[:max_rels]
    lines = ["ENTITIES"]
    lines += [f"- {e['name']} ({e['type']}): {e['description'][:100]}" for e in ents]
    lines.append("RELATIONSHIPS")
    name = {e["node_id"]: e["name"] for e in entities_by_id.values()}
    for r in inside:
        chunk = r["evidence"][0]["record_ref"] if r["evidence"] else "-"
        lines.append(f"- {name[r['source_id']]} -{r['rel_type']}-> {name[r['target_id']]}: "
                     f"{r['properties']['description'][:120]} [{chunk}]")
    allowed = sorted({ev["record_ref"] for r in inside for ev in r["evidence"]})
    return "\n".join(lines), allowed


def validate_report(raw: dict, allowed_chunks: list[str]) -> dict | None:
    title, summary = _s(raw.get("title"), 160), _s(raw.get("summary"), 1200)
    if not title or not summary:
        return None
    findings = []
    for f in (raw.get("findings") or [])[:6]:
        if not isinstance(f, dict) or not _s(f.get("finding"), 400):
            continue
        support = [c for c in (f.get("support") or []) if isinstance(c, str) and c.strip("[] ") in allowed_chunks]
        findings.append({"finding": _s(f["finding"], 400), "support": [c.strip("[] ") for c in support]})
    return {"title": title, "summary": summary, "findings": findings,
            "unsupported_findings": sum(1 for f in findings if not f["support"])}


def write_report(cached_llm, comm: dict, entities_by_id: dict, rels: list[dict]) -> dict:
    user, allowed = community_prompt(comm, entities_by_id, rels)
    for suffix in ("", "\n\nYour previous reply was not valid JSON. Reply with ONLY the JSON object."):
        try:
            rec = cached_llm.complete("report", SYSTEM, user + suffix, label=comm["community_id"])
        except LLMError as ex:
            return {"community_id": comm["community_id"], "error": f"llm: {ex}"}
        parsed = parse_json(rec["text"])
        rep = validate_report(parsed, allowed) if parsed else None
        if rep:
            return {"community_id": comm["community_id"], "size": comm["size"], **rep,
                    "top_entities": comm["top_entities"], "doc_ids": comm["doc_ids"],
                    "allowed_chunks": allowed, "cache_file": cached_llm.relpath(rec)}
    return {"community_id": comm["community_id"], "error": "no valid report after retry"}
