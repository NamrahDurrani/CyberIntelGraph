"""LLM extraction of entities and relationships from advisory text, with grounding checks.

Everything the model returns is a CANDIDATE (evidence type `llm_extracted_candidate`).
Before it is kept, each item must be grounded in the text it came from:
  * an entity's name must literally occur in the window text;
  * a relationship's two endpoints must be accepted entities and its supporting quote must
    (almost) occur in the text (>= 80% of the quote's words), else it is dropped.
Dropped counts are recorded, so the hallucination rate is a measured number.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from canonical.ids import CVE_RE, TECH_RE, slug
from rag.bm25 import normalise_text
from rag.llm import LLMError

PROMPT_VERSION = "1"
ENTITY_TYPES = ("ThreatActor", "Malware", "Tool", "Vulnerability", "AttackTechnique", "Software",
                "Organization", "Campaign", "Mitigation", "Sector")   # Sector is extraction-only
REL_TYPES = ("USES", "EXPLOITS", "TARGETS", "CONDUCTS", "DELIVERS", "MITIGATES", "AFFECTS", "RELATED_TO")
_TYPE_BY_LOWER = {t.lower(): t for t in ENTITY_TYPES}
_TYPE_BY_LOWER.update({"attack_technique": "AttackTechnique", "technique": "AttackTechnique",
                       "threatactor": "ThreatActor", "threat_actor": "ThreatActor", "actor": "ThreatActor",
                       "vulnerability": "Vulnerability", "cve": "Vulnerability", "org": "Organization"})

SYSTEM = f"""You extract a cyber-threat knowledge graph from CISA advisory text.
Reply with ONE JSON object only - no prose, no markdown fences.
Schema:
{{"entities":[{{"name":str,"type":T,"description":str}}],
 "relationships":[{{"source":str,"target":str,"type":R,"description":str,"quote":str,"chunk":str}}]}}
T is one of: {", ".join(ENTITY_TYPES)}.
R is one of: {", ".join(REL_TYPES)}.
Rules:
- Use only facts stated in the text. Never add outside knowledge.
- "name" is written exactly as in the text. CVE ids look like CVE-2024-3400; ATT&CK ids like T1059.001.
- Skip generic words such as "attackers", "network", "organizations" unless a specific named sector or victim.
- "source" and "target" must be names that also appear in "entities".
- "quote" copies at most 25 consecutive words from the text that support the relationship;
  "chunk" is the [chunk id] header above that quote.
- Directions: ThreatActor USES Malware/Tool/AttackTechnique; ThreatActor or Malware EXPLOITS Vulnerability;
  anything TARGETS Organization/Sector/Software; Vulnerability AFFECTS Software;
  Mitigation MITIGATES AttackTechnique/Vulnerability; ThreatActor CONDUCTS Campaign; Malware DELIVERS Malware.
- At most 40 entities and 40 relationships. If nothing qualifies return {{"entities":[],"relationships":[]}}."""


@dataclass
class Window:
    doc_id: str
    index: int
    chunk_ids: list[str]
    text: str
    words: int
    title: str = ""
    source_url: str = ""
    report_id: str = ""
    chunk_texts: dict = field(default_factory=dict)
    suffix: str = ""                      # "a" / "b" / "aa" ... when a too-large window was split

    @property
    def window_id(self) -> str:
        return f"{self.doc_id}_w{self.index:02d}{self.suffix}"

    def user_prompt(self) -> str:
        return f"Advisory: {self.title}\n\n{self.text}"


def make_windows(doc_chunks: list[dict], max_words: int = 1400, hard_cap_words: int = 2600) -> list[Window]:
    """Pack consecutive chunks of one advisory into windows (fewer, richer LLM calls)."""
    windows: list[Window] = []
    cur: list[dict] = []
    cur_words = 0

    def flush():
        nonlocal cur, cur_words
        if cur:
            first = cur[0]
            text = "\n\n".join(f"[{c['chunk_id']}]\n{c['_t']}" for c in cur)
            windows.append(Window(doc_id=first["doc_id"], index=len(windows) + 1,
                                  chunk_ids=[c["chunk_id"] for c in cur], text=text, words=cur_words,
                                  title=first.get("title", ""), source_url=first.get("source_url", ""),
                                  report_id=first.get("report_id", ""),
                                  chunk_texts={c["chunk_id"]: c["_t"] for c in cur}))
        cur, cur_words = [], 0

    for c in sorted(doc_chunks, key=lambda c: c["chunk_index"]):
        words = (c.get("text") or "").split()
        has_id = bool(c.get("cve_ids") or c.get("technique_ids"))
        if len(words) < 8 and not has_id:
            continue                                        # banner / boilerplate line
        c = dict(c, _t=" ".join(words[:hard_cap_words]))
        n = min(len(words), hard_cap_words)
        if cur and cur_words + n > max_words:
            flush()
        cur.append(c)
        cur_words += n
    flush()
    return windows


def split_window(w: Window) -> list[Window] | None:
    """Halve a window that the API refused as too large (HTTP 413). Several chunks: split between
    chunks at the word midpoint. One chunk: split its text in two. None if too small to split."""
    def build(chunk_ids, texts, suffix):
        text = "\n\n".join(f"[{c}]\n{texts[c]}" for c in chunk_ids)
        return Window(doc_id=w.doc_id, index=w.index, chunk_ids=list(chunk_ids), text=text,
                      words=sum(len(texts[c].split()) for c in chunk_ids), title=w.title,
                      source_url=w.source_url, report_id=w.report_id, chunk_texts=dict(texts),
                      suffix=w.suffix + suffix)
    ids = w.chunk_ids
    if len(ids) > 1:
        sizes = [len(w.chunk_texts[c].split()) for c in ids]
        half, acc, cut = sum(sizes) / 2, 0, 1
        for i, n in enumerate(sizes[:-1], start=1):
            acc += n
            cut = i
            if acc >= half:
                break
        return [build(ids[:cut], {c: w.chunk_texts[c] for c in ids[:cut]}, "a"),
                build(ids[cut:], {c: w.chunk_texts[c] for c in ids[cut:]}, "b")]
    words = w.chunk_texts[ids[0]].split()
    if len(words) < 60:
        return None
    mid = len(words) // 2
    return [build(ids, {ids[0]: " ".join(words[:mid])}, "a"), build(ids, {ids[0]: " ".join(words[mid:])}, "b")]


# ----- parsing and validation ---------------------------------------------------------------
def parse_json(text: str):
    """The first JSON object in a model reply (tolerates fences, prose around it, trailing commas)."""
    if not text:
        return None
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I)
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end <= start:
        return None
    body = t[start:end + 1]
    for candidate in (body, re.sub(r",\s*([}\]])", r"\1", body)):
        try:
            obj = json.loads(candidate)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            continue
    return None


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", normalise_text(text)).strip()


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*", _norm(text))


def quote_grounded(quote: str, window_text: str, threshold: float = 0.8) -> bool:
    q = _tokens(quote)
    if len(q) < 3:
        return False
    have = set(_tokens(window_text))
    return sum(t in have for t in q) / len(q) >= threshold


def _s(value, limit: int) -> str:
    return re.sub(r"\s+", " ", value).strip()[:limit] if isinstance(value, str) else ""


def validate_extraction(raw: dict, window: Window) -> dict:
    """Keep only grounded, well-formed candidates; count what was dropped and why."""
    dropped: dict[str, int] = {}

    def drop(reason):
        dropped[reason] = dropped.get(reason, 0) + 1

    wtext = _norm(window.text)
    entities, by_slug = [], {}
    for e in (raw.get("entities") or [])[:60]:
        if not isinstance(e, dict):
            drop("entity_not_object")
            continue
        name = _s(e.get("name"), 120)
        etype = _TYPE_BY_LOWER.get(_s(e.get("type"), 40).lower().replace(" ", ""))
        if not name:
            drop("entity_no_name")
            continue
        if not etype:
            drop("entity_bad_type")
            continue
        if _norm(name) not in wtext:
            drop("entity_not_in_text")
            continue
        rec = {"name": name, "type": etype, "description": _s(e.get("description"), 240)}
        cve = CVE_RE.search(name)
        tech = TECH_RE.search(name)
        if etype == "Vulnerability" and cve:
            rec["cve_id"] = cve.group(0).upper()
        if etype == "AttackTechnique" and tech:
            rec["attack_id"] = tech.group(0)
        if slug(name) in by_slug:
            drop("entity_duplicate")
            continue
        by_slug[slug(name)] = rec
        entities.append(rec)

    rels = []
    for r in (raw.get("relationships") or [])[:60]:
        if not isinstance(r, dict):
            drop("rel_not_object")
            continue
        s, t = by_slug.get(slug(_s(r.get("source"), 120))), by_slug.get(slug(_s(r.get("target"), 120)))
        if not s or not t:
            drop("rel_unknown_endpoint")
            continue
        if s is t:
            drop("rel_self_loop")
            continue
        rtype = _s(r.get("type"), 30).upper().replace(" ", "_")
        if rtype not in REL_TYPES:
            rtype = "RELATED_TO"
            drop("rel_type_fallback")                        # kept, but counted
        quote = _s(r.get("quote"), 400)
        if not quote_grounded(quote, window.text):
            drop("rel_quote_not_in_text")
            continue
        chunk = _s(r.get("chunk"), 200).strip("[] ")
        if chunk not in window.chunk_ids:
            chunk = next((cid for cid in window.chunk_ids if quote_grounded(quote, window.chunk_texts[cid])), None)
        rels.append({"source": s["name"], "target": t["name"], "type": rtype,
                     "description": _s(r.get("description"), 240), "quote": quote, "chunk": chunk})
    return {"window_id": window.window_id, "doc_id": window.doc_id, "chunk_ids": list(window.chunk_ids),
            "entities": entities, "relationships": rels, "dropped": dropped,
            "raw_counts": {"entities": len(raw.get("entities") or []),
                           "relationships": len(raw.get("relationships") or [])}}


def extract_window(cached_llm, window: Window) -> dict:
    """One window -> validated candidates (or {'error': ...}). One JSON-repair retry."""
    user = window.user_prompt()
    for attempt, suffix in enumerate(("", "\n\nYour previous reply was not valid JSON. "
                                          "Reply with ONLY the JSON object described above.")):
        try:
            rec = cached_llm.complete("extract", SYSTEM, user + suffix, label=window.window_id)
        except LLMError as ex:
            msg = str(ex)
            return {"window_id": window.window_id, "doc_id": window.doc_id, "error": f"llm: {msg}",
                    "too_large": "413" in msg or "too large" in msg.lower()}
        parsed = parse_json(rec["text"])
        if parsed is not None:
            out = validate_extraction(parsed, window)
            out["finish_reason"] = rec.get("finish_reason")
            out["cache_file"] = cached_llm.relpath(rec)
            out["retrieved_at"] = rec.get("created_at")
            out["from_cache"] = rec["from_cache"]
            return out
    return {"window_id": window.window_id, "doc_id": window.doc_id, "error": "reply was not valid JSON twice"}
