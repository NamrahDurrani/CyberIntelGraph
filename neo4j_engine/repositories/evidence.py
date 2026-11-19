"""Evidence classification: documented vs inferred vs candidate.

Two separate questions are kept apart:
  * evidence_status - what the STORED record says about itself
        'candidate'    origin is graphrag or evidence type mentions llm/candidate
        'structured'   a canonical record (ATT&CK, NVD, KEV, CWE ... or human-reviewed)
        'unclassified' nothing recognisable stored (never silently upgraded)
  * derivation      - HOW we reached the claim
        'direct'  one canonical edge (actor USES technique)
        'via_campaign' / 'via_software'  two canonical edges chained (derived)
        'candidate' a GraphRAG RELATED_TO edge
and one display value combines them:
  claim_class = documented | inferred | candidate
"""
from __future__ import annotations

from typing import Any

from neo4j_engine.schema.mapping import GraphMap

CLASS_ORDER = {"documented": 0, "inferred": 1, "candidate": 2}


def _as_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return " ".join(str(x) for x in v).lower()
    return str(v).lower()


def evidence_status(props: dict[str, Any], gm: GraphMap, *, kind: str = "rel") -> str:
    fields = gm.rel if kind == "rel" else gm.node
    origin = _as_text(props.get(fields.get("origin"))) if fields.get("origin") else ""
    etype = _as_text(props.get(fields.get("evidence_type"))) if fields.get("evidence_type") else ""
    if origin == "graphrag" or "llm" in etype or "candidate" in etype:
        return "candidate"
    if "inferred" in etype:
        return "candidate"      # an inferred relationship is never treated as documented
    if etype or origin:
        return "structured"
    return "unclassified"


def claim_class(derivation: str, statuses: list[str]) -> str:
    """Display class for ONE path."""
    if derivation == "candidate" or "candidate" in statuses:
        return "candidate"
    if derivation == "direct":
        return "documented"
    return "inferred"


def best_class(classes: list[str]) -> str:
    return min(classes, key=lambda c: CLASS_ORDER[c]) if classes else "candidate"


def slim(props: dict[str, Any] | None, max_len: int = 400) -> dict[str, Any]:
    """Shorten long strings so results stay readable; lists are capped at 20 items."""
    out: dict[str, Any] = {}
    for k, v in (props or {}).items():
        if isinstance(v, str) and len(v) > max_len:
            v = v[:max_len] + "…"
        elif isinstance(v, list) and len(v) > 20:
            v = v[:20] + [f"… (+{len(v) - 20} more)"]
        out[k] = v
    return out
