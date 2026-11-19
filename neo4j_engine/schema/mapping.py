"""Resolve logical field names (id, name, ...) to the REAL property names in Neo4j.

Why: the Milestone 10 exporter chose the property names; Milestone 11 must not guess
them. `introspect.py` reads what is actually stored, and `GraphMap` picks, for each
logical field, the first candidate that really exists. Fields that do not exist
resolve to None and the queries simply leave them out.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Labels/relationship types known from the Milestone 10 sync (used as whitelist
# fallback when no introspection report is available).
CANONICAL_LABELS = (
    "AttackTactic", "AttackTechnique", "Campaign", "IntelligenceReport", "Malware",
    "Mitigation", "Software", "ThreatActor", "Tool", "Vulnerability", "Weakness",
)
CANDIDATE_ONLY_LABELS = ("Organization", "Sector")
REL_TYPES = (
    "AFFECTS", "CHILD_OF", "CONDUCTS", "HAS_WEAKNESS", "MENTIONS", "MITIGATES",
    "PART_OF_TACTIC", "RELATED_TO", "SUBTECHNIQUE_OF", "USES",
    "EXTRACTED_FROM", "PART_OF", "IN_COMMUNITY",
)

NODE_FIELDS: dict[str, tuple[str, ...]] = {
    "id": ("entity_id", "id"),
    "name": ("name", "canonical_name", "title", "label"),
    "aliases": ("aliases", "alias", "synonyms"),
    "description": ("description", "summary"),
    "origin": ("origin", "source_origin"),
    "evidence_type": ("evidence_type", "evidence_types", "evidence_kind"),
    "source_url": ("source_url", "url"),
    "date": ("modified_at", "last_modified_at", "last_modified", "modified", "updated_at", "published_at", "created_at"),
}
REL_FIELDS: dict[str, tuple[str, ...]] = {
    "id": ("rel_id", "relationship_id", "id"),
    "origin": ("origin",),
    "evidence_type": ("evidence_type", "evidence_types"),
    "description": ("description", "quote", "supporting_quote", "evidence_text"),
    "source_url": ("source_url", "url"),
}
TEXTUNIT_FIELDS: dict[str, tuple[str, ...]] = {
    "id": ("text_unit_id", "id"), "text": ("text",), "chunk_ids": ("chunk_ids", "chunk_id"),
}
COMMUNITY_FIELDS: dict[str, tuple[str, ...]] = {
    "id": ("community_id", "id"), "title": ("title", "name"),
    "summary": ("summary", "full_content", "report"), "level": ("level",),
}
LIST_TYPES = {"StringArray", "LongArray", "DoubleArray", "BooleanArray"}
DATE_TYPES = {"DateTime", "ZonedDateTime", "LocalDateTime", "Date"}


def ident(name: str) -> str:
    """Validate and backtick-quote a property/label/relationship identifier."""
    if not isinstance(name, str) or not _IDENT.match(name):
        raise ValueError(f"unsafe identifier: {name!r}")
    return f"`{name}`"


def _pick(candidates: tuple[str, ...], observed: dict[str, list[str]]) -> str | None:
    for c in candidates:
        if c in observed:
            return c
    return None


@dataclass(frozen=True)
class GraphMap:
    labels: frozenset[str] = frozenset()
    rel_types: frozenset[str] = frozenset()
    node: dict[str, str | None] = field(default_factory=dict)
    node_types: dict[str, list[str]] = field(default_factory=dict)   # actual prop -> property types
    rel: dict[str, str | None] = field(default_factory=dict)
    textunit: dict[str, str | None] = field(default_factory=dict)
    community: dict[str, str | None] = field(default_factory=dict)
    from_introspection: bool = False

    # ---- construction ------------------------------------------------------
    @staticmethod
    def default() -> "GraphMap":
        """Used only when the database was not introspected (offline / tests)."""
        return GraphMap(
            labels=frozenset(CANONICAL_LABELS + CANDIDATE_ONLY_LABELS + ("Entity", "Candidate", "TextUnit", "Community")),
            rel_types=frozenset(REL_TYPES),
            node={k: v[0] for k, v in NODE_FIELDS.items()},
            node_types={"aliases": ["StringArray"], "name": ["String"], "entity_id": ["String"]},
            rel={k: v[0] for k, v in REL_FIELDS.items()},
            textunit={k: v[0] for k, v in TEXTUNIT_FIELDS.items()},
            community={k: v[0] for k, v in COMMUNITY_FIELDS.items()},
        )

    @staticmethod
    def from_report(report: dict[str, Any]) -> "GraphMap":
        """Build from the dict produced by `introspect.introspect()`."""
        ent_props: dict[str, list[str]] = report.get("properties", {}).get("Entity", {})
        tu_props = report.get("properties", {}).get("TextUnit", {})
        co_props = report.get("properties", {}).get("Community", {})
        rel_props: dict[str, list[str]] = {}
        for _t, props in report.get("rel_properties", {}).items():
            for p, types in props.items():
                rel_props.setdefault(p, types)
        return GraphMap(
            labels=frozenset(report.get("labels", [])),
            rel_types=frozenset(report.get("rel_types", [])),
            node={k: _pick(v, ent_props) for k, v in NODE_FIELDS.items()},
            node_types=dict(ent_props),
            rel={k: _pick(v, rel_props) for k, v in REL_FIELDS.items()},
            textunit={k: _pick(v, tu_props) for k, v in TEXTUNIT_FIELDS.items()},
            community={k: _pick(v, co_props) for k, v in COMMUNITY_FIELDS.items()},
            from_introspection=True,
        )

    # ---- helpers used by the query builders -----------------------------------
    def n(self, logical: str, *, required: bool = False) -> str | None:
        actual = self.node.get(logical)
        if actual is None and required:
            raise LookupError(f"node property for {logical!r} was not found in the graph (run `schema` and check the report)")
        return actual

    def q(self, logical: str) -> str:
        """Backtick-quoted real property name; raises if the property is missing."""
        return ident(self.n(logical, required=True))

    def is_list(self, logical: str) -> bool:
        actual = self.node.get(logical)
        return bool(actual) and any(t in LIST_TYPES for t in self.node_types.get(actual, []))

    def is_temporal(self, logical: str) -> bool:
        actual = self.node.get(logical)
        return bool(actual) and any(t in DATE_TYPES for t in self.node_types.get(actual, []))

    def has_label(self, label: str) -> bool:
        return label in self.labels

    def check_labels(self, labels: list[str] | None) -> list[str] | None:
        """Whitelist user-supplied labels (types). Unknown labels are an error, not ignored."""
        if not labels:
            return None
        known = set(CANONICAL_LABELS) | set(CANDIDATE_ONLY_LABELS) | set(self.labels)
        bad = [l for l in labels if l not in known]
        if bad:
            raise ValueError(f"unknown entity type(s): {bad}; known: {sorted(known - {'Entity', 'Candidate', 'TextUnit', 'Community'})}")
        return list(labels)

    def check_rel_types(self, types: list[str] | None) -> list[str] | None:
        if not types:
            return None
        known = set(REL_TYPES) | set(self.rel_types)
        bad = [t for t in types if t not in known]
        if bad:
            raise ValueError(f"unknown relationship type(s): {bad}; known: {sorted(known)}")
        return [ident(t).strip("`") for t in types]

    def candidate_pred(self, var: str) -> str:
        """Cypher predicate that is true when `var` is a GraphRAG candidate."""
        if self.has_label("Candidate"):
            return f"{var}:Candidate"
        origin = self.node.get("origin")
        if origin:
            return f"coalesce({var}.{ident(origin)}, '') = 'graphrag'"
        return "false"

    def unresolved(self) -> list[str]:
        out = [f"node.{k}" for k, v in self.node.items() if v is None]
        out += [f"rel.{k}" for k, v in self.rel.items() if v is None]
        out += [f"textunit.{k}" for k, v in self.textunit.items() if v is None]
        out += [f"community.{k}" for k, v in self.community.items() if v is None]
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"node": self.node, "rel": self.rel, "textunit": self.textunit, "community": self.community,
                "from_introspection": self.from_introspection, "unresolved": self.unresolved()}
