"""Discover the real shape of the Neo4j graph instead of guessing it.

M10 created the graph; this module asks the database which labels,
relationship types and property keys exist, then decides which property
holds a node's name / identifier / text. The result is cached in
data/agent/graph_schema.json (git-ignored) so it is only discovered once.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

Runner = Callable[[str, dict | None], list[dict]]

CANONICAL_LABELS = [
    "AttackTactic", "AttackTechnique", "Campaign", "IntelligenceReport", "Malware",
    "Mitigation", "Software", "ThreatActor", "Tool", "Vulnerability", "Weakness",
]

NAME_PROP_PREFERENCE = [
    "name", "title", "cve_id", "cveID", "cwe_id", "attack_id", "technique_id",
    "external_id", "canonical_id", "id", "entity_id",
]
ID_PROP_PREFERENCE = [
    "cve_id", "cveID", "cwe_id", "attack_id", "technique_id", "external_id",
    "canonical_id", "stix_id", "id", "entity_id",
]
TEXT_PROP_PREFERENCE = ["text", "chunk_text", "content", "description", "summary"]

_SAFE_LABEL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def safe_label(label: str) -> str:
    """Labels are interpolated into Cypher, so only plain identifiers are allowed."""
    if not _SAFE_LABEL.match(label or ""):
        raise ValueError(f"Unsafe label name: {label!r}")
    return label


@dataclass
class SchemaMap:
    labels: list[str] = field(default_factory=list)
    rel_types: list[str] = field(default_factory=list)
    property_keys: dict[str, list[str]] = field(default_factory=dict)
    canonical_labels: list[str] = field(default_factory=lambda: list(CANONICAL_LABELS))
    candidate_label: str | None = None
    textunit_label: str | None = None
    community_label: str | None = None
    report_label: str | None = "IntelligenceReport"
    name_props: list[str] = field(default_factory=lambda: list(NAME_PROP_PREFERENCE))
    id_props: list[str] = field(default_factory=lambda: list(ID_PROP_PREFERENCE))
    text_props: list[str] = field(default_factory=lambda: list(TEXT_PROP_PREFERENCE))

    # ------------------------------------------------------------------ helpers
    def has_rel(self, rel: str) -> bool:
        return not self.rel_types or rel in self.rel_types

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict) -> "SchemaMap":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    # ---------------------------------------------------------------- discovery
    @classmethod
    def discover(cls, runner: Runner) -> "SchemaMap":
        labels = [r["label"] for r in runner(
            "// tool:schema_labels\nCALL db.labels() YIELD label RETURN label ORDER BY label", {})]
        rels = [r["relationshipType"] for r in runner(
            "// tool:schema_rel_types\nCALL db.relationshipTypes() YIELD relationshipType "
            "RETURN relationshipType ORDER BY relationshipType", {})]

        keys_by_label: dict[str, list[str]] = {}
        for label in labels:
            try:
                safe_label(label)
            except ValueError:
                continue
            rows = runner(
                f"// tool:schema_keys\nMATCH (n:`{label}`) WITH n LIMIT 50 "
                "UNWIND keys(n) AS k RETURN DISTINCT k ORDER BY k", {})
            keys_by_label[label] = [r["k"] for r in rows]

        all_keys = {k for ks in keys_by_label.values() for k in ks}

        def pick(preference: list[str]) -> list[str]:
            found = [p for p in preference if p in all_keys]
            return found or list(preference)

        def find_label(*needles: str) -> str | None:
            for label in labels:
                low = label.lower().replace("_", "")
                if any(n in low for n in needles):
                    return label
            return None

        candidate = find_label("candidate")
        textunit = find_label("textunit")
        community = find_label("community")
        canonical = [l for l in CANONICAL_LABELS if l in labels] or list(CANONICAL_LABELS)
        report = "IntelligenceReport" if "IntelligenceReport" in labels else None

        return cls(
            labels=labels,
            rel_types=rels,
            property_keys=keys_by_label,
            canonical_labels=canonical,
            candidate_label=candidate,
            textunit_label=textunit,
            community_label=community,
            report_label=report,
            name_props=pick(NAME_PROP_PREFERENCE),
            id_props=pick(ID_PROP_PREFERENCE),
            text_props=pick(TEXT_PROP_PREFERENCE),
        )

    @classmethod
    def load_or_discover(cls, runner: Runner, cache_path: Path, refresh: bool = False) -> "SchemaMap":
        if cache_path.exists() and not refresh:
            try:
                return cls.from_dict(json.loads(cache_path.read_text(encoding="utf-8")))
            except (ValueError, OSError):
                pass
        schema = cls.discover(runner)
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(schema.to_json(), encoding="utf-8")
        except OSError:
            pass
        return schema
