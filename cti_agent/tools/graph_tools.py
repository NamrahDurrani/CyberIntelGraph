"""Read-only Cypher tools. Each query starts with a '// tool:<name>' comment:
it labels the query in Neo4j logs and lets the tests route fake answers.

Property names are NOT hard-coded: queries search the property lists found by
schema_map.SchemaMap, so they keep working if the M10 exporter names differ."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schema_map import Runner, SchemaMap, safe_label

LONG_FIELDS = {"description", "text", "summary", "content", "chunk_text", "references", "raw"}


# ------------------------------------------------------------------ small helpers
def trim(value: Any, limit: int = 200) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def display_name(props: dict[str, Any], schema: SchemaMap) -> str:
    for key in schema.name_props:
        if props.get(key) not in (None, ""):
            return trim(props[key], 120)
    return "(unnamed)"


def identifier_values(props: dict[str, Any], schema: SchemaMap) -> dict[str, str]:
    return {k: str(props[k]) for k in schema.id_props if props.get(k) not in (None, "")}


def main_label(labels: list[str], schema: SchemaMap) -> str:
    for label in labels:
        if label in schema.canonical_labels:
            return label
    return labels[0] if labels else "Node"


def describe_props(props: dict[str, Any], schema: SchemaMap, max_props: int = 14) -> str:
    """Compact 'key: value' lines for an evidence record (long fields trimmed)."""
    lines = []
    for key, value in props.items():
        if value in (None, "", [], {}):
            continue
        limit = 320 if key in LONG_FIELDS else 140
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value[:8])
        lines.append(f"{key}: {trim(value, limit)}")
        if len(lines) >= max_props:
            break
    return "\n".join(lines)


@dataclass
class EntityRef:
    eid: str
    label: str
    name: str
    ids: dict[str, str] = field(default_factory=dict)
    props: dict[str, Any] = field(default_factory=dict)
    term: str = ""
    match: str = "partial"  # "exact" or "partial"

    def key(self) -> str:
        return self.ids.get("cve_id") or next(iter(self.ids.values()), self.name)

    def to_dict(self) -> dict[str, Any]:
        return {"eid": self.eid, "label": self.label, "name": self.name, "ids": self.ids,
                "term": self.term, "match": self.match}


def _rank(ref: EntityRef, term_l: str) -> tuple:
    values = [ref.name.lower()] + [v.lower() for v in ref.ids.values()]
    if term_l in values:
        return (0, len(ref.name))
    if any(v.startswith(term_l) for v in values):
        return (1, len(ref.name))
    return (2, len(ref.name))


# --------------------------------------------------------------------- entity lookup
def find_entities(runner: Runner, schema: SchemaMap, term: str, *, exact: bool = False,
                  labels: list[str] | None = None, limit: int = 6) -> list[EntityRef]:
    term_l = term.strip().lower()
    if not term_l:
        return []
    props = list(dict.fromkeys(schema.name_props + schema.id_props))
    test = "= $term" if exact else "CONTAINS $term"
    cypher = (
        "// tool:find_entities\n"
        "MATCH (n) "
        "WHERE any(l IN labels(n) WHERE l IN $labels) "
        f"AND any(k IN $props WHERE n[k] IS NOT NULL AND toLower(toString(n[k])) {test}) "
        "RETURN elementId(n) AS eid, labels(n) AS labels, properties(n) AS props "
        "LIMIT $fetch"
    )
    rows = runner(cypher, {
        "labels": labels or schema.canonical_labels,
        "props": props,
        "term": term_l,
        "fetch": max(limit * 6, 30),
    })
    refs: list[EntityRef] = []
    for row in rows:
        p = row.get("props") or {}
        ref = EntityRef(
            eid=row["eid"],
            label=main_label(row.get("labels", []), schema),
            name=display_name(p, schema),
            ids=identifier_values(p, schema),
            props=p,
            term=term,
        )
        ref.match = "exact" if _rank(ref, term_l)[0] == 0 else "partial"
        refs.append(ref)
    refs.sort(key=lambda r: _rank(r, term_l))
    return refs[:limit]


# ----------------------------------------------------------------------- neighbours
def neighbor_summary(runner: Runner, schema: SchemaMap, eid: str,
                     rels: list[str] | None = None) -> list[dict[str, Any]]:
    exclude = [l for l in (schema.candidate_label, schema.textunit_label, schema.community_label) if l]
    cypher = (
        "// tool:neighbor_summary\n"
        "MATCH (n) WHERE elementId(n) = $eid "
        "MATCH (n)-[r]-(m) "
        "WHERE ($rels IS NULL OR type(r) IN $rels) "
        "AND NOT any(l IN labels(m) WHERE l IN $exclude) "
        "RETURN type(r) AS rel, startNode(r) = n AS outgoing, labels(m)[0] AS label, count(*) AS n "
        "ORDER BY n DESC"
    )
    return runner(cypher, {"eid": eid, "rels": rels, "exclude": exclude})


def neighbor_sample(runner: Runner, schema: SchemaMap, eid: str, rel: str, outgoing: bool,
                    label: str, limit: int = 12) -> list[dict[str, Any]]:
    cypher = (
        "// tool:neighbor_sample\n"
        "MATCH (n) WHERE elementId(n) = $eid "
        "MATCH (n)-[r]-(m) "
        "WHERE type(r) = $rel AND (startNode(r) = n) = $outgoing AND $label IN labels(m) "
        "RETURN properties(m) AS props, properties(r) AS rprops "
        "LIMIT $limit"
    )
    return runner(cypher, {"eid": eid, "rel": rel, "outgoing": outgoing, "label": label, "limit": limit})


def shortest_path(runner: Runner, schema: SchemaMap, eid_a: str, eid_b: str,
                  max_hops: int = 3) -> dict[str, Any] | None:
    hops = max(1, min(int(max_hops), 4))
    exclude = [l for l in (schema.candidate_label, schema.textunit_label, schema.community_label) if l]
    cypher = (
        "// tool:shortest_path\n"
        "MATCH (a), (b) WHERE elementId(a) = $a AND elementId(b) = $b "
        f"MATCH p = shortestPath((a)-[*..{hops}]-(b)) "
        "WHERE none(x IN nodes(p) WHERE any(l IN labels(x) WHERE l IN $exclude)) "
        "RETURN [x IN nodes(p) | {label: labels(x)[0], "
        "name: head([k IN $props WHERE x[k] IS NOT NULL | toString(x[k])])}] AS nodes, "
        "[r IN relationships(p) | type(r)] AS rels "
        "LIMIT 1"
    )
    rows = runner(cypher, {"a": eid_a, "b": eid_b, "exclude": exclude,
                           "props": list(dict.fromkeys(schema.name_props + schema.id_props))})
    return rows[0] if rows else None


# ----------------------------------------------------------- candidates and reports
def candidates_for(runner: Runner, schema: SchemaMap, term: str, limit: int = 8) -> list[dict[str, Any]]:
    if not schema.candidate_label or not term.strip():
        return []
    cand = safe_label(schema.candidate_label)
    unit = f"(t:`{safe_label(schema.textunit_label)}`)" if schema.textunit_label else "(t)"
    cypher = (
        "// tool:candidates_for\n"
        f"MATCH (c:`{cand}`) "
        "WHERE any(k IN $props WHERE c[k] IS NOT NULL AND toLower(toString(c[k])) CONTAINS $term) "
        f"OPTIONAL MATCH (c)-[:EXTRACTED_FROM]-{unit} "
        "WITH c, [u IN collect(DISTINCT properties(t)) WHERE u IS NOT NULL][..3] AS units "
        "RETURN elementId(c) AS eid, properties(c) AS props, units "
        "LIMIT $limit"
    )
    return runner(cypher, {"props": list(dict.fromkeys(schema.name_props + schema.id_props)),
                           "term": term.strip().lower(), "limit": limit})


def candidate_relations(runner: Runner, schema: SchemaMap, eid: str, limit: int = 10) -> list[dict[str, Any]]:
    if not schema.candidate_label:
        return []
    cand = safe_label(schema.candidate_label)
    cypher = (
        "// tool:candidate_relations\n"
        f"MATCH (c)-[r]-(d:`{cand}`) WHERE elementId(c) = $eid "
        "RETURN type(r) AS rel, startNode(r) = c AS outgoing, properties(d) AS props, "
        "properties(r) AS rprops LIMIT $limit"
    )
    return runner(cypher, {"eid": eid, "limit": limit})


def report_mentions(runner: Runner, schema: SchemaMap, eid: str, limit: int = 5) -> list[dict[str, Any]]:
    if not schema.report_label:
        return []
    rep = safe_label(schema.report_label)
    cypher = (
        "// tool:report_mentions\n"
        f"MATCH (r:`{rep}`)-[:MENTIONS]-(n) WHERE elementId(n) = $eid "
        "RETURN properties(r) AS props LIMIT $limit"
    )
    return runner(cypher, {"eid": eid, "limit": limit})


def textunits_matching(runner: Runner, schema: SchemaMap, terms: list[str], limit: int = 6) -> list[dict[str, Any]]:
    if not schema.textunit_label or not terms:
        return []
    unit = safe_label(schema.textunit_label)
    cypher = (
        "// tool:textunits_matching\n"
        f"MATCH (t:`{unit}`) "
        "WHERE any(term IN $terms WHERE any(k IN $props WHERE t[k] IS NOT NULL "
        "AND toLower(toString(t[k])) CONTAINS term)) "
        "RETURN elementId(t) AS eid, properties(t) AS props LIMIT $limit"
    )
    return runner(cypher, {"terms": [t.lower() for t in terms if t.strip()],
                           "props": schema.text_props, "limit": limit})
