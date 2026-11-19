"""Read-only inspection of the live graph: labels, relationship types, property
names/types, counts, indexes and constraints. Output feeds `GraphMap`."""
from __future__ import annotations

import re
from typing import Any

from neo4j_engine.schema.mapping import GraphMap

_LABEL = re.compile(r"`([^`]+)`")


def _labels_of(node_labels: Any) -> list[str]:
    if isinstance(node_labels, list):
        return [str(x) for x in node_labels]
    return _LABEL.findall(str(node_labels)) or ([str(node_labels).strip(":")] if node_labels else [])


def introspect(client) -> dict[str, Any]:
    labels = [r["label"] for r in client.run_read("CALL db.labels() YIELD label RETURN label ORDER BY label")]
    rel_types = [r["t"] for r in client.run_read("CALL db.relationshipTypes() YIELD relationshipType AS t RETURN t ORDER BY t")]
    node_counts = {r["l"]: r["c"] for r in client.run_read("MATCH (n) UNWIND labels(n) AS l RETURN l, count(*) AS c ORDER BY l")}
    rel_counts = {r["t"]: r["c"] for r in client.run_read("MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c ORDER BY t")}

    props: dict[str, dict[str, list[str]]] = {}
    for r in client.run_read("CALL db.schema.nodeTypeProperties() YIELD nodeLabels, propertyName, propertyTypes "
                             "RETURN nodeLabels, propertyName, propertyTypes"):
        if not r.get("propertyName"):
            continue
        for lab in _labels_of(r["nodeLabels"]):
            slot = props.setdefault(lab, {})
            types = slot.setdefault(r["propertyName"], [])
            for t in r.get("propertyTypes") or []:
                if t not in types:
                    types.append(t)

    rel_props: dict[str, dict[str, list[str]]] = {}
    for r in client.run_read("CALL db.schema.relTypeProperties() YIELD relType, propertyName, propertyTypes "
                             "RETURN relType, propertyName, propertyTypes"):
        if not r.get("propertyName"):
            continue
        t = str(r["relType"]).strip(":`")
        slot = rel_props.setdefault(t, {})
        types = slot.setdefault(r["propertyName"], [])
        for x in r.get("propertyTypes") or []:
            if x not in types:
                types.append(x)

    indexes = client.run_read("SHOW INDEXES YIELD name, type, entityType, labelsOrTypes, properties, state "
                              "RETURN name, type, entityType, labelsOrTypes, properties, state ORDER BY name")
    constraints = client.run_read("SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties "
                                  "RETURN name, type, labelsOrTypes, properties ORDER BY name")
    report = {
        "labels": labels, "rel_types": rel_types, "node_counts": node_counts, "rel_counts": rel_counts,
        "properties": props, "rel_properties": rel_props, "indexes": indexes, "constraints": constraints,
    }
    report["graph_map"] = GraphMap.from_report(report).to_dict()
    return report
