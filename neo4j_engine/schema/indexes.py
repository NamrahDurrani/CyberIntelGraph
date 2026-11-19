"""Milestone 11 indexes (idempotent: IF NOT EXISTS). Uniqueness constraints from
Milestone 10 already cover lookups by id; these speed up lookups by name."""
from __future__ import annotations

from neo4j_engine.schema.mapping import GraphMap, ident


def plan_indexes(gm: GraphMap) -> list[str]:
    name = gm.n("name")
    if not name:
        return []
    p = ident(name)
    return [
        f"CREATE RANGE INDEX m11_entity_name_range IF NOT EXISTS FOR (n:Entity) ON (n.{p})",
        f"CREATE TEXT INDEX m11_entity_name_text IF NOT EXISTS FOR (n:Entity) ON (n.{p})",
    ]


def apply_indexes(client, gm: GraphMap) -> list[str]:
    return client.run_schema_write(plan_indexes(gm))
