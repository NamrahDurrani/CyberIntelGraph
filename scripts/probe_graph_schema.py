r"""Read-only look at the Neo4j graph: labels, relationship types, property keys,
and which properties the agent will use. Writes data/agent/graph_schema.json.

  python scripts\probe_graph_schema.py
"""
from __future__ import annotations

import sys

import _bootstrap  # noqa: F401

from cti_agent.config import Settings
from cti_agent.neo4j_client import Neo4jConnectionError, Neo4jRunner
from cti_agent.schema_map import SchemaMap


def main() -> int:
    settings = Settings.from_env()
    try:
        runner = Neo4jRunner.from_settings(settings)
        runner.verify()
    except Exception as exc:  # noqa: BLE001
        print(f"CANNOT CONNECT: {exc}")
        print("Check NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD in .env (Aura must be running).")
        return 2
    try:
        schema = SchemaMap.load_or_discover(runner, settings.resolve(settings.schema_cache), refresh=True)
        print("\nNODE LABELS")
        for label in schema.labels:
            n = runner(f"// tool:probe_count\nMATCH (n:`{label}`) RETURN count(n) AS n", {})[0]["n"]
            keys = ", ".join(schema.property_keys.get(label, [])[:14])
            print(f"  {label:<24}{n:>7}   keys: {keys}")
        print("\nRELATIONSHIP TYPES")
        for rel in schema.rel_types:
            n = runner(f"// tool:probe_count\nMATCH ()-[r:`{rel}`]->() RETURN count(r) AS n", {})[0]["n"]
            print(f"  {rel:<24}{n:>7}")
        print("\nWHAT THE AGENT WILL USE")
        print(f"  candidate label : {schema.candidate_label}")
        print(f"  text unit label : {schema.textunit_label}")
        print(f"  community label : {schema.community_label}")
        print(f"  report label    : {schema.report_label}")
        print(f"  name properties : {schema.name_props}")
        print(f"  id properties   : {schema.id_props}")
        print(f"  text properties : {schema.text_props}")
        if not schema.candidate_label:
            print("\nWARNING: no label containing 'candidate' was found, so GraphRAG candidates cannot be searched.")
            print("         Send this output so the candidate label can be set.")
        print(f"\nSaved: {settings.resolve(settings.schema_cache)}")
        return 0
    finally:
        runner.close()


if __name__ == "__main__":
    sys.exit(main())
