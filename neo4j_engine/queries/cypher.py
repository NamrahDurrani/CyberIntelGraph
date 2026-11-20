"""Cypher builders. RULES: user text is ONLY ever sent as a $parameter; labels,
relationship types and property names are validated (whitelist + identifier regex)
and backtick-quoted before they are placed in query text."""
from __future__ import annotations

from neo4j_engine.schema.mapping import GraphMap, ident


def find_entities(gm: GraphMap, *, typed: bool, include_candidates: bool) -> str:
    idp, namep = f"n.{gm.q('id')}", f"n.{gm.q('name')}"
    alias = f"n.{gm.q('aliases')}" if gm.n("aliases") and gm.is_list("aliases") else None
    conds = [f"toLower({idp}) = $q", f"toLower({idp}) ENDS WITH $qsuf", f"toLower({namep}) CONTAINS $q"]
    ranks = [f"WHEN toLower({idp}) = $q OR toLower({idp}) ENDS WITH $qsuf THEN 0", f"WHEN toLower({namep}) = $q THEN 1"]
    if alias:
        conds.append(f"any(a IN {alias} WHERE toLower(a) CONTAINS $q)")
        ranks.append(f"WHEN any(a IN {alias} WHERE toLower(a) = $q) THEN 2")
    ranks.append(f"WHEN toLower({namep}) STARTS WITH $q THEN 3")
    where = ["(" + " OR ".join(conds) + ")"]
    if typed:
        where.append("any(l IN labels(n) WHERE l IN $types)")
    if not include_candidates:
        where.append(f"NOT ({gm.candidate_pred('n')})")
    return (
        "MATCH (n:Entity)\nWHERE " + "\n  AND ".join(where) + "\n"
        "WITH n, CASE " + " ".join(ranks) + " ELSE 4 END AS rank\n"
        f"RETURN labels(n) AS labels, properties(n) AS props, rank\n"
        f"ORDER BY rank, size(coalesce({namep}, '')), {idp}\nLIMIT $limit"
    )


def get_entity(gm: GraphMap) -> str:
    return f"MATCH (n:Entity {{{gm.q('id')}: $id}}) RETURN labels(n) AS labels, properties(n) AS props"


def degree_by_type(gm: GraphMap) -> str:
    return (f"MATCH (n:Entity {{{gm.q('id')}: $id}})-[r]-() "
            "RETURN type(r) AS rel_type, count(*) AS n ORDER BY n DESC")


def neighbors(gm: GraphMap, *, typed_rels: list[str] | None, include_candidates: bool) -> str:
    rel_filter = f" AND type(r) IN $rel_types" if typed_rels else ""
    cand = "" if include_candidates else f" AND NOT ({gm.candidate_pred('m')})"
    return (
        f"MATCH (n:Entity {{{gm.q('id')}: $id}})-[r]-(m)\n"
        f"WHERE true{rel_filter}{cand}\n"
        "RETURN type(r) AS rel_type, startNode(r) = n AS outgoing, properties(r) AS rprops,\n"
        "       labels(m) AS labels, properties(m) AS props\n"
        f"ORDER BY rel_type, coalesce(m.{gm.q('name')}, '')\nLIMIT $limit"
    )


def actor_techniques_direct(gm: GraphMap, rel: str = "USES") -> str:
    return (
        f"MATCH (a:Entity)-[r:{ident(rel)}]->(t:AttackTechnique)\n"
        f"WHERE a.{gm.q('id')} IN $ids\n"
        "RETURN properties(t) AS tprops, labels(t) AS tlabels, properties(r) AS rprops, null AS via\nLIMIT $limit"
    )


def actor_techniques_via_campaign(gm: GraphMap) -> str:
    return (
        "MATCH (a:Entity)-[r1:CONDUCTS]-(c:Campaign)-[r2:USES]->(t:AttackTechnique)\n"
        f"WHERE a.{gm.q('id')} IN $ids\n"
        "RETURN properties(t) AS tprops, labels(t) AS tlabels, properties(r2) AS rprops,\n"
        "       properties(r1) AS rprops_first, properties(c) AS via\nLIMIT $limit"
    )


def actor_techniques_via_software(gm: GraphMap) -> str:
    return (
        "MATCH (a:Entity)-[r1:USES]->(s)-[r2:USES]->(t:AttackTechnique)\n"
        f"WHERE a.{gm.q('id')} IN $ids AND (s:Malware OR s:Tool)\n"
        "RETURN properties(t) AS tprops, labels(t) AS tlabels, properties(r2) AS rprops,\n"
        "       properties(r1) AS rprops_first, properties(s) AS via\nLIMIT $limit"
    )


def actor_techniques_candidate(gm: GraphMap) -> str:
    return (
        "MATCH (a:Entity)-[r:RELATED_TO]-(t:AttackTechnique)\n"
        f"WHERE a.{gm.q('id')} IN $ids\n"
        "RETURN properties(t) AS tprops, labels(t) AS tlabels, properties(r) AS rprops, null AS via\nLIMIT $limit"
    )


def same_name_entities(gm: GraphMap) -> str:
    return (f"MATCH (x:Entity) WHERE toLower(x.{gm.q('name')}) = $name AND x.{gm.q('id')} <> $id\n"
            f"RETURN x.{gm.q('id')} AS id, labels(x) AS labels LIMIT 10")


def reports_mentioning(gm: GraphMap) -> str:
    return (
        "MATCH (rep:IntelligenceReport)-[:MENTIONS]-(t:Entity)\n"
        f"WHERE t.{gm.q('id')} IN $ids\n"
        f"RETURN t.{gm.q('id')} AS tid, properties(rep) AS rprops LIMIT $limit"
    )


def provenance(gm: GraphMap) -> str:
    return (
        f"MATCH (n:Entity {{{gm.q('id')}: $id}})\n"
        "RETURN labels(n) AS labels, properties(n) AS props,\n"
        "  [(n)-[:EXTRACTED_FROM]-(tu:TextUnit) | properties(tu)] AS text_units,\n"
        "  [(n)-[:IN_COMMUNITY]-(c:Community) | properties(c)] AS communities,\n"
        "  [(rep:IntelligenceReport)-[:MENTIONS]-(n) | properties(rep)] AS reports"
    )


def relationship_evidence(gm: GraphMap) -> str:
    """Text units behind the candidate relationships touching an entity."""
    return (
        f"MATCH (n:Entity {{{gm.q('id')}: $id}})-[r:RELATED_TO]-(m:Entity)\n"
        "RETURN properties(r) AS rprops, labels(m) AS labels, properties(m) AS props,\n"
        "  [(n)-[:EXTRACTED_FROM]-(tu:TextUnit) | properties(tu)] AS text_units LIMIT $limit"
    )


def shortest_path(gm: GraphMap, *, rel_types: list[str] | None, max_hops: int, include_candidates: bool, all_paths: bool) -> str:
    hops = max(1, min(int(max_hops), 5))
    rels = ":" + "|".join(ident(t) for t in rel_types) if rel_types else ""
    fn = "allShortestPaths" if all_paths else "shortestPath"
    idp, namep = gm.q("id"), gm.q("name") if gm.n("name") else None
    cand = "" if include_candidates else f"\nWHERE none(x IN nodes(p) WHERE {gm.candidate_pred('x')})"
    name_expr = f", name: x.{namep}" if namep else ""
    return (
        f"MATCH (a:Entity {{{idp}: $a}}), (b:Entity {{{idp}: $b}})\n"
        f"MATCH p = {fn}((a)-[{rels}*..{hops}]-(b)){cand}\n"
        f"RETURN [x IN nodes(p) | {{id: x.{idp}, labels: labels(x){name_expr}}}] AS nodes,\n"
        f"       [r IN relationships(p) | {{type: type(r), from: startNode(r).{idp}, to: endNode(r).{idp}}}] AS rels,\n"
        "       length(p) AS hops\nLIMIT $limit"
    )


def changed_since(gm: GraphMap, *, typed: bool) -> str:
    """Entities whose date property is on/after $since.

    * real Neo4j temporal property -> compared as a datetime;
    * STRING property (e.g. kev_date_added "2021-11-03") -> only values that LOOK like an ISO date are
      compared (first 10 characters, fixed-width so text order == calendar order). Missing (null) and
      malformed values are left out, never guessed at, and never raise an error in the database.
    """
    datep = gm.q("date")
    if gm.is_temporal("date"):
        cmp_ = f"n.{datep} >= datetime($since)"
    else:
        cmp_ = (f"n.{datep} =~ '[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}.*' "
                f"AND substring(n.{datep}, 0, 10) >= $since")
    where = [cmp_] + (["any(l IN labels(n) WHERE l IN $types)"] if typed else [])
    return ("MATCH (n:Entity)\nWHERE " + " AND ".join(where) + "\n"
            f"RETURN labels(n) AS labels, properties(n) AS props\nORDER BY n.{datep} DESC\nLIMIT $limit")
