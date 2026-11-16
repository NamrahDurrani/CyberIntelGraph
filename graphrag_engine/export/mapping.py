"""Map the REAL GraphRAG output (plain dict rows) onto our canonical model. No pandas, no Neo4j - pure and testable.

What the real output gives us (see docs/data_dictionary/GRAPHRAG_OUTPUT_SCHEMA.md):
  entities: title, type (UPPER_SNAKE), description, text_unit_ids, frequency, degree - NO canonical ids
  relationships: source/target TITLES, description, weight, text_unit_ids - NO relationship type
So this module (1) filters noise, (2) maps types, (3) links to canonical ids or creates candidate ids,
(4) validates every relationship endpoint, (5) keeps TextUnit references mapped back to our chunk ids.
Everything here is evidence type `llm_extracted_candidate`.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter

from canonical.ids import CVE_RE, TECH_RE, slug
from canonical.models import CANONICAL_ID_RE, ENTITY_CLASSES, Relationship
from graphrag_engine.indexing.resolve import GROUP, build_canonical_index

EVIDENCE_TYPE = "llm_extracted_candidate"


def load_rules(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        rules = json.load(fh)
    for key in ("type_map", "generic_titles", "advisory_author_orgs", "merge_aliases", "extension_types"):
        rules.setdefault(key, {} if key in ("type_map", "merge_aliases") else [])
    return rules


def norm_title(title) -> str:
    return re.sub(r"\s+", " ", str(title or "")).strip().upper()


def _compatible(a: str, b: str) -> bool:
    return a == b or (a in GROUP and b in GROUP)


def _clean_list(v) -> list:
    if v is None:
        return []
    if hasattr(v, "tolist"):
        v = v.tolist()
    return [x for x in v if x is not None]


def candidate_slug(title: str) -> str:
    """Readable id part for candidates: 'OPERATIONAL TECHNOLOGIES' -> 'operational-technologies'.
    (Matching against canonical names still uses canonical.ids.slug, which drops every separator.)"""
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "unnamed"


def resolve_id(title: str, ctype: str, cindex: dict) -> tuple[str, bool, bool | None, list]:
    """-> (node_id, linked_to_canonical, in_canonical, ambiguous_matches)"""
    have = cindex["ids"]
    cve = CVE_RE.search(title)
    if ctype == "Vulnerability" and cve:
        nid = f"Vulnerability:{cve.group(0).upper()}"
        return nid, True, (nid in have) if have else None, []
    tech = TECH_RE.search(title)
    if ctype == "AttackTechnique" and tech:
        nid = f"AttackTechnique:{tech.group(0).upper()}"
        return nid, True, (nid in have) if have else None, []
    matches = sorted({cid for cid, ct in cindex["by_slug"].get(slug(title), []) if _compatible(ctype, ct)})
    if len(matches) == 1:
        return matches[0], True, True, []
    return f"{ctype}:cand-{candidate_slug(title)}", False, None, matches


def map_entities(entities: list[dict], rules: dict, cindex: dict):
    """-> (nodes {node_id: record}, title_to_node {UPPER TITLE: node_id}, graphrag_id_to_node, skipped Counter)"""
    generic = {norm_title(t) for t in rules["generic_titles"]}
    authors = {norm_title(t) for t in rules["advisory_author_orgs"]}
    aliases = {norm_title(k): norm_title(v) for k, v in rules["merge_aliases"].items()}
    type_map = {k.upper(): v for k, v in rules["type_map"].items()}
    nodes, title_to_node, gid_to_node, skipped = {}, {}, {}, Counter()
    for e in sorted(entities, key=lambda r: (norm_title(r.get("title")), str(r.get("id")))):
        raw_title = norm_title(e.get("title"))
        if not raw_title:
            skipped["empty_title"] += 1
            continue
        ctype = type_map.get(str(e.get("type") or "").strip().upper().replace(" ", "_"))
        if not ctype:
            skipped["unmapped_type"] += 1
            continue
        if raw_title in generic:
            skipped["generic_title"] += 1
            continue
        if ctype == "Organization" and raw_title in authors:
            skipped["advisory_author"] += 1
            continue
        title = aliases.get(raw_title, raw_title)
        nid, linked, in_canon, ambiguous = resolve_id(title, ctype, cindex)
        n = nodes.setdefault(nid, {
            "entity_id": nid, "name": title, "entity_type": ctype, "canonical_type": ctype in ENTITY_CLASSES,
            "origin": "graphrag", "linked": linked, "in_canonical": in_canon, "ambiguous_with": ambiguous,
            "titles": [], "descriptions": [], "graphrag_ids": [], "text_unit_ids": [], "frequency": 0, "degree": 0,
            "evidence_type": EVIDENCE_TYPE})
        if raw_title not in n["titles"]:
            n["titles"].append(raw_title)
        if e.get("description") and e["description"] not in n["descriptions"]:
            n["descriptions"].append(str(e["description"]))
        n["graphrag_ids"].append(str(e.get("id")))
        n["text_unit_ids"] = sorted(set(n["text_unit_ids"]) | set(map(str, _clean_list(e.get("text_unit_ids")))))
        n["frequency"] += int(e.get("frequency") or 0)
        n["degree"] = max(n["degree"], int(e.get("degree") or 0))
        title_to_node[raw_title] = nid
        title_to_node[title] = nid
        gid_to_node[str(e.get("id"))] = nid
    for n in nodes.values():
        n["description"] = max(n["descriptions"], key=len) if n["descriptions"] else ""
        n["descriptions"] = n["descriptions"][:3]
        n["titles"].sort()
    return nodes, title_to_node, gid_to_node, skipped


def map_relationships(rels: list[dict], title_to_node: dict, nodes: dict):
    """GraphRAG relationships have no type -> RELATED_TO. Endpoints are validated against the kept nodes."""
    out, skipped = {}, Counter()
    for r in sorted(rels, key=lambda r: (norm_title(r.get("source")), norm_title(r.get("target")), str(r.get("id")))):
        s, t = title_to_node.get(norm_title(r.get("source"))), title_to_node.get(norm_title(r.get("target")))
        if not s or not t:
            skipped["endpoint_filtered_or_unknown"] += 1
            continue
        if s == t:
            skipped["self_loop_after_merge"] += 1
            continue
        rid = f"RELATED_TO|{s}|{t}"
        rec = out.setdefault(rid, {"rel_id": rid, "rel_type": "RELATED_TO", "source_id": s, "target_id": t,
                                   "evidence_type": EVIDENCE_TYPE, "description": "", "weight": 0.0,
                                   "text_unit_ids": [], "origin": "graphrag"})
        rec["weight"] += float(r.get("weight") or 0.0)
        if len(str(r.get("description") or "")) > len(rec["description"]):
            rec["description"] = str(r["description"])
        rec["text_unit_ids"] = sorted(set(rec["text_unit_ids"]) | set(map(str, _clean_list(r.get("text_unit_ids")))))
    return out, skipped


def map_text_units(text_units: list[dict], documents: list[dict], manifest: dict, input_dir: str,
                   chunk_report: dict[str, str], planned_ids: set[str]):
    """Locate each text unit inside its advisory file -> our chunk ids, document and report."""
    title_to_key = {v["file"]: k for k, v in manifest.items()}
    doc_title = {str(d.get("id")): os.path.basename(str(d.get("title") or "")) for d in documents}
    cache, out, stats = {}, [], Counter()
    for t in sorted(text_units, key=lambda r: str(r.get("id"))):
        fname = doc_title.get(str(t.get("document_id")), "")
        key = title_to_key.get(fname)
        chunk_ids = []
        if key:
            if key not in cache:
                with open(os.path.join(input_dir, fname), encoding="utf-8") as fh:
                    cache[key] = fh.read()
            text = str(t.get("text") or "").strip()
            pos = cache[key].find(text) if text else -1
            if pos >= 0:
                end = pos + len(text)
                chunk_ids = [c["chunk_id"] for c in manifest[key]["chunks"] if c["start"] < end and c["end"] > pos]
        stats["mapped" if chunk_ids else "unmapped"] += 1
        report_id = next((chunk_report[c] for c in chunk_ids if chunk_report.get(c) in planned_ids), None)
        out.append({"text_unit_id": str(t["id"]), "text": str(t.get("text") or ""), "n_tokens": int(t.get("n_tokens") or 0),
                    "doc_id": key, "chunk_ids": chunk_ids, "report_id": report_id, "origin": "graphrag"})
    return out, stats


def map_communities(communities: list[dict], reports: list[dict], gid_to_node: dict):
    by_comm = {int(r["community"]): r for r in reports}
    out, members = [], []
    for c in sorted(communities, key=lambda r: int(r["community"])):
        rep = by_comm.get(int(c["community"]), {})
        key = f"gr-c{int(c['community'])}"
        findings = _clean_list(rep.get("findings"))
        out.append({"community_key": key, "community": int(c["community"]), "level": int(c["level"]),
                    "parent": int(c["parent"]), "size": int(c.get("size") or 0),
                    "title": str(rep.get("title") or c.get("title") or ""), "summary": str(rep.get("summary") or ""),
                    "rank": float(rep["rank"]) if rep.get("rank") is not None else None,
                    "findings_json": json.dumps(findings[:10], ensure_ascii=False, default=str, sort_keys=True),
                    "origin": "graphrag"})
        for gid in map(str, _clean_list(c.get("entity_ids"))):
            if gid in gid_to_node:
                members.append([gid_to_node[gid], key])
    return out, members


def build_export(frames: dict[str, list[dict]], rules: dict, canonical_entities: list[dict], manifest: dict,
                 input_dir: str, chunk_report: dict[str, str] | None = None) -> dict:
    cindex = build_canonical_index(canonical_entities)
    nodes, t2n, g2n, e_skip = map_entities(frames["entities"], rules, cindex)
    rels, r_skip = map_relationships(frames["relationships"], t2n, nodes)
    invalid = 0
    for r in list(rels.values()):
        try:
            Relationship(rel_id=r["rel_id"], rel_type=r["rel_type"], source_id=r["source_id"], target_id=r["target_id"],
                         evidence_type=EVIDENCE_TYPE, properties={"weight": r["weight"]})
            assert CANONICAL_ID_RE.match(r["source_id"]) and CANONICAL_ID_RE.match(r["target_id"])
        except Exception:                                                    # noqa: BLE001
            invalid += 1
            del rels[r["rel_id"]]
    planned = set(cindex["ids"]) | set(nodes)
    tus, tu_stats = map_text_units(frames.get("text_units", []), frames.get("documents", []), manifest, input_dir,
                                   chunk_report or {}, planned)
    comms, members = map_communities(frames.get("communities", []), frames.get("community_reports", []), g2n)
    tu_ids = {t["text_unit_id"] for t in tus}
    chunk_of = {t["text_unit_id"]: t["chunk_ids"] for t in tus}
    entity_tu, dangling = [], 0
    for n in nodes.values():
        n["chunk_ids"] = sorted({c for tu in n["text_unit_ids"] for c in chunk_of.get(tu, [])})
        for tu in n["text_unit_ids"]:
            if tu in tu_ids:
                entity_tu.append([n["entity_id"], tu])
            else:
                dangling += 1
    for r in rels.values():
        r["chunk_ids"] = sorted({c for tu in r["text_unit_ids"] for c in chunk_of.get(tu, [])})
    tu_report = [[t["text_unit_id"], t["report_id"]] for t in tus if t["report_id"]]
    linked = sum(1 for n in nodes.values() if n["linked"])
    report = {
        "entities_in": len(frames["entities"]), "nodes_out": len(nodes), "nodes_linked_to_canonical_id": linked,
        "nodes_in_canonical_graph": sum(1 for n in nodes.values() if n["in_canonical"]),
        "nodes_candidate_only": len(nodes) - linked, "nodes_ambiguous": sum(1 for n in nodes.values() if n["ambiguous_with"]),
        "nodes_noncanonical_type": sum(1 for n in nodes.values() if not n["canonical_type"]),
        "entities_skipped": dict(e_skip), "relationships_in": len(frames["relationships"]), "relationships_out": len(rels),
        "relationships_skipped": dict(r_skip), "relationships_invalid": invalid,
        "text_units": dict(tu_stats), "text_units_linked_to_report": len(tu_report),
        "entity_text_unit_links": len(entity_tu), "entity_text_unit_dangling": dangling,
        "communities": len(comms), "entity_community_links": len(members)}
    return {"metadata": {"schema_version": 1, "evidence_type": EVIDENCE_TYPE},
            "nodes": sorted(nodes.values(), key=lambda n: n["entity_id"]),
            "relationships": sorted(rels.values(), key=lambda r: r["rel_id"]),
            "text_units": tus, "communities": comms,
            "links": {"entity_text_unit": sorted(entity_tu), "text_unit_report": sorted(tu_report),
                      "entity_community": sorted(members)},
            "report": report}
