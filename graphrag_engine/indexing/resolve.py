"""Merge window-level candidates into one entity/relationship set and link it to the canonical graph.

Node ids
  * CVE ids and ATT&CK technique ids already have stable canonical ids -> `Vulnerability:CVE-2024-3400`,
    `AttackTechnique:T1059.001` (the same ids Milestone 5 uses).
  * A name found in the canonical graph (unique match) -> that entity's canonical_id.
  * Anything else stays a CANDIDATE: `<Type>:cand-<slug>`, never presented as canonical.
Every record carries evidence of type `llm_extracted_candidate`.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from canonical.ids import rel_id, slug

GROUP = {"ThreatActor", "Malware", "Tool", "Campaign"}      # ATT&CK blurs these; match across them
PRIORITY = ("Malware", "ThreatActor", "Tool", "Campaign", "Vulnerability", "AttackTechnique",
            "Software", "Organization", "Sector", "Mitigation")


def build_canonical_index(canonical_entities: list[dict]) -> dict:
    """slug(name or alias) -> [(canonical_id, entity_type)], plus a set of all canonical ids."""
    by_slug: dict[str, list[tuple[str, str]]] = defaultdict(list)
    ids = set()
    for e in canonical_entities:
        cid, etype = e["canonical_id"], e["entity_type"]
        ids.add(cid)
        for n in [e.get("name", "")] + list(e.get("aliases") or []):
            if n and (cid, etype) not in by_slug[slug(n)]:
                by_slug[slug(n)].append((cid, etype))
    return {"by_slug": by_slug, "ids": ids}


def _compatible(a: str, b: str) -> bool:
    return a == b or (a in GROUP and b in GROUP)


def _evidence(chunk_id, window_result, chunk_meta):
    meta = chunk_meta.get(chunk_id, {})
    return {"source": "advisories", "evidence_type": "llm_extracted_candidate", "record_ref": chunk_id,
            "raw_file_reference": window_result.get("cache_file"), "source_url": meta.get("source_url"),
            "retrieved_at": window_result.get("retrieved_at")}


def merge(window_results: list[dict], chunk_meta: dict[str, dict], canonical: dict | None = None):
    """-> (entities, relationships) as plain dicts, deterministically ordered."""
    groups: dict[tuple, dict] = {}
    slug_to_group: dict[tuple[str, str], tuple] = {}         # (window_id, slug(name)) -> group key
    for wr in window_results:
        if "error" in wr:
            continue
        for e in wr["entities"]:
            if e.get("cve_id"):
                key = ("id", e["cve_id"])
            elif e.get("attack_id"):
                key = ("id", e["attack_id"])
            else:
                key = ("slug", slug(e["name"]))
            g = groups.setdefault(key, {"names": Counter(), "types": Counter(), "desc": "", "windows": set(),
                                        "docs": set(), "cve_id": None, "attack_id": None, "mentions": 0})
            g["names"][e["name"]] += 1
            g["types"][e["type"]] += 1
            g["mentions"] += 1
            g["windows"].add(wr["window_id"])
            g["docs"].add(wr["doc_id"])
            g["cve_id"] = g["cve_id"] or e.get("cve_id")
            g["attack_id"] = g["attack_id"] or e.get("attack_id")
            if len(e.get("description", "")) > len(g["desc"]):
                g["desc"] = e["description"]
            slug_to_group[(wr["window_id"], slug(e["name"]))] = key

    cindex = canonical or {"by_slug": {}, "ids": set()}
    entities, node_of = {}, {}
    for key, g in sorted(groups.items(), key=lambda kv: kv[0]):
        counts = g["types"]
        etype = sorted(counts, key=lambda t: (-counts[t], PRIORITY.index(t) if t in PRIORITY else 99))[0]
        name = sorted(g["names"], key=lambda n: (-g["names"][n], n))[0]
        rec = {"name": name, "type": etype, "aliases": sorted(set(g["names"]) - {name}),
               "description": g["desc"], "mentions": g["mentions"], "doc_ids": sorted(g["docs"]),
               "windows": sorted(g["windows"]), "canonical_id": None, "linked": False,
               "in_canonical": None, "ambiguous_with": [], "type_conflict": sorted(set(counts) - {etype})}
        if etype == "Vulnerability" and g["cve_id"]:
            rec.update(node_id=f"Vulnerability:{g['cve_id']}", canonical_id=f"Vulnerability:{g['cve_id']}",
                       linked=True, cve_id=g["cve_id"], in_canonical=(f"Vulnerability:{g['cve_id']}" in cindex["ids"]) if cindex["ids"] else None)
        elif etype == "AttackTechnique" and g["attack_id"]:
            cid = f"AttackTechnique:{g['attack_id']}"
            rec.update(node_id=cid, canonical_id=cid, linked=True, attack_id=g["attack_id"],
                       in_canonical=(cid in cindex["ids"]) if cindex["ids"] else None)
        else:
            matches = []
            for n in [name] + rec["aliases"]:
                for cid, ctype in cindex["by_slug"].get(slug(n), []):
                    if _compatible(etype, ctype) and cid not in [m for m in matches]:
                        matches.append(cid)
            if len(matches) == 1:
                rec.update(node_id=matches[0], canonical_id=matches[0], linked=True, in_canonical=True)
            else:
                rec.update(node_id=f"{etype}:cand-{slug(name) or 'unnamed'}", ambiguous_with=sorted(matches))
        entities[key] = rec
        node_of[key] = rec["node_id"]

    rels: dict[str, dict] = {}
    for wr in window_results:
        if "error" in wr:
            continue
        for r in wr["relationships"]:
            sk = slug_to_group.get((wr["window_id"], slug(r["source"])))
            tk = slug_to_group.get((wr["window_id"], slug(r["target"])))
            if not sk or not tk or node_of[sk] == node_of[tk]:
                continue
            rid = rel_id(r["type"], node_of[sk], node_of[tk])
            rec = rels.setdefault(rid, {"rel_id": rid, "rel_type": r["type"], "source_id": node_of[sk],
                                        "target_id": node_of[tk], "evidence_type": "llm_extracted_candidate",
                                        "evidence": [],
                                        "properties": {"description": "", "weight": 0, "quotes": [],
                                                       "doc_ids": [], "candidate": True}})
            rec["properties"]["weight"] += 1
            if len(r["description"]) > len(rec["properties"]["description"]):
                rec["properties"]["description"] = r["description"]
            if r["quote"] not in rec["properties"]["quotes"] and len(rec["properties"]["quotes"]) < 4:
                rec["properties"]["quotes"].append(r["quote"])
            if wr["doc_id"] not in rec["properties"]["doc_ids"]:
                rec["properties"]["doc_ids"].append(wr["doc_id"])
            if r.get("chunk"):
                ev = _evidence(r["chunk"], wr, chunk_meta)
                if ev["record_ref"] not in {x["record_ref"] for x in rec["evidence"]}:
                    rec["evidence"].append(ev)

    # entity evidence: the chunks (of the windows where it was extracted) that literally mention it
    for key, rec in entities.items():
        names = [rec["name"]] + rec["aliases"] + [rec.get("cve_id") or "", rec.get("attack_id") or ""]
        needles = [n.lower() for n in names if n]
        seen = []
        for wr in window_results:
            if "error" in wr or wr["window_id"] not in rec["windows"]:
                continue
            for cid in wr.get("chunk_ids", []):
                if cid not in seen and any(n in chunk_meta.get(cid, {}).get("_text_l", "") for n in needles):
                    seen.append(cid)
                    rec.setdefault("evidence", []).append(_evidence(cid, wr, chunk_meta))
                    if len(rec["evidence"]) >= 5:
                        break
            if len(rec.get("evidence", [])) >= 5:
                break
        rec.setdefault("evidence", [])
    ent_list = sorted(entities.values(), key=lambda e: e["node_id"])
    for e in ent_list:
        e.pop("windows", None)
    return ent_list, sorted(rels.values(), key=lambda r: r["rel_id"])
