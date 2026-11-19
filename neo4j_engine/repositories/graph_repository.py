"""Retrieval functions over the Neo4j graph (Milestone 11).

Every function is read-only, parameterised, bounded by a LIMIT, and returns plain
dicts so the later LangGraph agent (Milestone 13) and FastAPI layer (Milestone 15)
can use the results directly. Candidates (GraphRAG, LLM-extracted) are never mixed
into documented results without a label.
"""
from __future__ import annotations

from typing import Any

from neo4j_engine.queries import cypher as C
from neo4j_engine.repositories.evidence import best_class, claim_class, evidence_status, slim
from neo4j_engine.schema.mapping import GraphMap

MAX_LIMIT = 1000


class EntityNotFound(LookupError):
    pass


class AmbiguousEntity(LookupError):
    def __init__(self, ref: str, matches: list[dict[str, Any]]):
        self.ref, self.matches = ref, matches
        super().__init__(f"{ref!r} matches {len(matches)} entities; use a full entity id")


class CapabilityUnavailable(RuntimeError):
    """The graph does not hold the data this query needs (reported, never faked)."""


def _limit(n: int, default: int = 25) -> int:
    try:
        n = int(n)
    except (TypeError, ValueError):
        n = default
    return max(1, min(n, MAX_LIMIT))


class GraphRepository:
    def __init__(self, client, graph_map: GraphMap | None = None):
        self.client = client
        self.gm = graph_map or GraphMap.default()

    # ------------------------------------------------------------------ helpers
    def _entity(self, labels: list[str], props: dict[str, Any], **extra) -> dict[str, Any]:
        gm = self.gm
        out = {
            "id": props.get(gm.n("id")),
            "name": props.get(gm.n("name")) if gm.n("name") else None,
            "types": [l for l in labels if l not in ("Entity", "Candidate")],
            "is_candidate": "Candidate" in labels or (bool(gm.n("origin")) and str(props.get(gm.n("origin"))).lower() == "graphrag"),
            "properties": slim(props),
        }
        out.update(extra)
        return out

    # ------------------------------------------------------------------ lookup
    def find_entities(self, text: str, *, types: list[str] | None = None,
                      include_candidates: bool = True, limit: int = 10) -> list[dict[str, Any]]:
        q = (text or "").strip().lower()
        if not q:
            raise ValueError("search text is empty")
        if len(q) > 200:
            raise ValueError("search text is too long (max 200 characters)")
        types = self.gm.check_labels(types)
        cy = C.find_entities(self.gm, typed=bool(types), include_candidates=include_candidates)
        params: dict[str, Any] = {"q": q, "qsuf": ":" + q, "limit": _limit(limit, 10)}
        if types:
            params["types"] = types
        rows = self.client.run_read(cy, params)
        return [self._entity(r["labels"], r["props"], match_rank=r["rank"]) for r in rows]

    def get_entity(self, entity_id: str) -> dict[str, Any]:
        rows = self.client.run_read(C.get_entity(self.gm), {"id": entity_id})
        if not rows:
            raise EntityNotFound(entity_id)
        ent = self._entity(rows[0]["labels"], rows[0]["props"])
        deg = self.client.run_read(C.degree_by_type(self.gm), {"id": entity_id})
        ent["degree"] = {d["rel_type"]: d["n"] for d in deg}
        return ent

    def resolve_entity(self, ref: str, *, types: list[str] | None = None) -> dict[str, Any]:
        """Turn a name, bare id (T1059.001) or full id into ONE entity, or raise.
        Never guesses between several equally good matches."""
        found = self.find_entities(ref, types=types, include_candidates=False, limit=10)
        if not found:
            found = self.find_entities(ref, types=types, include_candidates=True, limit=10)
        if not found:
            raise EntityNotFound(ref)
        best = found[0]["match_rank"]
        top = [f for f in found if f["match_rank"] == best]
        if best <= 2 and len(top) == 1:
            return top[0]
        if best <= 2 and len(top) > 1:
            raise AmbiguousEntity(ref, top)
        if len(found) == 1:
            return found[0]
        raise AmbiguousEntity(ref, found)

    # --------------------------------------------------------------- one hop
    def neighbors(self, entity_id: str, *, rel_types: list[str] | None = None,
                  include_candidates: bool = False, limit: int = 50) -> dict[str, Any]:
        rel_types = self.gm.check_rel_types(rel_types)
        cy = C.neighbors(self.gm, typed_rels=rel_types, include_candidates=include_candidates)
        lim = _limit(limit, 50)
        params: dict[str, Any] = {"id": entity_id, "limit": lim}
        if rel_types:
            params["rel_types"] = rel_types
        rows = self.client.run_read(cy, params)
        items = [{
            "rel_type": r["rel_type"],
            "direction": "out" if r["outgoing"] else "in",
            "evidence_status": evidence_status(r["rprops"] or {}, self.gm),
            "relationship": slim(r["rprops"]),
            "other": self._entity(r["labels"], r["props"]),
        } for r in rows]
        return {"entity_id": entity_id, "count": len(items), "truncated": len(items) >= lim, "neighbors": items}

    # ------------------------------------------------------- actor -> techniques
    def techniques_for_actor(self, actor: str, *, include_inferred: bool = True,
                             include_candidates: bool = True, with_reports: bool = True,
                             reports_per_technique: int = 3, limit: int = 500) -> dict[str, Any]:
        """Techniques linked to a threat actor, each marked documented / inferred / candidate."""
        ent = self.resolve_entity(actor, types=["ThreatActor"])
        ids = [ent["id"]]
        notes: list[str] = []
        if self.gm.n("name") and ent.get("name"):
            same = self.client.run_read(C.same_name_entities(self.gm), {"name": str(ent["name"]).lower(), "id": ent["id"]})
            extra = [s["id"] for s in same if "ThreatActor" in s["labels"]]
            if extra:
                ids += extra
                notes.append(f"also searched same-name actor node(s): {extra}")
        lim = _limit(limit, 500)
        params = {"ids": ids, "limit": lim}

        collected: list[tuple[str, dict[str, Any]]] = []   # (derivation, row)
        for r in self.client.run_read(C.actor_techniques_direct(self.gm), params):
            collected.append(("direct", r))
        if include_inferred:
            for r in self.client.run_read(C.actor_techniques_via_campaign(self.gm), params):
                collected.append(("via_campaign", r))
            for r in self.client.run_read(C.actor_techniques_via_software(self.gm), params):
                collected.append(("via_software", r))
        if include_candidates:
            for r in self.client.run_read(C.actor_techniques_candidate(self.gm), params):
                collected.append(("candidate", r))

        gm = self.gm
        techniques: dict[str, dict[str, Any]] = {}
        for derivation, r in collected:
            tid = r["tprops"].get(gm.n("id"))
            statuses = [evidence_status(r["rprops"] or {}, gm)]
            if r.get("rprops_first") is not None:
                statuses.append(evidence_status(r["rprops_first"], gm))
            path = {
                "derivation": derivation,
                "claim_class": claim_class(derivation, statuses),
                "evidence_status": statuses[-1] if len(statuses) == 1 else statuses,
                "relationship": slim(r["rprops"]),
            }
            if r.get("via"):
                path["via"] = {"id": r["via"].get(gm.n("id")), "name": r["via"].get(gm.n("name")) if gm.n("name") else None}
            tech = techniques.setdefault(tid, {
                "id": tid, "name": r["tprops"].get(gm.n("name")) if gm.n("name") else None,
                "paths": [],
            })
            tech["paths"].append(path)

        for tech in techniques.values():
            classes = [p["claim_class"] for p in tech["paths"]]
            tech["claim_class"] = best_class(classes)
            tech["also_reported_as_candidate"] = tech["claim_class"] != "candidate" and "candidate" in classes

        if with_reports and techniques:
            self._attach_reports(techniques, reports_per_technique)

        ordered = sorted(techniques.values(), key=lambda t: ({"documented": 0, "inferred": 1, "candidate": 2}[t["claim_class"]], str(t["id"])))
        counts = {c: sum(1 for t in ordered if t["claim_class"] == c) for c in ("documented", "inferred", "candidate")}
        counts["total"] = len(ordered)
        if any(len([1 for d, _ in collected if d == k]) >= lim for k in ("direct", "via_campaign", "via_software", "candidate")):
            notes.append(f"a query reached the limit of {lim} rows; raise --limit to see everything")
        return {"actor": ent, "techniques": ordered, "counts": counts, "notes": notes}

    def _attach_reports(self, techniques: dict[str, dict[str, Any]], per: int) -> None:
        gm = self.gm
        rows = self.client.run_read(C.reports_mentioning(gm), {"ids": list(techniques), "limit": MAX_LIMIT * 5})
        by_t: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            by_t.setdefault(r["tid"], []).append(r["rprops"])
        datek = gm.n("date")
        for tid, reps in by_t.items():
            if datek:
                reps.sort(key=lambda p: str(p.get(datek) or ""), reverse=True)
            techniques[tid]["reports"] = [
                {"id": p.get(gm.n("id")), "name": p.get(gm.n("name")) if gm.n("name") else None,
                 "source_url": p.get(gm.n("source_url")) if gm.n("source_url") else None,
                 "date": p.get(datek) if datek else None}
                for p in reps[:per]
            ]

    # ------------------------------------------------------------ multi hop
    def find_path(self, a: str, b: str, *, max_hops: int = 4, rel_types: list[str] | None = None,
                  include_candidates: bool = False, all_paths: bool = False, limit: int = 5) -> dict[str, Any]:
        ea, eb = self.resolve_entity(a), self.resolve_entity(b)
        rel_types = self.gm.check_rel_types(rel_types)
        cy = C.shortest_path(self.gm, rel_types=rel_types, max_hops=max_hops,
                             include_candidates=include_candidates, all_paths=all_paths)
        rows = self.client.run_read(cy, {"a": ea["id"], "b": eb["id"], "limit": _limit(limit, 5)})
        return {"from": ea, "to": eb, "max_hops": max(1, min(int(max_hops), 5)),
                "paths": [{"hops": r["hops"], "nodes": r["nodes"], "relationships": r["rels"]} for r in rows],
                "found": bool(rows)}

    # ----------------------------------------------------- evidence / provenance
    def provenance(self, entity_id: str) -> dict[str, Any]:
        rows = self.client.run_read(C.provenance(self.gm), {"id": entity_id})
        if not rows:
            raise EntityNotFound(entity_id)
        r = rows[0]
        gm = self.gm
        ent = self._entity(r["labels"], r["props"])
        tu_text, tu_id, tu_chunks = gm.textunit.get("text"), gm.textunit.get("id"), gm.textunit.get("chunk_ids")
        co_title, co_id = gm.community.get("title"), gm.community.get("id")
        return {
            "entity": ent,
            "evidence_status": evidence_status(r["props"], gm, kind="node"),
            "text_units": [{"id": t.get(tu_id) if tu_id else None,
                            "chunk_ids": t.get(tu_chunks) if tu_chunks else None,
                            "text": (str(t.get(tu_text))[:600] if tu_text and t.get(tu_text) else None)} for t in r["text_units"]],
            "communities": [{"id": c.get(co_id) if co_id else None, "title": c.get(co_title) if co_title else None} for c in r["communities"]],
            "reports": [{"id": p.get(gm.n("id")), "name": p.get(gm.n("name")) if gm.n("name") else None,
                         "source_url": p.get(gm.n("source_url")) if gm.n("source_url") else None} for p in r["reports"]],
        }

    def candidate_evidence(self, entity_id: str, *, limit: int = 25) -> dict[str, Any]:
        """GraphRAG candidate relationships around an entity WITH their source text units."""
        rows = self.client.run_read(C.relationship_evidence(self.gm), {"id": entity_id, "limit": _limit(limit, 25)})
        gm = self.gm
        tu_text, tu_id = gm.textunit.get("text"), gm.textunit.get("id")
        items = [{
            "relationship": slim(r["rprops"]),
            "evidence_status": evidence_status(r["rprops"] or {}, gm),
            "other": self._entity(r["labels"], r["props"]),
            "text_units": [{"id": t.get(tu_id) if tu_id else None,
                            "text": str(t.get(tu_text))[:600] if tu_text and t.get(tu_text) else None} for t in r["text_units"]],
        } for r in rows]
        return {"entity_id": entity_id, "count": len(items), "candidates": items}

    # -------------------------------------------------------------- temporal
    def changed_since(self, since: str, *, types: list[str] | None = None, limit: int = 25) -> dict[str, Any]:
        if not self.gm.n("date"):
            raise CapabilityUnavailable("no date property (modified_at / published_at ...) exists on entities in this graph")
        types = self.gm.check_labels(types)
        params: dict[str, Any] = {"since": since, "limit": _limit(limit, 25)}
        if types:
            params["types"] = types
        rows = self.client.run_read(C.changed_since(self.gm, typed=bool(types)), params)
        return {"since": since, "date_property": self.gm.n("date"),
                "entities": [self._entity(r["labels"], r["props"]) for r in rows]}
