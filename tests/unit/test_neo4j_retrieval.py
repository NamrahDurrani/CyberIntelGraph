"""Milestone 11 unit tests. No Neo4j server needed: a fake client returns canned rows
and records every query so we can assert on the Cypher text and parameters."""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from neo4j_engine.connection.client import (Neo4jConfigError, Neo4jSettings, ReadOnlyViolation,  # noqa: E402
                                            assert_read_only, clean_value, driver_kwargs)
from neo4j_engine.queries import cypher as C  # noqa: E402
from neo4j_engine.repositories.evidence import best_class, claim_class, evidence_status, slim  # noqa: E402
from neo4j_engine.repositories.graph_repository import (AmbiguousEntity, CapabilityUnavailable,  # noqa: E402
                                                        EntityNotFound, GraphRepository)
from neo4j_engine.schema.indexes import plan_indexes  # noqa: E402
from neo4j_engine.schema.mapping import GraphMap, ident  # noqa: E402

REPORT = {
    "labels": ["Entity", "ThreatActor", "AttackTechnique", "Campaign", "Malware", "Tool", "Candidate", "TextUnit", "Community", "IntelligenceReport"],
    "rel_types": ["USES", "CONDUCTS", "RELATED_TO", "MENTIONS", "EXTRACTED_FROM"],
    "properties": {
        "Entity": {"entity_id": ["String"], "name": ["String"], "aliases": ["StringArray"], "origin": ["String"],
                   "modified_at": ["String"], "source_url": ["String"]},
        "TextUnit": {"text_unit_id": ["String"], "text": ["String"], "chunk_ids": ["StringArray"]},
        "Community": {"community_id": ["String"], "title": ["String"]},
    },
    "rel_properties": {"USES": {"rel_id": ["String"], "evidence_type": ["String"]},
                       "RELATED_TO": {"rel_id": ["String"], "origin": ["String"], "evidence_type": ["String"]}},
}


class FakeClient:
    """Returns rows for the first registered key found in the query text."""
    def __init__(self, routes=None):
        self.routes = routes or []
        self.calls = []

    def run_read(self, cypher, params=None):
        self.calls.append((cypher, params or {}))
        for key, rows in self.routes:
            if key in cypher:
                return rows(params) if callable(rows) else rows
        return []


def tech(i, name="T"):
    return {"entity_id": i, "name": name or i}


class MappingTests(unittest.TestCase):
    def test_resolves_real_names_and_leaves_missing_none(self):
        gm = GraphMap.from_report(REPORT)
        self.assertEqual(gm.n("id"), "entity_id")
        self.assertEqual(gm.n("date"), "modified_at")
        self.assertIsNone(gm.n("description"))
        self.assertTrue(gm.is_list("aliases"))
        self.assertIn("node.description", gm.unresolved())

    def test_alternative_property_names(self):
        rep = {**REPORT, "properties": {"Entity": {"id": ["String"], "title": ["String"]}}}
        gm = GraphMap.from_report(rep)
        self.assertEqual((gm.n("id"), gm.n("name")), ("id", "title"))

    def test_required_missing_raises(self):
        gm = GraphMap.from_report({**REPORT, "properties": {"Entity": {"foo": ["String"]}}})
        with self.assertRaises(LookupError):
            gm.q("id")

    def test_ident_rejects_injection(self):
        for bad in ("a`b", "x y", "n) DETACH DELETE (m", "", "1abc"):
            with self.assertRaises(ValueError):
                ident(bad)
        self.assertEqual(ident("entity_id"), "`entity_id`")

    def test_label_and_rel_whitelists(self):
        gm = GraphMap.from_report(REPORT)
        self.assertEqual(gm.check_labels(["ThreatActor"]), ["ThreatActor"])
        with self.assertRaises(ValueError):
            gm.check_labels(["ThreatActor) DETACH DELETE (n"])
        with self.assertRaises(ValueError):
            gm.check_rel_types(["NOPE"])

    def test_candidate_predicate(self):
        self.assertEqual(GraphMap.from_report(REPORT).candidate_pred("m"), "m:Candidate")
        no_label = {**REPORT, "labels": ["Entity"]}
        self.assertIn("graphrag", GraphMap.from_report(no_label).candidate_pred("m"))


class ReadOnlyTests(unittest.TestCase):
    def test_rejects_writes(self):
        for q in ("CREATE (n:X)", "MATCH (n) SET n.a=1", "MATCH (n) DETACH DELETE n", "MERGE (n:X)",
                  "LOAD CSV FROM 'x' AS r RETURN r", "CALL apoc.create.node(['X'],{})", "match (n) remove n.a",
                  "DROP INDEX x", "CALL dbms.security.createUser('a','b')"):
            with self.assertRaises(ReadOnlyViolation, msg=q):
                assert_read_only(q)

    def test_keywords_inside_strings_and_identifiers_are_fine(self):
        assert_read_only("MATCH (n) WHERE n.`set` = 'create me' AND n.created_at > $x RETURN n")

    def test_every_generated_query_is_read_only(self):
        gm = GraphMap.from_report(REPORT)
        qs = [C.find_entities(gm, typed=True, include_candidates=False), C.find_entities(gm, typed=False, include_candidates=True),
              C.get_entity(gm), C.degree_by_type(gm), C.neighbors(gm, typed_rels=["USES"], include_candidates=False),
              C.actor_techniques_direct(gm), C.actor_techniques_via_campaign(gm), C.actor_techniques_via_software(gm),
              C.actor_techniques_candidate(gm), C.same_name_entities(gm), C.reports_mentioning(gm), C.provenance(gm),
              C.relationship_evidence(gm), C.shortest_path(gm, rel_types=["USES"], max_hops=4, include_candidates=False, all_paths=False),
              C.shortest_path(gm, rel_types=None, max_hops=99, include_candidates=True, all_paths=True), C.changed_since(gm, typed=True)]
        for q in qs:
            assert_read_only(q)

    def test_index_writer_only_accepts_index_statements(self):
        from neo4j_engine.connection.client import Neo4jClient
        c = Neo4jClient(Neo4jSettings("neo4j+s://h", "u", "p"))
        c._driver = object()
        with self.assertRaises(ReadOnlyViolation):
            c.run_schema_write(["MATCH (n) DETACH DELETE n"])


class SettingsTests(unittest.TestCase):
    def test_env_and_fallbacks(self):
        s = Neo4jSettings.from_env({"NEO4J_URI": "neo4j+s://x.databases.neo4j.io", "NEO4J_USERNAME": "abc", "NEO4J_PASSWORD": "pw"}, load=False)
        self.assertEqual((s.user, s.database), ("abc", "neo4j"))
        s2 = Neo4jSettings.from_env({"NEO4J_URI": "u", "NEO4J_USER": "neo4j", "NEO4J_USERNAME": "abc", "NEO4J_PASSWORD": "pw", "NEO4J_DATABASE": "d"}, load=False)
        self.assertEqual((s2.user, s2.database), ("neo4j", "d"))
        self.assertNotIn("pw", s2.describe())

    def test_missing_settings(self):
        with self.assertRaises(Neo4jConfigError):
            Neo4jSettings.from_env({}, load=False)

    def test_ca_bundle_rewrites_scheme(self):
        uri, kw = driver_kwargs("neo4j+s://h:7687", None)
        self.assertEqual((uri, kw), ("neo4j+s://h:7687", {}))
        try:
            import certifi
            uri, kw = driver_kwargs("neo4j+s://h:7687", certifi.where())
        except ImportError:
            self.skipTest("neo4j driver / certifi not installed")
        self.assertEqual(uri, "neo4j://h:7687")
        self.assertTrue(kw["encrypted"])

    def test_clean_value(self):
        class T:
            def iso_format(self):
                return "2026-01-01T00:00:00Z"
        self.assertEqual(clean_value({"a": [T(), 1]}), {"a": ["2026-01-01T00:00:00Z", 1]})


class EvidenceTests(unittest.TestCase):
    gm = GraphMap.from_report(REPORT)

    def test_status(self):
        s = lambda p: evidence_status(p, self.gm)
        self.assertEqual(s({"origin": "graphrag", "evidence_type": "llm_extracted_candidate"}), "candidate")
        self.assertEqual(s({"evidence_type": "LLM_Extracted_Candidate"}), "candidate")
        self.assertEqual(s({"evidence_type": "inferred"}), "candidate")          # never documented
        self.assertEqual(s({"evidence_type": "structured_authoritative_record"}), "structured")
        self.assertEqual(s({"rel_id": "r1"}), "unclassified")                    # not silently upgraded

    def test_claim_class(self):
        self.assertEqual(claim_class("direct", ["structured"]), "documented")
        self.assertEqual(claim_class("direct", ["unclassified"]), "documented")
        self.assertEqual(claim_class("via_campaign", ["structured", "structured"]), "inferred")
        self.assertEqual(claim_class("candidate", ["candidate"]), "candidate")
        self.assertEqual(claim_class("direct", ["candidate"]), "candidate")
        self.assertEqual(best_class(["candidate", "inferred", "documented"]), "documented")

    def test_slim(self):
        out = slim({"t": "x" * 1000, "l": list(range(50))})
        self.assertTrue(len(out["t"]) < 450)
        self.assertEqual(len(out["l"]), 21)


def actor_routes(**over):
    actor = {"labels": ["Entity", "ThreatActor"], "props": {"entity_id": "ThreatActor:G1", "name": "APT-X", "aliases": ["Foo"]}, "rank": 1}
    r = [
        ("MATCH (n:Entity)\nWHERE", [actor]),
        ("AS id, labels(x)", over.get("same", [])),
        ("MATCH (a:Entity)-[r:`USES`]->(t:AttackTechnique)", over.get("direct", [
            {"tprops": tech("T1"), "tlabels": ["Entity", "AttackTechnique"], "rprops": {"rel_id": "r1", "evidence_type": "structured_authoritative_record"}, "via": None},
            {"tprops": tech("T2"), "tlabels": ["Entity", "AttackTechnique"], "rprops": {"rel_id": "r2"}, "via": None}])),
        ("CONDUCTS", over.get("campaign", [
            {"tprops": tech("T3"), "tlabels": [], "rprops": {"rel_id": "r3"}, "rprops_first": {"rel_id": "r4"}, "via": {"entity_id": "Campaign:C1", "name": "Op C"}}])),
        ("(s:Malware OR s:Tool)", over.get("software", [
            {"tprops": tech("T3"), "tlabels": [], "rprops": {"rel_id": "r5"}, "rprops_first": {"rel_id": "r6"}, "via": {"entity_id": "Malware:S1", "name": "Mal"}}])),
        ("[r:RELATED_TO]", over.get("cand", [
            {"tprops": tech("T1"), "tlabels": [], "rprops": {"origin": "graphrag", "evidence_type": "llm_extracted_candidate"}, "via": None},
            {"tprops": tech("T9"), "tlabels": [], "rprops": {"origin": "graphrag", "evidence_type": "llm_extracted_candidate"}, "via": None}])),
        ("MATCH (rep:IntelligenceReport)", over.get("reports", [
            {"tid": "T1", "rprops": {"entity_id": "R1", "name": "AA22-1", "modified_at": "2022-01-01", "source_url": "https://x"}},
            {"tid": "T1", "rprops": {"entity_id": "R2", "name": "AA23-2", "modified_at": "2023-01-01"}}])),
    ]
    return r


class RepositoryTests(unittest.TestCase):
    def repo(self, routes):
        self.fake = FakeClient(routes)
        return GraphRepository(self.fake, GraphMap.from_report(REPORT))

    def test_find_entities_parameterises_user_text(self):
        repo = self.repo(actor_routes())
        evil = "x'}) DETACH DELETE (n) //"
        repo.find_entities(evil)
        cy, params = self.fake.calls[0]
        self.assertNotIn("DETACH", cy)
        self.assertEqual(params["q"], evil.lower())
        self.assertIn("any(a IN n.`aliases`", cy)

    def test_alias_clause_skipped_for_scalar_alias(self):
        rep = {**REPORT, "properties": {"Entity": {"entity_id": ["String"], "name": ["String"], "aliases": ["String"]}}}
        self.assertNotIn("aliases", C.find_entities(GraphMap.from_report(rep), typed=False, include_candidates=True))

    def test_find_validation(self):
        repo = self.repo([])
        with self.assertRaises(ValueError):
            repo.find_entities("  ")
        with self.assertRaises(ValueError):
            repo.find_entities("x" * 201)
        with self.assertRaises(ValueError):
            repo.find_entities("a", types=["Bogus"])

    def test_limit_is_clamped(self):
        repo = self.repo([])
        repo.find_entities("a", limit=10 ** 9)
        self.assertEqual(self.fake.calls[0][1]["limit"], 1000)
        repo.find_entities("a", limit=-5)
        self.assertEqual(self.fake.calls[1][1]["limit"], 1)

    def test_resolve_unique_ambiguous_missing(self):
        mk = lambda i, rank: {"labels": ["Entity", "ThreatActor"], "props": {"entity_id": i, "name": "n"}, "rank": rank}
        self.assertEqual(self.repo([("MATCH (n:Entity)", [mk("A", 1)])]).resolve_entity("n")["id"], "A")
        with self.assertRaises(AmbiguousEntity):
            self.repo([("MATCH (n:Entity)", [mk("A", 1), mk("B", 1)])]).resolve_entity("n")
        with self.assertRaises(EntityNotFound):
            self.repo([]).resolve_entity("zzz")

    def test_actor_techniques_classification(self):
        res = self.repo(actor_routes()).techniques_for_actor("apt-x")
        by = {t["id"]: t for t in res["techniques"]}
        self.assertEqual(by["T1"]["claim_class"], "documented")
        self.assertTrue(by["T1"]["also_reported_as_candidate"])
        self.assertEqual(by["T2"]["claim_class"], "documented")           # canonical, evidence type not stored
        self.assertEqual(by["T3"]["claim_class"], "inferred")
        self.assertEqual({p["derivation"] for p in by["T3"]["paths"]}, {"via_campaign", "via_software"})
        self.assertEqual(by["T9"]["claim_class"], "candidate")
        self.assertEqual(res["counts"], {"documented": 2, "inferred": 1, "candidate": 1, "total": 4})
        self.assertEqual([t["id"] for t in res["techniques"]], ["T1", "T2", "T3", "T9"])   # documented first

    def test_candidate_never_counted_as_documented(self):
        res = self.repo(actor_routes(direct=[], campaign=[], software=[])).techniques_for_actor("apt-x")
        self.assertTrue(all(t["claim_class"] == "candidate" for t in res["techniques"]))
        self.assertEqual(res["counts"]["documented"], 0)

    def test_reports_attached_newest_first_and_limited(self):
        res = self.repo(actor_routes()).techniques_for_actor("apt-x", reports_per_technique=1)
        t1 = [t for t in res["techniques"] if t["id"] == "T1"][0]
        self.assertEqual([r["id"] for r in t1["reports"]], ["R2"])

    def test_flags_switch_queries_off(self):
        repo = self.repo(actor_routes())
        repo.techniques_for_actor("apt-x", include_inferred=False, include_candidates=False, with_reports=False)
        joined = "\n".join(c for c, _ in self.fake.calls)
        for absent in ("CONDUCTS", "Malware OR s:Tool", "RELATED_TO", "IntelligenceReport"):
            self.assertNotIn(absent, joined)

    def test_same_name_nodes_searched(self):
        repo = self.repo(actor_routes(same=[{"id": "ThreatActor:cand-aptx", "labels": ["Entity", "ThreatActor", "Candidate"]}]))
        res = repo.techniques_for_actor("apt-x")
        ids = [p for c, p in self.fake.calls if "USES`]->(t:AttackTechnique)" in c][0]["ids"]
        self.assertEqual(ids, ["ThreatActor:G1", "ThreatActor:cand-aptx"])
        self.assertTrue(res["notes"])

    def test_truncation_note(self):
        rows = [{"tprops": tech(f"T{i}"), "tlabels": [], "rprops": {}, "via": None} for i in range(3)]
        res = self.repo(actor_routes(direct=rows, campaign=[], software=[], cand=[])).techniques_for_actor("apt-x", limit=3)
        self.assertTrue(any("limit" in n for n in res["notes"]))

    def test_neighbors_filters_and_status(self):
        rows = [{"rel_type": "USES", "outgoing": True, "rprops": {"rel_id": "r"}, "labels": ["Entity", "AttackTechnique"], "props": tech("T1")}]
        repo = self.repo([("MATCH (n:Entity {", rows)])
        r = repo.neighbors("X", rel_types=["USES"])
        cy, params = self.fake.calls[0]
        self.assertIn("type(r) IN $rel_types", cy)
        self.assertIn("NOT (m:Candidate)", cy)
        self.assertEqual(params["rel_types"], ["USES"])
        self.assertEqual(r["neighbors"][0]["direction"], "out")
        with self.assertRaises(ValueError):
            repo.neighbors("X", rel_types=["USES]-() DELETE"])

    def test_path_hops_clamped_and_candidates_excluded(self):
        cy = C.shortest_path(GraphMap.from_report(REPORT), rel_types=None, max_hops=50, include_candidates=False, all_paths=False)
        self.assertIn("*..5", cy)
        self.assertIn("none(x IN nodes(p)", cy)
        cy2 = C.shortest_path(GraphMap.from_report(REPORT), rel_types=["USES"], max_hops=0, include_candidates=True, all_paths=True)
        self.assertIn("allShortestPaths", cy2)
        self.assertIn("*..1", cy2)
        self.assertNotIn("none(", cy2)

    def test_find_path_result_shape(self):
        ent = lambda i: {"labels": ["Entity"], "props": {"entity_id": i, "name": i}, "rank": 0}
        repo = self.repo([("MATCH (n:Entity)\nWHERE", lambda p: [ent(p["q"])]),
                          ("shortestPath", [{"nodes": [{"id": "a"}, {"id": "b"}], "rels": [{"type": "USES", "from": "a", "to": "b"}], "hops": 1}])])
        res = repo.find_path("a", "b")
        self.assertTrue(res["found"])
        self.assertEqual(res["paths"][0]["hops"], 1)

    def test_provenance_shape(self):
        row = {"labels": ["Entity", "Malware", "Candidate"], "props": {"entity_id": "M", "name": "m", "origin": "graphrag"},
               "text_units": [{"text_unit_id": "tu1", "text": "t" * 900, "chunk_ids": ["c1"]}], "communities": [{"community_id": "0", "title": "C"}], "reports": []}
        res = self.repo([("EXTRACTED_FROM", [row])]).provenance("M")
        self.assertEqual(res["evidence_status"], "candidate")
        self.assertTrue(res["entity"]["is_candidate"])
        self.assertEqual(len(res["text_units"][0]["text"]), 600)
        with self.assertRaises(EntityNotFound):
            self.repo([]).provenance("none")

    def test_changed_since_string_vs_datetime_and_missing(self):
        gm = GraphMap.from_report(REPORT)
        self.assertIn(">= $since", C.changed_since(gm, typed=False))
        self.assertNotIn("datetime(", C.changed_since(gm, typed=False))
        rep = {**REPORT, "properties": {"Entity": {**REPORT["properties"]["Entity"], "modified_at": ["DateTime"]}}}
        self.assertIn("datetime($since)", C.changed_since(GraphMap.from_report(rep), typed=False))
        none = GraphRepository(FakeClient(), GraphMap.from_report({**REPORT, "properties": {"Entity": {"entity_id": ["String"], "name": ["String"]}}}))
        with self.assertRaises(CapabilityUnavailable):
            none.changed_since("2026-01-01")

    def test_index_plan(self):
        plan = plan_indexes(GraphMap.from_report(REPORT))
        self.assertEqual(len(plan), 2)
        self.assertTrue(all("IF NOT EXISTS" in p for p in plan))
        self.assertEqual(plan_indexes(GraphMap.from_report({**REPORT, "properties": {"Entity": {"entity_id": ["String"]}}})), [])


if __name__ == "__main__":
    unittest.main()
