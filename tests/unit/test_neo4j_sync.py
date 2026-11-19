import contextlib
import io
import json
import math
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from canonical.models import Relationship                                      # noqa: E402
from graphrag_engine.export import mapping as mp                               # noqa: E402
from graphrag_engine.indexing.resolve import build_canonical_index             # noqa: E402
from graphrag_engine.synchronization import sync_neo4j as sy                   # noqa: E402

RULES = mp.load_rules(os.path.join(ROOT, "config", "graphrag_export_rules.json"))
RULES_DROP = {**RULES, "generic_mode": "drop"}
REPORT_ID = "IntelligenceReport:advisory_x"


def ev(source="mitre_attack", typ="structured_authoritative"):
    return {"source": source, "evidence_type": typ, "record_ref": "ref1", "source_url": "https://x", "retrieved_at": "t"}


CANON_ENTS = [
    {"canonical_id": "Malware:S0266", "entity_type": "Malware", "name": "TrickBot", "aliases": ["Trickbot"], "sources": ["mitre_attack"], "evidence": [ev()]},
    {"canonical_id": "ThreatActor:G0102", "entity_type": "ThreatActor", "name": "Wizard Spider", "aliases": [], "sources": ["mitre_attack"], "evidence": [ev()]},
    {"canonical_id": "Vulnerability:CVE-2024-3400", "entity_type": "Vulnerability", "name": "CVE-2024-3400", "aliases": [], "sources": ["cisa_kev"],
     "evidence": [ev("cisa_kev")], "cve_id": "CVE-2024-3400", "cvss_primary": {"score": 10.0, "v": "3.1"}, "in_kev": True},
    {"canonical_id": REPORT_ID, "entity_type": "IntelligenceReport", "name": "Advisory X", "aliases": [], "sources": ["advisories"], "evidence": [ev("advisories", "stated_in_source")]},
]
CANON_RELS = [
    {"rel_id": "USES|ThreatActor:G0102|Malware:S0266", "rel_type": "USES", "source_id": "ThreatActor:G0102", "target_id": "Malware:S0266",
     "evidence_type": "structured_authoritative", "evidence": [ev()], "properties": {"note": "x"}},
    {"rel_id": f"MENTIONS|{REPORT_ID}|Vulnerability:CVE-2024-3400", "rel_type": "MENTIONS", "source_id": REPORT_ID,
     "target_id": "Vulnerability:CVE-2024-3400", "evidence_type": "stated_in_source", "evidence": [ev("advisories", "stated_in_source")], "properties": {}},
    {"rel_id": "USES|ThreatActor:G9999|Malware:S0266", "rel_type": "USES", "source_id": "ThreatActor:G9999", "target_id": "Malware:S0266",
     "evidence_type": "structured_authoritative", "evidence": [], "properties": {}},
]
FILE_TEXT = "Title\n\nChunk one about TrickBot and PIPEDREAM.\n\nChunk two about OT networks and CVE-2024-3400.\n"
C1, C2 = "advisory_x_chunk_001", "advisory_x_chunk_002"


def manifest():
    s1 = FILE_TEXT.index("Chunk one")
    e1 = FILE_TEXT.index("\n\nChunk two")
    s2 = FILE_TEXT.index("Chunk two")
    return {"advisory_x": {"title": "Title", "file": "advisory_x.txt", "chars": len(FILE_TEXT),
                           "chunks": [{"chunk_id": C1, "start": s1, "end": e1}, {"chunk_id": C2, "start": s2, "end": len(FILE_TEXT) - 1}]}}


def frames():
    tu1, tu2 = "tu1", "tu2"
    ent = lambda i, title, typ, tus, freq=1, deg=2: {"id": i, "title": title, "type": typ, "description": f"{title} desc", "text_unit_ids": tus, "frequency": freq, "degree": deg}  # noqa: E731
    return {
        "entities": [ent("e1", "TRICKBOT", "MALWARE", [tu1], 2), ent("e2", "APT ACTORS", "THREAT_ACTOR", [tu1]), ent("e3", "CISA", "ORGANIZATION", [tu1]),
                     ent("e4", "OT", "SECTOR", [tu2]), ent("e5", "OPERATIONAL TECHNOLOGIES", "SECTOR", [tu2], 3, 5), ent("e6", "CVE-2024-3400", "VULNERABILITY", [tu2]),
                     ent("e7", "PIPEDREAM", "MALWARE", [tu1, tu2]), ent("e8", "FOO", "WEIRD", [tu1]), ent("e9", "", "MALWARE", [tu1])],
        "relationships": [
            {"id": "r1", "source": "TRICKBOT", "target": "PIPEDREAM", "description": "short", "weight": 3.0, "text_unit_ids": [tu1]},
            {"id": "r2", "source": "TRICKBOT", "target": "PIPEDREAM", "description": "a longer description wins", "weight": 2.0, "text_unit_ids": [tu2]},
            {"id": "r3", "source": "OT", "target": "OPERATIONAL TECHNOLOGIES", "description": "alias pair", "weight": 1.0, "text_unit_ids": [tu2]},
            {"id": "r4", "source": "APT ACTORS", "target": "TRICKBOT", "description": "noise", "weight": 9.0, "text_unit_ids": [tu1]},
            {"id": "r5", "source": "PIPEDREAM", "target": "CVE-2024-3400", "description": "p exploits", "weight": 1.0, "text_unit_ids": [tu2]},
            {"id": "r6", "source": "OT", "target": "NOT AN ENTITY", "description": "x", "weight": 1.0, "text_unit_ids": []}],
        "text_units": [{"id": tu1, "text": "Chunk one about TrickBot and PIPEDREAM.", "n_tokens": 9, "document_id": "d1"},
                       {"id": tu2, "text": "Chunk two about OT networks and CVE-2024-3400.", "n_tokens": 10, "document_id": "d1"},
                       {"id": "tu3", "text": "text that is not in the file", "n_tokens": 5, "document_id": "d1"}],
        "documents": [{"id": "d1", "title": "advisory_x.txt"}],
        "communities": [{"community": 0, "level": 0, "parent": -1, "size": 3, "title": "Community 0", "entity_ids": ["e1", "e7", "e2"]},
                        {"community": 1, "level": 1, "parent": 0, "size": 1, "title": "Community 1", "entity_ids": ["e6"]}],
        "community_reports": [{"community": 0, "title": "TrickBot and Pipedream", "summary": "s", "rank": 8.5, "findings": [{"summary": "f"}]}],
    }


def build(tmp=None, rules=None):
    tmp = tmp or tempfile.mkdtemp()
    with open(os.path.join(tmp, "advisory_x.txt"), "w", encoding="utf-8", newline="") as fh:
        fh.write(FILE_TEXT)
    return mp.build_export(frames(), rules or RULES, CANON_ENTS, manifest(), tmp, {C1: REPORT_ID, C2: REPORT_ID})


class MappingTests(unittest.TestCase):
    """generic_mode "drop": generic hubs and everything attached to them are removed."""
    def setUp(self):
        self.export = build(rules=RULES_DROP)
        self.nodes = {n["entity_id"]: n for n in self.export["nodes"]}

    def test_filtering_typing_linking_and_alias_merge(self):
        rep = self.export["report"]
        self.assertEqual(rep["entities_skipped"], {"generic_title": 1, "advisory_author": 1, "unmapped_type": 1, "empty_title": 1})
        self.assertEqual(self.nodes["Malware:S0266"]["linked"], True)                       # TRICKBOT -> canonical TrickBot
        self.assertEqual(self.nodes["Vulnerability:CVE-2024-3400"]["in_canonical"], True)
        self.assertIn("Malware:cand-pipedream", self.nodes)
        self.assertFalse(self.nodes["Malware:cand-pipedream"]["linked"])
        sector = self.nodes["Sector:cand-operational-technologies"]                        # OT merged into OPERATIONAL TECHNOLOGIES
        self.assertEqual(sector["titles"], ["OPERATIONAL TECHNOLOGIES", "OT"])
        self.assertEqual((sector["frequency"], sector["degree"], sector["canonical_type"]), (4, 5, False))
        self.assertEqual(rep["nodes_out"], 4)
        self.assertEqual((rep["nodes_linked_to_canonical_id"], rep["nodes_candidate_only"], rep["nodes_noncanonical_type"]), (2, 2, 1))

    def test_relationships_are_validated_summed_deduplicated_and_untyped_become_related_to(self):
        rels = {r["rel_id"]: r for r in self.export["relationships"]}
        self.assertEqual(set(rels), {"RELATED_TO|Malware:S0266|Malware:cand-pipedream", "RELATED_TO|Malware:cand-pipedream|Vulnerability:CVE-2024-3400"})
        tp = rels["RELATED_TO|Malware:S0266|Malware:cand-pipedream"]
        self.assertEqual((tp["weight"], tp["description"], tp["text_unit_ids"]), (5.0, "a longer description wins", ["tu1", "tu2"]))
        self.assertEqual(tp["chunk_ids"], [C1, C2])
        rr = self.export["report"]["relationships_skipped"]
        self.assertEqual(rr, {"endpoint_generic_title": 1, "endpoint_unknown_title": 1, "self_loop_after_merge": 1})
        for r in rels.values():
            Relationship(rel_id=r["rel_id"], rel_type=r["rel_type"], source_id=r["source_id"], target_id=r["target_id"],
                         evidence_type=r["evidence_type"])

    def test_text_units_keep_provenance_to_our_chunks_and_report(self):
        tus = {t["text_unit_id"]: t for t in self.export["text_units"]}
        self.assertEqual(tus["tu1"]["chunk_ids"], [C1])
        self.assertEqual(tus["tu1"]["report_id"], REPORT_ID)
        self.assertEqual(tus["tu2"]["chunk_ids"], [C2])
        self.assertEqual((tus["tu3"]["chunk_ids"], tus["tu3"]["report_id"]), ([], None))
        self.assertEqual(self.export["report"]["text_units"], {"mapped": 2, "unmapped": 1})
        self.assertEqual(self.nodes["Malware:cand-pipedream"]["chunk_ids"], [C1, C2])
        self.assertIn(["Malware:S0266", "tu1"], self.export["links"]["entity_text_unit"])
        self.assertEqual(len(self.export["links"]["text_unit_report"]), 2)

    def test_communities_and_membership_skip_filtered_entities(self):
        comms = {c["community_key"]: c for c in self.export["communities"]}
        self.assertEqual(comms["gr-c0"]["title"], "TrickBot and Pipedream")                 # report title wins
        self.assertEqual(comms["gr-c1"]["title"], "Community 1")                            # no report -> community title
        self.assertEqual(self.export["links"]["entity_community"],
                         [["Malware:S0266", "gr-c0"], ["Malware:cand-pipedream", "gr-c0"], ["Vulnerability:CVE-2024-3400", "gr-c1"]])

    def test_export_is_deterministic_and_json_safe(self):
        for rules in (RULES, RULES_DROP):
            self.assertEqual(json.dumps(build(rules=rules), sort_keys=True), json.dumps(build(rules=rules), sort_keys=True))

    def test_ambiguous_names_stay_candidates(self):
        ents = CANON_ENTS + [{"canonical_id": "Tool:S0001", "entity_type": "Tool", "name": "TrickBot", "aliases": [], "sources": [], "evidence": []}]
        nodes, *_ = mp.map_entities(frames()["entities"], RULES, build_canonical_index(ents))
        n = nodes["Malware:cand-trickbot"]
        self.assertEqual((n["linked"], n["ambiguous_with"]), (False, ["Malware:S0266", "Tool:S0001"]))


class ScopeModeTests(unittest.TestCase):
    """generic_mode "scope" (shipped default): generic hubs become one candidate node per advisory."""
    def setUp(self):
        self.export = build()
        self.nodes = {n["entity_id"]: n for n in self.export["nodes"]}

    def test_generic_entity_becomes_a_document_scoped_candidate(self):
        n = self.nodes["ThreatActor:cand-apt-actors-x"]
        self.assertEqual((n["name"], n["generic"], n["scoped_to_document"], n["text_unit_ids"]),
                         ("APT ACTORS [x]", True, "advisory_x", ["tu1"]))
        rep = self.export["report"]
        self.assertNotIn("generic_title", rep["entities_skipped"])
        self.assertEqual((rep["generic_nodes_scoped_to_advisory"], rep["nodes_out"]), (1, 5))

    def test_relationships_through_the_generic_hub_survive(self):
        rels = {r["rel_id"]: r for r in self.export["relationships"]}
        hub = rels["RELATED_TO|ThreatActor:cand-apt-actors-x|Malware:S0266"]
        self.assertEqual((hub["weight"], hub["chunk_ids"]), (9.0, [C1]))
        self.assertEqual(len(rels), 3)
        self.assertEqual(self.export["report"]["relationships_skipped"], {"endpoint_unknown_title": 1, "self_loop_after_merge": 1})
        self.assertEqual(self.export["report"]["nodes_without_relationships"], 1)            # the merged sector only had a self-loop

    def test_membership_reaches_the_scoped_node(self):
        self.assertIn(["ThreatActor:cand-apt-actors-x", "gr-c0"], self.export["links"]["entity_community"])

    def test_one_scoped_node_and_one_relationship_per_advisory(self):
        ents = [{"id": "g1", "title": "TOOL", "type": "TOOL", "text_unit_ids": ["a1", "b1"], "frequency": 2, "degree": 3},
                {"id": "g2", "title": "PIPEDREAM", "type": "MALWARE", "text_unit_ids": ["a1", "b1"], "frequency": 2, "degree": 3}]
        rels = [{"id": "r", "source": "TOOL", "target": "PIPEDREAM", "weight": 4, "description": "d", "text_unit_ids": ["a1", "b1"]}]
        tu_doc = {"a1": "advisory_a", "b1": "advisory_b"}
        nodes, t2n, g2n, skipped, tskip = mp.map_entities(ents, RULES, build_canonical_index([]), tu_doc)
        self.assertEqual(sorted(nodes), ["Malware:cand-pipedream", "Tool:cand-tool-a", "Tool:cand-tool-b"])
        self.assertEqual(nodes["Tool:cand-tool-a"]["text_unit_ids"], ["a1"])
        self.assertEqual(g2n["g1"], ["Tool:cand-tool-a", "Tool:cand-tool-b"])
        out, rskip = mp.map_relationships(rels, t2n, nodes, tu_doc, tskip)
        self.assertEqual(sorted(out), ["RELATED_TO|Tool:cand-tool-a|Malware:cand-pipedream", "RELATED_TO|Tool:cand-tool-b|Malware:cand-pipedream"])
        self.assertEqual(out["RELATED_TO|Tool:cand-tool-b|Malware:cand-pipedream"]["text_unit_ids"], ["b1"])
        self.assertEqual(dict(rskip), {})

    def test_without_document_information_scope_mode_falls_back_to_dropping(self):
        ents = [{"id": "g1", "title": "TOOL", "type": "TOOL", "text_unit_ids": ["a1"]}]
        nodes, _t, _g, skipped, tskip = mp.map_entities(ents, RULES, build_canonical_index([]), None)
        self.assertEqual((nodes, dict(skipped), tskip), ({}, {"generic_title": 1}, {"TOOL": "generic_title"}))


class SanitizeTests(unittest.TestCase):
    def test_property_sanitising(self):
        p = sy.sanitize_props({"a": 1, "b": None, "c": float("nan"), "d": {"x": [1, 2]}, "e": [1, "two"], "f": [["n"]], "g": ["x", "y"],
                               "h": True, "i": 1.5, "j": [None, "k"], "k": ()})
        self.assertEqual(p["a"], 1)
        self.assertNotIn("b", p)
        self.assertNotIn("c", p)
        self.assertEqual(json.loads(p["d"]), {"x": [1, 2]})
        self.assertEqual(p["e"], ["1", "two"])
        self.assertEqual(json.loads(p["f"]), [["n"]])
        self.assertEqual((p["g"], p["h"], p["i"], p["j"], p["k"]), (["x", "y"], True, 1.5, ["k"], []))
        self.assertTrue(all(not isinstance(v, float) or not math.isnan(v) for v in p.values()))

    def test_evidence_summary(self):
        s = sy.evidence_summary([ev(), ev("nvd", "structured_authoritative")] + [ev("advisories", "stated_in_source")] * 5)
        self.assertEqual(s["evidence_sources"], ["advisories", "mitre_attack", "nvd"])
        self.assertEqual(len(s["evidence_record_refs"]), 5)
        self.assertEqual(len(json.loads(s["evidence_json"])), 5)
        self.assertIsNone(sy.evidence_summary([])["evidence_json"])

    def test_unsafe_names_are_refused(self):
        for bad in ("Malware`) DETACH DELETE n //", "9bad", "a b", ""):
            with self.assertRaises(ValueError):
                sy.check_names([bad], [])
        with self.assertRaises(ValueError):
            sy.check_names([], ["uses"])
        sy.check_names(["Malware", "Entity_2"], ["USES", "RELATED_TO"])

    def test_env_file_never_overrides_the_real_environment(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, ".env")
        with open(p, "w", encoding="utf-8-sig") as fh:
            fh.write('# c\nZZ_TEST_A=from_file\nZZ_TEST_B="quoted value"\n')
        with mock.patch.dict(os.environ, {"ZZ_TEST_A": "from_env"}, clear=False):
            os.environ.pop("ZZ_TEST_B", None)
            sy.load_env_file(p)
            self.assertEqual((os.environ["ZZ_TEST_A"], os.environ["ZZ_TEST_B"]), ("from_env", "quoted value"))
        os.environ.pop("ZZ_TEST_B", None)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.export = build()

    def test_plan_groups_and_counts(self):
        plan = sy.build_plan(self.export, CANON_ENTS, CANON_RELS)
        names = [n for n, _q, _r in plan["steps"]]
        self.assertTrue(all("__" not in q for _n, q, _r in plan["steps"]))
        self.assertEqual(plan["skipped"], {"canonical_rel_endpoint_missing": 1})
        c, exp = plan["counts"], self.export
        canon = {e["canonical_id"] for e in CANON_ENTS}
        cands = sum(1 for n in exp["nodes"] if n["entity_id"] not in canon)
        self.assertEqual(c["candidate_nodes"], cands)
        self.assertEqual(c["nodes"], 4 + cands + len(exp["text_units"]) + len(exp["communities"]))
        lk = exp["links"]
        self.assertEqual(c["relationships"], 2 + len(exp["relationships"]) + len(lk["entity_text_unit"])
                         + len(lk["text_unit_report"]) + len(lk["entity_community"]))
        self.assertLess(names.index("canonical nodes :Malware"), names.index("relationships USES"))
        self.assertLess(names.index("text units"), names.index("links EXTRACTED_FROM"))

    def test_linked_nodes_only_get_gr_properties_and_keep_their_canonical_label(self):
        plan = sy.build_plan(self.export, CANON_ENTS, CANON_RELS)
        step = next(s for s in plan["steps"] if s[0] == "graphrag facts on canonical :Malware")
        row = next(r for r in step[2] if r["entity_id"] == "Malware:S0266")
        self.assertTrue(set(row["props"]) <= {"gr_description", "gr_titles", "gr_ids", "gr_text_unit_ids", "gr_chunk_ids", "gr_frequency", "gr_degree", "seen_in_graphrag"})
        cand = next(s for s in plan["steps"] if s[0] == "graphrag candidate nodes :Malware")
        self.assertIn("SET n:Candidate", cand[1])
        self.assertEqual(cand[2][0]["props"]["origin"], "graphrag")

    def test_canonical_properties_are_sanitised(self):
        plan = sy.build_plan(None, CANON_ENTS, CANON_RELS)
        v = next(s for s in plan["steps"] if s[0] == "canonical nodes :Vulnerability")[2][0]["props"]
        self.assertEqual(json.loads(v["cvss_primary"]), {"score": 10.0, "v": "3.1"})
        self.assertEqual((v["origin"], v["in_kev"]), ("canonical", True))
        self.assertNotIn("evidence", v)

    def test_graphrag_only_and_canonical_only(self):
        g = sy.build_plan(self.export, CANON_ENTS, CANON_RELS, do_canonical=False)
        self.assertFalse(any(n.startswith("canonical nodes") for n, _q, _r in g["steps"]))
        self.assertFalse(any(n.startswith("relationships USES") for n, _q, _r in g["steps"]))
        c = sy.build_plan(None, CANON_ENTS, CANON_RELS, do_graphrag=False)
        self.assertEqual(c["counts"], {"nodes": 4, "candidate_nodes": 0, "relationships": 2})

    def test_describe_warns_near_the_free_tier_limit(self):
        text = sy.describe_plan({"steps": [], "counts": {"nodes": 170_000, "relationships": 10}, "skipped": {}})
        self.assertIn("[WARN]", text)


class FakeCounters:
    def __init__(self, n=0, r=0, p=0):
        self.nodes_created, self.relationships_created, self.properties_set = n, r, p


class FakeResult:
    def __init__(self, counters=None, value=None):
        self._c, self._v = counters, value

    def consume(self):
        return mock.Mock(counters=self._c)

    def single(self):
        return {"c": self._v}


class FakeGraph:
    """Emulates MERGE semantics on the keys our queries use, including MATCH-endpoint checks."""
    def __init__(self):
        self.nodes, self.rels, self.queries = set(), set(), []

    def run(self, q, rows=None):
        self.queries.append((q, rows))
        if q.startswith("CREATE CONSTRAINT"):
            return FakeResult(FakeCounters())
        if q.startswith("MATCH (n:Entity) RETURN"):
            return FakeResult(value=sum(1 for k in self.nodes if k[0] == "E"))
        if q.startswith("MATCH (n:TextUnit) RETURN"):
            return FakeResult(value=sum(1 for k in self.nodes if k[0] == "T"))
        if q.startswith("MATCH (n:Community) RETURN"):
            return FakeResult(value=sum(1 for k in self.nodes if k[0] == "C"))
        if q.startswith("MATCH ()-[r]->() RETURN"):
            return FakeResult(value=len(self.rels))
        n = r = 0
        for row in rows:
            if "MERGE (n:Entity" in q:
                k = ("E", row["entity_id"])
                n += k not in self.nodes
                self.nodes.add(k)
            elif "MERGE (t:TextUnit" in q:
                k = ("T", row["text_unit_id"])
                n += k not in self.nodes
                self.nodes.add(k)
            elif "MERGE (c:Community" in q:
                k = ("C", row["community_key"])
                n += k not in self.nodes
                self.nodes.add(k)
            else:
                ends = (("E", row.get("source_id", row.get("a"))), ("E", row.get("target_id", row.get("b"))))
                if "(t:TextUnit" in q:
                    ends = (("E", row["a"]), ("T", row["b"]))
                if "MERGE (t)-[r:PART_OF" in q:
                    ends = (("T", row["a"]), ("E", row["b"]))
                if "(c:Community" in q:
                    ends = (("E", row["a"]), ("C", row["b"]))
                if all(e in self.nodes for e in ends):
                    k = row["rel_id"]
                    r += k not in self.rels
                    self.rels.add(k)
        return FakeResult(FakeCounters(n, r))


class FakeSession:
    def __init__(self, g):
        self.g = g

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_write(self, fn):
        return fn(self.g)

    def execute_read(self, fn):
        return fn(self.g)


class FakeDriver:
    def __init__(self):
        self.g = FakeGraph()

    def session(self, database=None):
        return FakeSession(self.g)

    def close(self):
        pass


class SyncRunTests(unittest.TestCase):
    def test_second_pass_creates_nothing_and_plan_keys_are_unique(self):
        plan = sy.build_plan(build(), CANON_ENTS, CANON_RELS)
        for name, _q, rows in plan["steps"]:
            keys = [r.get("entity_id") or r.get("text_unit_id") or r.get("community_key") or r.get("rel_id") for r in rows]
            self.assertEqual(len(keys), len(set(keys)), name)
        d = FakeDriver()
        sy.ensure_constraints(d)
        first = sy.run_steps(d, plan["steps"], batch_size=3, log=lambda *_: None)
        c1 = sy.graph_counts(d)
        second = sy.run_steps(d, plan["steps"], batch_size=3, log=lambda *_: None)
        self.assertGreater(first["nodes_created"], 0)
        self.assertGreater(first["relationships_created"], 0)
        self.assertEqual((second["nodes_created"], second["relationships_created"]), (0, 0))
        self.assertEqual(sy.graph_counts(d), c1)
        self.assertEqual(c1["entities"], 4 + plan["counts"]["candidate_nodes"])
        self.assertEqual((c1["text_units"], c1["communities"]), (3, 2))
        self.assertEqual(c1["relationships"], plan["counts"]["relationships"])           # every planned relationship found its endpoints

    def test_batches_split_rows(self):
        d = FakeDriver()
        sy.run_steps(d, [("x", sy.Q_TU, [{"text_unit_id": str(i), "props": {}} for i in range(5)])], batch_size=2, log=lambda *_: None)
        self.assertEqual([len(r) for _q, r in d.g.queries], [2, 2, 1])

    def test_cli_dry_run_needs_no_credentials_or_neo4j(self):
        tmp = tempfile.mkdtemp()
        exp = os.path.join(tmp, "export.json")
        with open(exp, "w", encoding="utf-8") as fh:
            json.dump(build(), fh)
        cdir = os.path.join(tmp, "canonical")
        os.makedirs(cdir)
        for name, recs in (("entities.json", CANON_ENTS), ("relationships.json", CANON_RELS)):
            with open(os.path.join(cdir, name), "w", encoding="utf-8") as fh:
                json.dump({"metadata": {}, "records": recs}, fh)
        env = {k: v for k, v in os.environ.items() if not k.startswith("NEO4J_")}
        p = subprocess.run([sys.executable, os.path.join(ROOT, "graphrag_engine", "synchronization", "sync_neo4j.py"), "--dry-run",
                            "--export", exp, "--canonical-dir", cdir], capture_output=True, text=True, env=env, cwd=tmp, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        c = sy.build_plan(build(), CANON_ENTS, CANON_RELS)["counts"]
        self.assertIn(f"planned: {c['nodes']} nodes ({c['candidate_nodes']} GraphRAG candidates), {c['relationships']} relationships", p.stdout)
        self.assertIn("dry run: nothing was sent to Neo4j", p.stdout)

    def test_verify_twice_reports_pass_with_a_well_behaved_graph(self):
        tmp = tempfile.mkdtemp()
        exp = os.path.join(tmp, "export.json")
        with open(exp, "w", encoding="utf-8") as fh:
            json.dump(build(), fh)
        cdir = os.path.join(tmp, "canonical")
        os.makedirs(cdir)
        for name, recs in (("entities.json", CANON_ENTS), ("relationships.json", CANON_RELS)):
            with open(os.path.join(cdir, name), "w", encoding="utf-8") as fh:
                json.dump({"metadata": {}, "records": recs}, fh)
        out = io.StringIO()
        with mock.patch.object(sy, "connect", return_value=(FakeDriver(), None)), mock.patch.object(
                sys, "argv", ["sync", "--verify-twice", "--export", exp, "--canonical-dir", cdir]), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            sy.main()
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("IDEMPOTENT: PASS", out.getvalue())

    def test_tcp_probe_and_uri_parsing(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.assertTrue(sy.tcp_probe("127.0.0.1", port, 2))
        srv.close()
        self.assertFalse(sy.tcp_probe("127.0.0.1", port, 2))
        self.assertEqual(sy.split_uri("neo4j+s://abc123.databases.neo4j.io"), ("abc123.databases.neo4j.io", 7687))
        self.assertEqual(sy.split_uri("bolt://localhost:7999/x"), ("localhost", 7999))

    def test_unreachable_host_gives_a_network_message_instead_of_hanging(self):
        env = {"NEO4J_URI": "neo4j+s://unreachable.example", "NEO4J_USERNAME": "neo4j", "NEO4J_PASSWORD": "never-printed-secret"}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(sy, "load_env_file"), mock.patch.object(sy, "tcp_probe", return_value=False), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            sy.connect()
        msg = str(cm.exception)
        self.assertIn("NETWORK problem", msg)
        self.assertIn("7687", msg)
        self.assertNotIn("never-printed-secret", msg + out.getvalue())
        self.assertIn("step 1/3", out.getvalue())

    def test_connect_refuses_when_credentials_are_missing(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("NEO4J_")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(sy, "load_env_file"), self.assertRaises(SystemExit) as cm:
            sy.connect()
        self.assertIn("NEO4J_URI", str(cm.exception))


class AuraAuthError(Exception):
    pass


class AuraUnavailable(Exception):
    pass


def fake_neo4j(behaviours):
    """A stand-in for the neo4j package: each GraphDatabase.driver() call consumes one outcome (None = connects, or an exception)."""
    calls, outcomes = [], iter(behaviours)

    class Driver:
        def __init__(self, outcome):
            self.outcome, self.closed = outcome, False

        def verify_connectivity(self):
            if self.outcome:
                raise self.outcome

        def close(self):
            self.closed = True

    class GraphDatabase:
        @staticmethod
        def driver(uri, **kw):
            d = Driver(next(outcomes))
            calls.append((uri, kw, d))
            return d
    mod, exc = types.ModuleType("neo4j"), types.ModuleType("neo4j.exceptions")
    mod.GraphDatabase, mod.TrustCustomCAs, mod.exceptions = GraphDatabase, (lambda *p: ("CA", p)), exc
    exc.AuthError = AuraAuthError
    return {"neo4j": mod, "neo4j.exceptions": exc}, calls


class ConnectTlsTests(unittest.TestCase):
    ENV = {"NEO4J_URI": "neo4j+s://abc123.databases.neo4j.io", "NEO4J_USERNAME": "neo4j", "NEO4J_PASSWORD": "pw-never-printed"}

    def run_connect(self, behaviours, env=None, bundle="/fake/certifi/cacert.pem"):
        modules, calls = fake_neo4j(behaviours)
        base = {k: v for k, v in os.environ.items() if not k.startswith("NEO4J_")}
        base.update(self.ENV if env is None else env)
        out, err = io.StringIO(), None
        with mock.patch.dict(os.environ, base, clear=True), mock.patch.dict(sys.modules, modules), \
                mock.patch.object(sy, "load_env_file"), mock.patch.object(sy, "tcp_probe", return_value=True), \
                mock.patch.object(sy, "_certifi_bundle", return_value=bundle), contextlib.redirect_stdout(out):
            try:
                result = sy.connect()
            except SystemExit as ex:
                result, err = None, str(ex)
        self.assertNotIn("pw-never-printed", out.getvalue() + (err or ""))
        return result, calls, out.getvalue(), err

    def test_system_certificates_work_first_time(self):
        result, calls, out, err = self.run_connect([None])
        self.assertIsNotNone(result)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "neo4j+s://abc123.databases.neo4j.io")
        self.assertNotIn("trusted_certificates", calls[0][1])
        self.assertEqual(calls[0][1]["auth"], ("neo4j", "pw-never-printed"))

    def test_falls_back_to_the_certifi_bundle_when_the_system_store_cannot_verify_the_server(self):
        """The situation seen on the real machine: 'Unable to retrieve routing information' with the system store, success with certifi."""
        result, calls, out, err = self.run_connect([AuraUnavailable("Unable to retrieve routing information"), None])
        self.assertIsNotNone(result)
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0][2].closed)
        uri, kw, _ = calls[1]
        self.assertEqual(uri, "neo4j://abc123.databases.neo4j.io")                      # +s removed: it cannot be combined with a CA bundle
        self.assertTrue(kw["encrypted"])
        self.assertEqual(kw["trusted_certificates"], ("CA", ("/fake/certifi/cacert.pem",)))
        self.assertIn("NEO4J_TLS=certifi", out)

    def test_wrong_password_is_reported_as_such_and_not_retried(self):
        result, calls, out, err = self.run_connect([AuraAuthError("bad")])
        self.assertIsNone(result)
        self.assertEqual(len(calls), 1)
        self.assertIn("login rejected", err)

    def test_when_every_attempt_fails_the_message_explains_what_to_try(self):
        result, calls, out, err = self.run_connect([AuraUnavailable("a"), AuraUnavailable("b")])
        self.assertEqual(len(calls), 2)
        self.assertIn("login failed", err)
        self.assertIn("NEO4J_CA_BUNDLE", err)

    def test_tls_mode_certifi_skips_the_first_attempt_and_system_never_uses_a_bundle(self):
        result, calls, *_ = self.run_connect([None], env={**self.ENV, "NEO4J_TLS": "certifi"})
        self.assertEqual(len(calls), 1)
        self.assertIn("trusted_certificates", calls[0][1])
        result, calls, out, err = self.run_connect([AuraUnavailable("x")], env={**self.ENV, "NEO4J_TLS": "system"})
        self.assertEqual(len(calls), 1)
        self.assertIn("login failed", err)

    def test_own_ca_bundle_overrides_certifi(self):
        _r, calls, *_ = self.run_connect([None], env={**self.ENV, "NEO4J_TLS": "certifi", "NEO4J_CA_BUNDLE": "C:/certs/corp-root.pem"})
        self.assertEqual(calls[0][1]["trusted_certificates"], ("CA", ("C:/certs/corp-root.pem",)))

    def test_plain_bolt_is_tried_once_without_a_bundle(self):
        _r, calls, *_ = self.run_connect([AuraUnavailable("x")], env={**self.ENV, "NEO4J_URI": "bolt://localhost:7687"})
        self.assertEqual(len(calls), 1)
        self.assertNotIn("trusted_certificates", calls[0][1])

    def test_neo4j_user_is_accepted_as_the_username(self):
        env = {"NEO4J_URI": self.ENV["NEO4J_URI"], "NEO4J_USER": "aura-user", "NEO4J_PASSWORD": "pw-never-printed"}
        result, calls, *_ = self.run_connect([None], env=env)
        self.assertEqual(calls[0][1]["auth"], ("aura-user", "pw-never-printed"))

    def test_without_certifi_only_the_system_store_is_tried(self):
        _r, calls, out, err = self.run_connect([AuraUnavailable("x")], bundle=None)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
