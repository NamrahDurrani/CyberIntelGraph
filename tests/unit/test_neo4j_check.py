"""Tests for scripts/check_neo4j_graph.py using a stand-in database that answers from the plan."""
import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
spec = importlib.util.spec_from_file_location("check_neo4j_graph", os.path.join(ROOT, "scripts", "check_neo4j_graph.py"))
ck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ck)


def ev(src="mitre_attack", typ="structured_authoritative"):
    return {"source": src, "evidence_type": typ, "record_ref": "r", "source_url": "https://x", "retrieved_at": "t"}


ENTS = [
    {"canonical_id": "Malware:S1", "entity_type": "Malware", "name": "TrickBot", "aliases": [], "sources": ["mitre_attack"], "evidence": [ev()]},
    {"canonical_id": "ThreatActor:G1", "entity_type": "ThreatActor", "name": "Wizard", "aliases": [], "sources": ["mitre_attack"], "evidence": [ev()]},
    {"canonical_id": "Vulnerability:CVE-2024-1", "entity_type": "Vulnerability", "name": "CVE-2024-1", "aliases": [], "sources": ["cisa_kev"], "evidence": [ev("cisa_kev")]},
    {"canonical_id": "Weakness:CWE-79", "entity_type": "Weakness", "name": "XSS", "aliases": [], "sources": ["cwe"], "evidence": [ev("cwe")]},
]
RELS = [
    {"rel_id": "USES|ThreatActor:G1|Malware:S1", "rel_type": "USES", "source_id": "ThreatActor:G1", "target_id": "Malware:S1",
     "evidence_type": "structured_authoritative", "evidence": [ev()], "properties": {}},
    {"rel_id": "HAS_WEAKNESS|Vulnerability:CVE-2024-1|Weakness:CWE-79", "rel_type": "HAS_WEAKNESS",
     "source_id": "Vulnerability:CVE-2024-1", "target_id": "Weakness:CWE-79", "evidence_type": "structured_authoritative",
     "evidence": [ev("cwe")], "properties": {}},
]


def gnode(eid, name, etype, canonical=False):
    return {"entity_id": eid, "name": name, "entity_type": etype, "canonical_type": True, "description": "d", "titles": [name.upper()],
            "graphrag_ids": ["g"], "text_unit_ids": ["tu1"], "chunk_ids": ["advisory_x_chunk_001"], "frequency": 1, "degree": 1,
            "evidence_type": "llm_extracted_candidate", "generic": False, "scoped_to_document": None}


EXPORT = {
    "nodes": [gnode("Malware:S1", "TrickBot", "Malware"), gnode("Tool:cand-cobalt", "Cobalt", "Tool"),
              gnode("Sector:cand-health", "Health", "Sector")],
    "relationships": [{"rel_id": "RELATED_TO|Malware:S1|Tool:cand-cobalt", "rel_type": "RELATED_TO", "source_id": "Malware:S1",
                       "target_id": "Tool:cand-cobalt", "evidence_type": "llm_extracted_candidate", "description": "d", "weight": 3.0,
                       "text_unit_ids": ["tu1"], "chunk_ids": ["advisory_x_chunk_001"]}],
    "text_units": [{"text_unit_id": "tu1", "text": "t", "n_tokens": 1, "doc_id": "advisory_x", "chunk_ids": ["advisory_x_chunk_001"]}],
    "communities": [{"community_key": "gr-c0", "community": 0, "level": 0, "parent": -1, "size": 2, "title": "T", "summary": "S",
                     "rank": 8.0, "findings_json": "[]", "origin": "graphrag"}],
    "links": {"entity_text_unit": [["Malware:S1", "tu1"], ["Tool:cand-cobalt", "tu1"], ["Sector:cand-health", "tu1"]],
              "text_unit_report": [], "entity_community": [["Tool:cand-cobalt", "gr-c0"]]},
}


class StandInDB:
    """Answers every checker query from the expected values; `override` changes single answers."""
    def __init__(self, exp, override=None):
        self.exp, self.override = exp, override or {}
        self.by_text = {v: k for k, v in ck.Q.items()}

    def __call__(self, q, **p):
        key = self.by_text[q]
        if key in self.override:
            return self.override[key]
        e = self.exp
        return {
            "constraints": [{"names": sorted(ck.REQUIRED_CONSTRAINTS)}],
            "canonical_by_type": [{"t": t, "c": c} for t, c in e["canonical_by_type"].items()],
            "candidates": [{"c": e["candidates"]}], "text_units": [{"c": e["text_units"]}], "communities": [{"c": e["communities"]}],
            "rels_by_type": [{"t": t, "c": c} for t, c in e["rels_by_type"].items()],
            "sample": [{"c": len(p["rows"])}] if "rows" in p else [{"c": 0}],
            "has_weakness_vulns": [{"c": e["has_weakness_vulns"]}],
        }.get(key, [{"c": 0}])


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.exp = ck.expected_from_files(EXPORT, ENTS, RELS)

    def fails(self, **override):
        res = ck.run_checks(StandInDB(self.exp, override), self.exp)
        return [m for lvl, ok, m in res if lvl == "FAIL" and not ok], [m for lvl, ok, m in res if lvl == "WARN" and not ok]

    def test_expected_values_come_from_the_files(self):
        e = self.exp
        self.assertEqual(e["canonical_by_type"], {"Malware": 1, "ThreatActor": 1, "Vulnerability": 1, "Weakness": 1})
        self.assertEqual(e["candidates"], 2)                       # Malware:S1 is canonical, not a candidate
        self.assertEqual((e["text_units"], e["communities"]), (1, 1))
        self.assertEqual(e["rels_by_type"], {"HAS_WEAKNESS": 1, "RELATED_TO": 1, "USES": 1, "EXTRACTED_FROM": 3, "IN_COMMUNITY": 1})
        self.assertEqual(sum(e["rels_by_type"].values()), e["total_relationships"])
        self.assertEqual(e["total_nodes"], 4 + 2 + 1 + 1)           # canonical + candidates + text unit + community
        self.assertEqual(e["has_weakness_vulns"], 1)
        self.assertEqual(len(e["sample"]), 2)

    def test_a_correct_database_passes(self):
        self.assertEqual(self.fails(), ([], []))

    def test_missing_relationship_type_fails(self):
        rows = [{"t": t, "c": c} for t, c in self.exp["rels_by_type"].items() if t != "HAS_WEAKNESS"]
        f, _ = self.fails(rels_by_type=rows)
        self.assertTrue(any("relationships per type" in m for m in f))

    def test_wrong_node_count_fails(self):
        f, _ = self.fails(canonical_by_type=[{"t": "Malware", "c": 2}])
        self.assertTrue(any("canonical nodes per type" in m for m in f))

    def test_pencil_notes_must_not_leak_into_printed_facts(self):
        for key, text in (("canonical_edges_touching_candidates", "touches a candidate"),
                          ("canonical_with_candidate_label", "labelled Candidate"),
                          ("bad_candidates", "every candidate node"), ("bad_related_to", "RELATED_TO")):
            f, _ = self.fails(**{key: [{"c": 1}]})
            self.assertTrue(any(text in m for m in f), key)

    def test_traceability_rules(self):
        f, w = self.fails(units_without_chunks=[{"c": 1}])
        self.assertTrue(any("text unit maps back" in m for m in f))
        f, w = self.fails(candidates_without_source=[{"c": 2}])
        self.assertEqual(f, [])                                      # only a warning
        self.assertTrue(any("EXTRACTED_FROM" in m for m in w))

    def test_duplicates_and_constraints_fail(self):
        self.assertTrue(self.fails(dup_entities=[{"c": 1}])[0])
        self.assertTrue(self.fails(dup_rels=[{"c": 3}])[0])
        self.assertTrue(self.fails(constraints=[{"names": ["entity_id_unique"]}])[0])

    def test_sampled_relationships_must_all_exist(self):
        self.assertTrue(self.fails(sample=[{"c": 1}])[0])


if __name__ == "__main__":
    unittest.main()
