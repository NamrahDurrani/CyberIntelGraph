"""Milestone 13 - unit tests for understanding, evidence, schema discovery, text tools."""
import json

import pytest

from cti_agent.evidence import EvidenceBook, EvidenceStatus
from cti_agent.llm import extract_json
from cti_agent.nodes import classify_intent, extract_identifiers, heuristic_terms
from cti_agent.schema_map import SchemaMap, safe_label
from cti_agent.testing import FakeRunner
from cti_agent.tools.text_tools import FunctionRetriever, normalize_hits, load_retriever, NullRetriever


def test_extract_identifiers_finds_each_kind():
    ids = extract_identifiers("Does cve-2024-3400 relate to T1059.001, CWE-77, G0016 or S0154?")
    assert ids["cve"] == ["CVE-2024-3400"]
    assert ids["technique"] == ["T1059.001"]
    assert ids["cwe"] == ["CWE-77"]
    assert ids["group"] == ["G0016"]
    assert ids["software"] == ["S0154"]


def test_heuristic_terms_names_not_question_words():
    q = "Which techniques does APT29 use, and is Cobalt Strike connected to LockBit?"
    terms = heuristic_terms(q, {})
    assert "APT29" in terms and "Cobalt Strike" in terms and "LockBit" in terms
    assert "Which" not in terms and "Does" not in terms


def test_heuristic_terms_quoted_and_identifier_removed():
    ids = extract_identifiers('What about "Volt Typhoon" and CVE-2024-3400?')
    terms = heuristic_terms('What about "Volt Typhoon" and CVE-2024-3400?', ids)
    assert terms == ["Volt Typhoon"]


def test_heuristic_terms_lowercase_fallback():
    assert heuristic_terms("tell me about lockbit", {}) == ["lockbit"]


@pytest.mark.parametrize("q,intent", [
    ("Which software does this affect?", "affected_software"),
    ("What weakness (CWE) is behind it?", "weakness"),
    ("Which techniques does it use?", "techniques"),
    ("Is it exploited?", "vulnerability"),
    ("Hello", "general"),
])
def test_classify_intent(q, intent):
    assert classify_intent(q) == intent


def test_evidence_book_ids_counts_roundtrip():
    book = EvidenceBook()
    a = book.add(EvidenceStatus.CONFIRMED_AUTHORITATIVE, "x", "one")
    b = book.add(EvidenceStatus.NOT_FOUND, "y", "two")
    assert (a.id, b.id) == ("E1", "E2")
    assert book.has_content()
    assert book.counts()["not_found"] == 1
    again = EvidenceBook(book.to_dicts())
    assert again.get("E2").status == EvidenceStatus.NOT_FOUND
    assert again.add(EvidenceStatus.INFERRED, "z", "three").id == "E3"


def test_evidence_only_misses_is_not_content():
    book = EvidenceBook()
    book.add(EvidenceStatus.NOT_FOUND, "m", "nothing")
    book.add(EvidenceStatus.UNABLE_TO_VERIFY, "f", "failed")
    assert not book.has_content()


def test_schema_discovery_on_sample_graph():
    schema = SchemaMap.discover(FakeRunner())
    assert schema.candidate_label == "GraphRAGCandidate"
    assert schema.textunit_label == "TextUnit"
    assert "cve_id" in schema.id_props and "name" in schema.name_props
    assert "text" in schema.text_props
    assert "USES" in schema.rel_types


def test_schema_cache_roundtrip(tmp_path):
    runner = FakeRunner()
    path = tmp_path / "s.json"
    first = SchemaMap.load_or_discover(runner, path)
    calls_after_first = len(runner.calls)
    second = SchemaMap.load_or_discover(runner, path)
    assert len(runner.calls) == calls_after_first  # served from cache
    assert first.to_json() == second.to_json()
    assert json.loads(path.read_text())["candidate_label"] == "GraphRAGCandidate"


def test_safe_label_rejects_injection():
    assert safe_label("Vulnerability") == "Vulnerability"
    with pytest.raises(ValueError):
        safe_label("X`) DETACH DELETE (n) //")


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 2}\n```') == {"a": 2}
    assert extract_json('Sure! {"a": 3} hope that helps') == {"a": 3}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_normalize_hits_accepts_dicts_objects_tuples():
    class Obj:
        text, chunk_id, doc_id, score = "obj text", "c9", "d9", 0.5

    raw = [{"text": "dict text", "chunk_id": "c1", "doc_id": "d1", "score": 1.5},
           Obj(), ({"chunk_text": "tuple text", "id": "c3"}, 0.25), "plain string", {"no_text": 1}]
    hits = normalize_hits(raw, 10)
    assert [h.text for h in hits] == ["dict text", "obj text", "tuple text", "plain string"]
    assert hits[0].chunk_id == "c1" and hits[0].score == 1.5
    assert hits[2].score == 0.25


def test_function_retriever_signature_fallbacks():
    def only_question(q):
        return [{"text": "ok"}]

    def positional(q, k):
        return [{"text": "pos"}]

    assert FunctionRetriever(only_question, "f").retrieve("x", 3)[0].text == "ok"
    assert FunctionRetriever(positional, "g").retrieve("x", 3)[0].text == "pos"


def test_load_retriever_variants():
    assert isinstance(load_retriever(""), NullRetriever)
    r = load_retriever("json:dumps")  # any importable callable works for loading
    assert r.name == "json:dumps"
    with pytest.raises(ValueError):
        load_retriever("badspec")
