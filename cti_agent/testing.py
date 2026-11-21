"""Test doubles: an in-memory mini knowledge graph that answers the agent's
'// tool:<name>' queries, a scripted LLM and a static document retriever.
Used by the unit tests and by scripts/check_agent.py (offline mode)."""

from __future__ import annotations

import re
from collections import deque
from typing import Any, Callable

from .config import Settings
from .deps import Deps
from .llm import LLMUnavailable
from .schema_map import SchemaMap
from .tools.text_tools import TextHit


class FakeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, tuple[list[str], dict[str, Any]]] = {}
        self.edges: list[tuple[str, str, str, dict[str, Any]]] = []

    def node(self, eid: str, labels: list[str], **props: Any) -> str:
        self.nodes[eid] = (labels, props)
        return eid

    def edge(self, src: str, rel: str, dst: str, **props: Any) -> None:
        self.edges.append((src, rel, dst, props))


def sample_graph() -> FakeGraph:
    g = FakeGraph()
    g.node("a1", ["ThreatActor"], name="APT29", attack_id="G0016", description="Russian state-sponsored group.")
    g.node("t1", ["AttackTechnique"], name="Command and Scripting Interpreter", attack_id="T1059")
    g.node("t2", ["AttackTechnique"], name="Phishing", attack_id="T1566")
    g.node("v1", ["Vulnerability"], cve_id="CVE-2024-3400", name="CVE-2024-3400",
           description="Command injection in PAN-OS GlobalProtect.", cvss=10.0)
    g.node("s1", ["Software"], name="PAN-OS")
    g.node("w1", ["Weakness"], cwe_id="CWE-77", name="Improper Neutralization of Special Elements in a Command")
    g.node("r1", ["IntelligenceReport"], title="AA24-100A Palo Alto PAN-OS Exploitation", url="https://example.test/aa24-100a")
    g.node("c1", ["GraphRAGCandidate"], name="Volt Typhoon", entity_type="THREAT_ACTOR")
    g.node("c2", ["GraphRAGCandidate"], name="Living off the land", entity_type="TECHNIQUE")
    g.node("u1", ["TextUnit"], chunk_id="aa24-100a::0003",
           text="Volt Typhoon was observed using living off the land techniques against critical infrastructure.")
    g.edge("a1", "USES", "t1")
    g.edge("a1", "USES", "t2")
    g.edge("v1", "AFFECTS", "s1")
    g.edge("v1", "HAS_WEAKNESS", "w1")
    g.edge("r1", "MENTIONS", "v1")
    g.edge("c1", "EXTRACTED_FROM", "u1")
    g.edge("c1", "RELATED_TO", "c2")
    return g


class FakeRunner:
    """Pretends to be Neo4jRunner. Routes on the '// tool:<name>' first line."""

    def __init__(self, graph: FakeGraph | None = None, fail_tools: set[str] | None = None,
                 flaky: set[str] | None = None):
        self.graph = graph or sample_graph()
        self.fail_tools = fail_tools or set()   # always fail
        self.flaky = set(flaky or ())            # fail once, then work
        self.calls: list[str] = []

    def close(self) -> None:  # parity with Neo4jRunner
        pass

    def __call__(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        params = params or {}
        tool = re.match(r"//\s*tool:(\w+)", cypher).group(1)
        self.calls.append(tool)
        if tool in self.fail_tools:
            raise RuntimeError(f"simulated failure in {tool}")
        if tool in self.flaky:
            self.flaky.discard(tool)
            raise RuntimeError(f"simulated one-off failure in {tool}")
        return getattr(self, f"_{tool}")(cypher, params)

    # ---- schema
    def _schema_labels(self, c, p):
        return [{"label": l} for l in sorted({l for ls, _ in self.graph.nodes.values() for l in ls})]

    def _schema_rel_types(self, c, p):
        return [{"relationshipType": r} for r in sorted({e[1] for e in self.graph.edges})]

    def _schema_keys(self, c, p):
        label = re.search(r"\(n:`(\w+)`\)", c).group(1)
        keys = sorted({k for ls, pr in self.graph.nodes.values() if label in ls for k in pr})
        return [{"k": k} for k in keys]

    def _probe_count(self, c, p):
        return [{"n": 1}]

    # ---- entity lookup
    def _find_entities(self, c, p):
        exact = "= $term" in c
        rows = []
        for eid, (labels, props) in self.graph.nodes.items():
            if not set(labels) & set(p["labels"]):
                continue
            for k in p["props"]:
                if props.get(k) is None:
                    continue
                v = str(props[k]).lower()
                if (v == p["term"]) if exact else (p["term"] in v):
                    rows.append({"eid": eid, "labels": labels, "props": props})
                    break
        return rows[: p["fetch"]]

    # ---- neighbours
    def _neighbor_summary(self, c, p):
        counts: dict[tuple, int] = {}
        for src, rel, dst, _ in self.graph.edges:
            for me, other, outgoing in ((src, dst, True), (dst, src, False)):
                if me != p["eid"]:
                    continue
                labels = self.graph.nodes[other][0]
                if set(labels) & set(p["exclude"]):
                    continue
                if p["rels"] and rel not in p["rels"]:
                    continue
                key = (rel, outgoing, labels[0])
                counts[key] = counts.get(key, 0) + 1
        return [{"rel": r, "outgoing": o, "label": l, "n": n}
                for (r, o, l), n in sorted(counts.items(), key=lambda kv: -kv[1])]

    def _neighbor_sample(self, c, p):
        rows = []
        for src, rel, dst, rprops in self.graph.edges:
            for me, other, outgoing in ((src, dst, True), (dst, src, False)):
                if me == p["eid"] and rel == p["rel"] and outgoing == p["outgoing"] \
                        and p["label"] in self.graph.nodes[other][0]:
                    rows.append({"props": self.graph.nodes[other][1], "rprops": rprops})
        return rows[: p["limit"]]

    def _shortest_path(self, c, p):
        adj: dict[str, list[tuple[str, str]]] = {}
        for src, rel, dst, _ in self.graph.edges:
            adj.setdefault(src, []).append((dst, rel))
            adj.setdefault(dst, []).append((src, rel))
        queue = deque([(p["a"], [p["a"]], [])])
        seen = {p["a"]}
        while queue:
            node, path, rels = queue.popleft()
            if node == p["b"]:
                names = [{"label": self.graph.nodes[n][0][0],
                          "name": next(str(self.graph.nodes[n][1][k]) for k in p["props"] if k in self.graph.nodes[n][1])}
                         for n in path]
                return [{"nodes": names, "rels": rels}]
            if len(rels) >= 3:
                continue
            for nxt, rel in adj.get(node, []):
                if nxt not in seen and not set(self.graph.nodes[nxt][0]) & set(p["exclude"]):
                    seen.add(nxt)
                    queue.append((nxt, path + [nxt], rels + [rel]))
        return []

    # ---- candidates, reports, text
    def _candidates_for(self, c, p):
        rows = []
        for eid, (labels, props) in self.graph.nodes.items():
            if "GraphRAGCandidate" not in labels:
                continue
            if not any(props.get(k) and p["term"] in str(props[k]).lower() for k in p["props"]):
                continue
            units = [self.graph.nodes[d][1] for s, r, d, _ in self.graph.edges
                     if s == eid and r == "EXTRACTED_FROM"]
            rows.append({"eid": eid, "props": props, "units": units})
        return rows[: p["limit"]]

    def _candidate_relations(self, c, p):
        rows = []
        for src, rel, dst, rprops in self.graph.edges:
            for me, other, outgoing in ((src, dst, True), (dst, src, False)):
                if me == p["eid"] and "GraphRAGCandidate" in self.graph.nodes[other][0]:
                    rows.append({"rel": rel, "outgoing": outgoing, "props": self.graph.nodes[other][1], "rprops": rprops})
        return rows

    def _report_mentions(self, c, p):
        return []

    def _textunits_matching(self, c, p):
        rows = []
        for eid, (labels, props) in self.graph.nodes.items():
            if "TextUnit" in labels and any(t in str(props.get("text", "")).lower() for t in p["terms"]):
                rows.append({"eid": eid, "props": props})
        return rows[: p["limit"]]


class FakeLLM:
    """Scripted LLM. By default: understanding -> no extra entities; answering -> the summaries of the
    first three evidence blocks, each followed by its own citation (so the answer is grounded)."""

    def __init__(self, handler: Callable[[str, str], str] | None = None, fail: bool = False):
        self.handler = handler
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, *, max_tokens: int | None = None) -> str:
        self.calls.append((system, user))
        if self.fail:
            raise LLMUnavailable("simulated outage")
        if self.handler:
            return self.handler(system, user)
        if "Extract the cybersecurity entities" in system:
            return '{"entities": []}'
        blocks = re.findall(r"^\[(E\d+)\] status=[^\n]*\nsummary: ([^\n]*)", user, flags=re.MULTILINE)
        sentences = [f"{summary.rstrip('.')} [{eid}]." for eid, summary in blocks[:3]]
        return " ".join(sentences) + "\nLimitations: test answer."


class StaticRetriever:
    name = "static-test-retriever"

    def __init__(self, hits: list[TextHit] | None = None, fail: bool = False):
        self.hits = hits or []
        self.fail = fail

    def retrieve(self, question: str, top_k: int) -> list[TextHit]:
        if self.fail:
            raise RuntimeError("simulated retriever failure")
        return self.hits[:top_k]


def make_test_deps(*, runner: FakeRunner | None = None, llm: Any = None, retriever: Any = None,
                   trace_dir: str | None = None, **setting_overrides: Any) -> Deps:
    from dataclasses import replace
    import tempfile

    settings = replace(Settings(), trace_dir=trace_dir or tempfile.mkdtemp(prefix="agent-trace-"),
                       schema_cache=tempfile.mkdtemp(prefix="agent-schema-") + "/schema.json",
                       **setting_overrides)
    runner = runner or FakeRunner()
    schema = SchemaMap.discover(runner)
    return Deps(settings=settings, runner=runner, schema=schema,
                llm=llm if llm is not None else FakeLLM(),
                retriever=retriever if retriever is not None else StaticRetriever())
