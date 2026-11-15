"""Graph construction and community detection.

Microsoft GraphRAG uses hierarchical Leiden. We use Louvain from networkx (pure Python, small
install, deterministic with a fixed seed), one level. Communities are numbered by size so the
ids are stable: C000 is the largest.
"""
from __future__ import annotations


def _nx():
    try:
        import networkx as nx
    except ImportError as ex:                               # pragma: no cover
        raise SystemExit("networkx is required for Milestone 9:  pip install networkx") from ex
    return nx


def build_graph(entities: list[dict], rels: list[dict]):
    nx = _nx()
    g = nx.Graph()
    for e in entities:
        g.add_node(e["node_id"], name=e["name"], type=e["type"])
    for r in rels:
        a, b = r["source_id"], r["target_id"]
        if a in g and b in g and a != b:
            w = r["properties"]["weight"] + (g[a][b]["weight"] if g.has_edge(a, b) else 0)
            g.add_edge(a, b, weight=w)
    return g


def detect_communities(g, seed: int = 42, resolution: float = 1.0) -> list[list[str]]:
    nx = _nx()
    if g.number_of_nodes() == 0:
        return []
    parts = nx.community.louvain_communities(g, weight="weight", resolution=resolution, seed=seed)
    comms = [sorted(p, key=lambda n: (-g.degree(n, weight="weight"), n)) for p in parts]
    return sorted(comms, key=lambda c: (-len(c), min(c)))


def community_table(g, comms: list[list[str]], entities: list[dict], rels: list[dict]) -> list[dict]:
    by_node = {e["node_id"]: e for e in entities}
    out = []
    for i, members in enumerate(comms):
        mset = set(members)
        inside = [r for r in rels if r["source_id"] in mset and r["target_id"] in mset]
        chunks = sorted({ev["record_ref"] for r in inside for ev in r["evidence"]}
                        | {ev["record_ref"] for n in members for ev in by_node[n].get("evidence", [])})
        out.append({"community_id": f"C{i:03d}", "size": len(members), "node_ids": members,
                    "top_entities": [by_node[n]["name"] for n in members[:5]],
                    "relationship_count": len(inside), "doc_ids": sorted({d for n in members for d in by_node[n]["doc_ids"]}),
                    "evidence_chunks": chunks})
    return out
