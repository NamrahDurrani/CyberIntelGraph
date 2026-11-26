"use client";
import { useEffect, useState } from "react";
import { GraphView } from "@/components/GraphView";
import { Empty, ErrorBox } from "@/components/ui";
import { api, streamSSE } from "@/lib/api";
import type { GNode, Graph } from "@/lib/types";

export default function GraphPage() {
  const [q, setQ] = useState(""); const [hits, setHits] = useState<GNode[]>([]); const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] });
  const [seeds, setSeeds] = useState<string[]>([]); const [err, setErr] = useState<string | null>(null);
  const [live, setLive] = useState<{ nodes: number; edges: number; changed?: boolean; at: string } | null>(null); const [watching, setWatching] = useState(true);
  useEffect(() => {
    if (q.length < 2) { setHits([]); return; }
    const t = setTimeout(async () => { try { const all = await Promise.all(["ThreatActor", "Malware", "Vulnerability", "AttackTechnique"].map((l) => api<GNode[]>(`/api/graph/entities?label=${l}&q=${encodeURIComponent(q)}`))); setHits(all.flat().slice(0, 12)); } catch (e) { setErr((e as Error).message); } }, 300);
    return () => clearTimeout(t);
  }, [q]);
  const load = (ids: string[]) => { if (ids.length) api<Graph>(`/api/graph/subgraph?ids=${ids.map(encodeURIComponent).join(",")}`).then((g) => { setGraph(g); setErr(null); }).catch((e) => setErr(e.message)); };
  useEffect(() => load(seeds), [seeds]);
  useEffect(() => { // live watch of the Neo4j database (SSE) - re-pulls the visible subgraph when counts change or the ingest webhook fires
    if (!watching) return; const c = new AbortController();
    streamSSE("/api/graph/watch", (e) => {
      if (e.type === "counts") setLive({ nodes: e.nodes as number, edges: e.edges as number, changed: e.changed as boolean, at: new Date().toLocaleTimeString() });
      if ((e.type === "counts" && e.changed) || e.type === "graph_changed") setSeeds((s) => [...s]);
    }, c.signal).catch(() => {});
    return () => c.abort();
  }, [watching]);
  return (
    <div className="page grid"><div className="row"><h2 className="grow">Knowledge graph</h2>
      <button className={`btn ${watching ? "btn-primary" : "btn-ghost"}`} onClick={() => setWatching(!watching)}>{watching ? "Live watch on" : "Live watch off"}</button></div>
      {live && watching && <p className="small muted">Neo4j: {live.nodes.toLocaleString()} nodes · {live.edges.toLocaleString()} relationships · checked {live.at}{live.changed && <span className="s-candidate"> · graph changed, view refreshed</span>}</p>}
      <input className="input" placeholder="Search an actor, malware, CVE or technique to start exploring" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search graph entities" />
      <ErrorBox msg={err} />
      {hits.length > 0 && <div className="row" style={{ flexWrap: "wrap" }}>{hits.map((h) => <button key={h.id} className="chip" style={{ cursor: "pointer" }} onClick={() => { setSeeds((s) => [...new Set([...s, h.id])]); setQ(""); }}>{h.name} · {h.labels[0]}</button>)}</div>}
      {graph.nodes.length ? <GraphView graph={graph} onSelect={(id) => setSeeds((s) => [...new Set([...s, id])])} /> : <div className="card"><Empty title="Nothing selected yet" hint="Search above, then click any node to expand its neighbours." /></div>}
      {seeds.length > 0 && <button className="btn btn-ghost" style={{ justifySelf: "start" }} onClick={() => { setSeeds([]); setGraph({ nodes: [], edges: [] }); }}>Clear graph</button>}
    </div>
  );
}
