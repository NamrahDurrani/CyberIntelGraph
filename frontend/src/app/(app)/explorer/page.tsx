"use client";
import { useEffect, useState } from "react";
import { Empty, ErrorBox, Skeleton, StatusBadge } from "@/components/ui";
import { api } from "@/lib/api";
import type { Graph, GNode } from "@/lib/types";

const LABELS = ["ThreatActor", "Malware", "Vulnerability", "AttackTechnique", "Campaign", "Tool", "Software", "Weakness"];
export default function Explorer() {
  const [label, setLabel] = useState("ThreatActor"); const [q, setQ] = useState(""); const [rows, setRows] = useState<GNode[] | null>(null);
  const [err, setErr] = useState<string | null>(null); const [sel, setSel] = useState<GNode | null>(null); const [nb, setNb] = useState<Graph | null>(null);
  useEffect(() => {
    setRows(null); setErr(null);
    const t = setTimeout(() => api<GNode[]>(`/api/graph/entities?label=${label}&q=${encodeURIComponent(q)}`).then(setRows).catch((e) => setErr(e.message)), 250);
    return () => clearTimeout(t);
  }, [label, q]);
  async function pick(n: GNode) { setSel(n); setNb(null); try { setNb(await api<Graph>(`/api/graph/subgraph?ids=${encodeURIComponent(n.id)}`)); } catch (e) { setErr((e as Error).message); } }
  const byId = new Map(nb?.nodes.map((n) => [n.id, n]));
  return (
    <div className="page grid"><h2>Intelligence explorer</h2>
      <div className="row" style={{ flexWrap: "wrap" }}>{LABELS.map((l) => <button key={l} className={`btn ${l === label ? "btn-primary" : "btn-ghost"}`} onClick={() => { setLabel(l); setSel(null); }}>{l.replace(/([A-Z])/g, " $1").trim()}</button>)}</div>
      <input className="input" placeholder={`Search ${label} by name`} value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search entities" />
      <ErrorBox msg={err} />
      <div className="grid g2" style={{ alignItems: "start" }}>
        <div className="card" style={{ padding: 8 }}>{!rows ? <div className="grid" style={{ padding: 12 }}>{[0, 1, 2, 3].map((i) => <Skeleton key={i} />)}</div> : !rows.length ? <Empty title="No matching entities" hint="Try a shorter name or another type." /> :
          <table><thead><tr><th>Name</th><th>Evidence status</th></tr></thead><tbody>{rows.map((n) => <tr key={n.id} className="click" onClick={() => pick(n)}><td>{n.name}</td><td><StatusBadge status={n.candidate ? "candidate" : "confirmed"} /></td></tr>)}</tbody></table>}</div>
        <div className="card">{!sel ? <Empty title="Select an entity" hint="See its direct relationships from the graph." /> : <>
          <h3>{sel.name}</h3><p className="muted small">{sel.labels.join(", ")}</p>
          {!nb ? <Skeleton h={80} /> : <table><thead><tr><th>Relationship</th><th>Connected entity</th></tr></thead><tbody>{nb.edges.slice(0, 80).map((e) => { const other = byId.get(e.source === sel.id ? e.target : e.source); return <tr key={e.id}><td className="small">{e.source === sel.id ? "" : "← "}{e.type}{e.source === sel.id ? " →" : ""}{e.candidate && " (candidate)"}</td><td>{other?.name} <span className="muted small">{other?.labels[0]}</span></td></tr>; })}</tbody></table>}</>}</div>
      </div>
    </div>
  );
}
