"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Empty, ErrorBox, Skeleton, StatusBadge, timeAgo } from "@/components/ui";
import { api } from "@/lib/api";
import type { Dashboard } from "@/lib/types";
import { entityLabel } from "@/lib/ui-text";

const FOCUS = ["ThreatActor", "Vulnerability", "Malware", "AttackTechnique"];
export default function DashboardPage() {
  const [d, setD] = useState<Dashboard | null>(null); const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api<Dashboard>("/api/dashboard").then(setD).catch((e) => setErr(e.message)); }, []);
  if (err) return <div className="page"><ErrorBox msg={err} /></div>;
  if (!d) return <div className="page grid g4">{[0, 1, 2, 3].map((i) => <div key={i} className="card"><Skeleton h={60} /></div>)}</div>;
  const labels = Object.entries(d.graph?.labels ?? {}).filter(([k]) => k !== "Candidate").slice(0, 10).map(([name, value]) => ({ name, value }));
  const agents = Object.entries(d.agent_runs).map(([name, value]) => ({ name: name.replace("_agent", ""), value }));
  const sys = d.system;
  return (
    <div className="page grid">
      <h2>Dashboard</h2>
      <div className="grid g4">
        <div className="card stat"><b>{d.investigations.total}</b><span className="muted small">Investigations</span></div>
        <div className="card stat"><b>{d.investigations.by_status.completed ?? 0}</b><span className="muted small">Completed and verified</span></div>
        <div className="card stat"><b>{d.investigations.by_status.needs_approval ?? 0}</b><span className="muted small">Awaiting your approval</span></div>
        {FOCUS.map((k) => <div className="card stat" key={k}><b>{d.graph ? (d.graph.labels[k] ?? 0).toLocaleString() : "n/a"}</b><span className="muted small">{entityLabel(k.replace(/([A-Z])/g, " $1").trim())}</span></div>)}
      </div>
      <div className="grid g2">
        <div className="card"><h3 style={{ fontSize: 16, marginBottom: 12 }}>Graph entities by type</h3>
          {d.graph ? <div style={{ height: 260 }}><ResponsiveContainer><BarChart data={labels} layout="vertical" margin={{ left: 30 }}><CartesianGrid stroke="rgba(157,113,232,.15)" horizontal={false} /><XAxis type="number" stroke="#9D71E8" fontSize={12} /><YAxis type="category" dataKey="name" stroke="#9D71E8" fontSize={12} width={110} /><Tooltip contentStyle={{ background: "#25134D", border: 0, borderRadius: 12, color: "#F2E9FF" }} /><Bar dataKey="value" radius={8}>{labels.map((_, i) => <Cell key={i} fill={i % 2 ? "#9D71E8" : "#6A2FC8"} />)}</Bar></BarChart></ResponsiveContainer></div> : <Empty title="Neo4j is not reachable" hint="Check NEO4J_URI and credentials on the backend." />}</div>
        <div className="card"><h3 style={{ fontSize: 16, marginBottom: 12 }}>Agent activity</h3>
          {agents.length ? <div style={{ height: 260 }}><ResponsiveContainer><BarChart data={agents}><CartesianGrid stroke="rgba(157,113,232,.15)" vertical={false} /><XAxis dataKey="name" stroke="#9D71E8" fontSize={12} /><YAxis stroke="#9D71E8" fontSize={12} allowDecimals={false} /><Tooltip contentStyle={{ background: "#25134D", border: 0, borderRadius: 12, color: "#F2E9FF" }} /><Bar dataKey="value" fill="#9D71E8" radius={8} /></BarChart></ResponsiveContainer></div> : <Empty title="No agent runs yet" hint="Start a chat to see agents at work." />}</div>
      </div>
      <div className="grid g2">
        <div className="card"><h3 style={{ fontSize: 16 }}>Recent activity</h3>
          {!d.recent.length ? <Empty title="No investigations yet" hint="Ask your first question from New chat." /> : d.recent.map((r) => <Link key={r.id} href={`/investigations/${r.id}`} className="row" style={{ padding: "10px 0", borderTop: "1px solid var(--line)" }}><span className="grow">{r.question}</span><StatusBadge status={r.status} /><span className="muted small">{timeAgo(r.created_at)}</span></Link>)}</div>
        <div className="card"><h3 style={{ fontSize: 16, marginBottom: 10 }}>System status</h3>
          {([["Neo4j Aura", sys.neo4j], [`Application store (${sys.store})`, sys.mongodb], ["LLM provider key", sys.llm], ["Outbound webhook", sys.webhook]] as const).map(([n, ok]) => <div className="row" key={n} style={{ padding: "8px 0", borderTop: "1px solid var(--line)" }}><span className="grow">{n}</span><span className={`chip ${ok ? "s-ok" : "s-error"}`}><span className={`dot ${ok ? "s-ok" : "s-error"}`} />{ok ? "Connected" : "Not available"}</span></div>)}
          {sys.store === "memory" && <p className="small s-candidate">MongoDB is not configured, so history is lost when the API restarts.</p>}</div>
      </div>
    </div>
  );
}
