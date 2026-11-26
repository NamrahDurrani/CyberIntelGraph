"use client";
import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { Empty, ErrorBox, Skeleton, StatusBadge } from "@/components/ui";
import { api } from "@/lib/api";
import type { Evidence } from "@/lib/types";

export default function EvidencePage() {
  const [q, setQ] = useState(""); const [rows, setRows] = useState<Evidence[] | null>(null); const [busy, setBusy] = useState(false); const [err, setErr] = useState<string | null>(null);
  async function search(e: React.FormEvent) { e.preventDefault(); if (q.trim().length < 3) return; setBusy(true); setErr(null); try { setRows(await api<Evidence[]>(`/api/evidence/search?q=${encodeURIComponent(q)}`)); } catch (x) { setErr((x as Error).message); } finally { setBusy(false); } }
  return (
    <div className="page grid"><h2>Evidence explorer</h2><p className="muted" style={{ margin: 0 }}>Search the original source passages behind the graph. Each result keeps its source and publication date.</p>
      <form className="row" onSubmit={search}><input className="input" placeholder="e.g. CVE-2023-23397 or APT28" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search evidence" /><button className="btn btn-primary" disabled={busy}>Search</button></form>
      <ErrorBox msg={err} />{busy && <Skeleton h={90} />}
      {rows && !rows.length && <div className="card"><Empty title="No passages found" hint="A search with no results does not prove the information does not exist." /></div>}
      {rows?.map((e) => <div className="card" key={e.evidence_id}><div className="row small muted" style={{ flexWrap: "wrap" }}><span className="chip">{e.kind}</span>{e.is_candidate && <StatusBadge status="candidate" />}<span>{e.source ?? "Unknown source"}</span><span>· {e.date ?? "date not recorded"}</span>{e.url && <a href={e.url} target="_blank" rel="noreferrer noopener" style={{ color: "var(--accent-2)" }}><ExternalLink size={13} /></a>}</div><p style={{ marginBottom: 0 }}>{e.text}</p></div>)}
    </div>
  );
}
