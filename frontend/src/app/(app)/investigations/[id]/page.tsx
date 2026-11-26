"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { GraphView } from "@/components/GraphView";
import { Empty, ErrorBox, Skeleton, StatusBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { useConv } from "@/lib/conversations";
import { useLive } from "@/lib/live";
import type { Graph, Investigation } from "@/lib/types";

export default function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const { activeId, events, watch, refreshHistory } = useLive();
  const { byInvestigation } = useConv(); const chat = byInvestigation(id);
  const back = <Link href={`/chat/${chat.id}`} className="muted small">← Back to chat</Link>;
  const [inv, setInv] = useState<Investigation | null>(null); const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<"answer" | "graph" | "evidence">("answer");
  const [graph, setGraph] = useState<Graph>({ nodes: [], edges: [] }); const [gErr, setGErr] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const load = useCallback(() => api<Investigation>(`/api/investigations/${id}`).then(setInv).catch((e) => setErr(e.message)), [id]);
  useEffect(() => { if (activeId !== id) watch(id); load(); }, [id]); // eslint-disable-line react-hooks/exhaustive-deps
  const terminal = events.some((e) => ["completed", "approval_required", "error"].includes(e.type));
  useEffect(() => { if (terminal) load(); }, [terminal, load]);
  // live graph: refetch (debounced) whenever agents report new entities, and once more when the answer is final
  const entityEvents = events.filter((e) => e.type === "entities").length;
  useEffect(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => api<Graph>(`/api/investigations/${id}/graph`).then((g) => { setGraph(g); setGErr(null); }).catch((e) => setGErr(e.message)), 400);
  }, [id, entityEvents, terminal]);

  async function approve() { await api(`/api/investigations/${id}/approve`, { method: "POST" }); load(); refreshHistory(); }
  if (err) return <div className="page grid">{back}<ErrorBox msg={err} /></div>;
  if (!inv) return <div className="page grid">{back}<Skeleton h={32} w="60%" /><Skeleton h={120} /><Skeleton h={220} /></div>;
  const v = inv.verification; const verdict = (cid: string) => v?.verdicts.find((x) => x.claim_id === cid);
  const evs = Object.values(inv.evidence ?? {});
  return (
    <div className="page">
      {back}
      <div className="row" style={{ gap: 12, flexWrap: "wrap" }}><h2 className="grow">{inv.question}</h2><StatusBadge status={inv.status} /></div>
      <div className="tabs" role="tablist">{(["answer", "graph", "evidence"] as const).map((t) => <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>{t === "answer" ? "Report" : t === "graph" ? "Live knowledge graph" : `Evidence (${evs.length})`}</button>)}</div>

      {tab === "answer" && (inv.status === "running" && !inv.answer ? <div className="card grid"><Skeleton h={22} w="40%" /><Skeleton /><Skeleton /><p className="muted small">Agents are working. Follow each step in the Pipeline panel.</p></div> :
        inv.status === "failed" ? <ErrorBox msg={`The investigation failed: ${inv.error ?? "unknown error"}. Start a new chat to retry.`} /> :
        <div className="grid">
          {inv.status === "needs_approval" && <div className="card row" style={{ borderColor: "var(--warn)" }}><ShieldAlert color="var(--warn)" /><div className="grow"><b>Analyst approval required</b><div className="small muted">Verification found contradictions, unknown identifiers or low confidence. Review the claims below before relying on this report.</div></div><button className="btn btn-primary" onClick={approve}>Approve report</button></div>}
          <div className="card"><div className="row small muted" style={{ marginBottom: 8 }}>Verified answer {v && <span className="chip">overall confidence {Math.round(v.overall * 100)}%</span>}</div>
            <p style={{ margin: 0, fontSize: 16 }}>{inv.answer?.summary}</p>
            <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 12 }}>{v && Object.entries(v.summary).map(([k, n]) => <span key={k} className={`chip s-${k}`}>{n} {k.replace(/_/g, " ")}</span>)}</div></div>
          <div className="card"><h3 style={{ fontSize: 16 }}>Claims and verification</h3>
            {!inv.answer?.claims.length && <Empty title="No claims could be supported" hint="This is not proof that nothing exists. See limitations below." />}
            {inv.answer?.claims.map((c) => { const d = verdict(c.claim_id); return (
              <div className="claim" key={c.claim_id}><div className="row" style={{ alignItems: "flex-start" }}><span className="grow">{c.text}</span>{d && <StatusBadge status={d.status} />}</div>
                {d && <div className="small muted">Confidence {Math.round(d.confidence * 100)}% · {d.evidence_ids.length} evidence item(s){d.issues.length > 0 && <span className="s-unverified"> · {d.issues.join("; ")}</span>}</div>}</div>); })}
          </div>
          {(v?.gaps.length || inv.answer?.limitations.length || v?.contradictions.length) ? <div className="card"><h3 style={{ fontSize: 16 }}>Limitations</h3>
            {v?.contradictions.map((c, i) => <p key={i} className="s-unverified small">Contradiction: {c}</p>)}
            {inv.answer?.limitations.map((l, i) => <p key={i} className="small s-unverified">{l}</p>)}
            {v?.gaps.map((g, i) => <p key={i} className="small row"><StatusBadge status={g.status} />{g.detail}</p>)}</div> : null}
        </div>)}

      {tab === "graph" && <>
        <ErrorBox msg={gErr && `Graph unavailable: ${gErr}`} />
        {graph.nodes.length ? <GraphView graph={graph} /> : <div className="card"><Empty title={inv.status === "running" ? "Waiting for agents to find entities…" : "No graph entities for this question"} hint="Entities appear here live as agents query Neo4j." /></div>}
        <p className="small muted">{graph.nodes.length} nodes · {graph.edges.length} relationships. Bright edges are the relationships cited by the answer.</p></>}

      {tab === "evidence" && <div className="grid">{!evs.length && <div className="card"><Empty title="No evidence collected" /></div>}
        {evs.map((e) => <div className="card" key={e.evidence_id}><div className="row small muted"><span className="chip">{e.kind}</span>{e.is_candidate && <StatusBadge status="candidate" />}<span>{e.source}</span>{e.date && <span>· {e.date}</span>}{e.url && <a href={e.url} target="_blank" rel="noreferrer noopener" style={{ color: "var(--accent-2)" }}><ExternalLink size={13} /></a>}</div><p style={{ marginBottom: 0 }}>{e.text}</p></div>)}</div>}
    </div>
  );
}
