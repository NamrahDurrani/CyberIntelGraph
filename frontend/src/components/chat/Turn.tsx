"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Activity, FileText, Loader2, ShieldAlert } from "lucide-react";
import { ErrorBox, Skeleton, StatusBadge } from "@/components/ui";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { Investigation } from "@/lib/types";

/** One question and its verified answer inside a chat. The full report (graph, evidence) opens on its own page. */
export function Turn({ id }: { id: string }) {
  const { activeId, events, watch, refreshHistory } = useLive();
  const [inv, setInv] = useState<Investigation | null>(null); const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => api<Investigation>(`/api/investigations/${id}`).then((x) => { setInv(x); setErr(null); }).catch((e: Error) => setErr(e.message)), [id]);
  useEffect(() => { void load(); }, [load]);
  const active = activeId === id;
  const finished = active && events.some((e) => ["completed", "approval_required", "error"].includes(e.type));
  useEffect(() => { if (finished) { void load(); void refreshHistory(); } }, [finished, load, refreshHistory]);
  const status = inv?.status;
  useEffect(() => { if (status !== "running") return; const t = setInterval(() => void load(), 3000); return () => clearInterval(t); }, [status, load]);
  async function approve() {
    try { await api(`/api/investigations/${id}/approve`, { method: "POST" }); } catch (e) { setErr((e as Error).message); return; }
    void load(); void refreshHistory();
  }

  const v = inv?.verification; const verdict = (cid: string) => v?.verdicts.find((x) => x.claim_id === cid);
  const claims = inv?.answer?.claims ?? [];
  return (
    <div className="turn">
      <div className="msg user">{inv ? <div className="bubble">{inv.question}</div> : <Skeleton h={38} w="240px" />}</div>
      <div className="msg bot">
        {err ? <ErrorBox msg={err} /> : !inv ? <div className="card grid"><Skeleton h={20} w="40%" /><Skeleton /></div> :
          inv.status === "running" && !inv.answer ? (
            <div className="card row"><Loader2 size={16} className="spin" /><span className="grow muted">Agents are working. Follow each step in the Pipeline panel.</span>
              <button className="btn btn-ghost" onClick={() => watch(id)} disabled={active}><Activity size={14} />Show pipeline</button></div>
          ) : inv.status === "failed" ? <ErrorBox msg={`The investigation failed: ${inv.error ?? "unknown error"}. Ask the question again to retry.`} /> : (
            <div className="card">
              <div className="row small muted" style={{ marginBottom: 8, flexWrap: "wrap" }}>Verified answer
                {v && <span className="chip">overall confidence {Math.round(v.overall * 100)}%</span>}<span className="grow" /><StatusBadge status={inv.status} /></div>
              <p style={{ margin: 0, fontSize: 16 }}>{inv.answer?.summary ?? "No answer was produced for this question."}</p>
              <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 12 }}>{v && Object.entries(v.summary).map(([k, n]) => <span key={k} className={`chip s-${k}`}>{n} {k.replace(/_/g, " ")}</span>)}</div>
              {inv.status === "needs_approval" && (
                <div className="row approve"><ShieldAlert color="var(--warn)" /><div className="grow"><b>Analyst approval required</b>
                  <div className="small muted">Verification found contradictions, unknown identifiers or low confidence. Review the claims before relying on this answer.</div></div>
                  <button className="btn btn-primary" onClick={() => void approve()}>Approve report</button></div>)}
              <details className="more"><summary>Claims and verification ({claims.length})</summary>
                {!claims.length && <p className="small muted">No claims could be supported. This is not proof that nothing exists.</p>}
                {claims.map((c) => { const d = verdict(c.claim_id); return (
                  <div className="claim" key={c.claim_id}><div className="row" style={{ alignItems: "flex-start" }}><span className="grow">{c.text}</span>{d && <StatusBadge status={d.status} />}</div>
                    {d && <div className="small muted">Confidence {Math.round(d.confidence * 100)}% · {d.evidence_ids.length} evidence item(s){d.issues.length > 0 && <span className="s-unverified"> · {d.issues.join("; ")}</span>}</div>}</div>); })}
                {v?.contradictions.map((c, i) => <p key={i} className="s-unverified small">Contradiction: {c}</p>)}
                {inv.answer?.limitations.map((l, i) => <p key={i} className="small s-unverified">{l}</p>)}
                {v?.gaps.map((g, i) => <p key={i} className="small row"><StatusBadge status={g.status} />{g.detail}</p>)}
              </details>
              <div className="row actions">
                <Link className="btn btn-ghost" href={`/investigations/${id}`}><FileText size={14} />Open full report, graph and evidence</Link>
                <button className="btn btn-ghost" onClick={() => watch(id)} disabled={active}><Activity size={14} />Show pipeline</button>
              </div>
            </div>)}
      </div>
    </div>
  );
}
