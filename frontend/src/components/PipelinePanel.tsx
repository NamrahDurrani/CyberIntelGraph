"use client";
import { Check, CircleDashed, Loader2, RotateCcw, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { useLive } from "@/lib/live";
import type { LiveEvent } from "@/lib/types";
import { Empty } from "./ui";

const NAMES: Record<string, string> = { plan: "Supervisor: plan", actor_agent: "Threat actor agent", cve_agent: "CVE agent", attack_agent: "ATT&CK agent",
  evidence_agent: "Evidence retrieval agent", synthesize: "Answer synthesis", verify: "Independent verification" };
interface Step { key: string; node: string; state: "run" | "ok" | "empty" | "error"; note?: string; ms?: number; attempt: number }

export function derive(events: LiveEvent[]) {
  const steps: Step[] = []; const notes: string[] = []; let done = false;
  for (const e of events) {
    const attempt = Number(e.attempt ?? 0);
    if (e.type === "plan") steps.push({ key: "plan", node: "plan", state: "ok", note: `Agents: ${(e.agents as string[]).join(", ")}`, attempt: 0 });
    if (e.type === "node_started" && e.node) steps.push({ key: `${e.node}${attempt}${steps.length}`, node: e.node, state: "run", attempt });
    if (e.type === "node_finished" && e.node) {
      const s = [...steps].reverse().find((x) => x.node === e.node && x.state === "run");
      const st = e.status === "error" ? "error" : e.status === "empty" ? "empty" : "ok";
      if (s) { s.state = st; s.note = (e.error as string) || (e.summary as string); s.ms = e.duration_ms as number; }
    }
    if (e.type === "verification") notes.push(`Verified: ${Object.entries(e.summary as Record<string, number>).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ") || "no claims"}`);
    if (e.type === "retry") notes.push(`Retrying ${(e.agents as string[]).join(", ")} (attempt ${e.attempt})`);
    if (["completed", "approval_required", "error"].includes(e.type)) done = true;
  }
  return { steps, notes, done };
}

export function PipelinePanel() {
  const { events, running, activeId } = useLive();
  const { steps, notes } = derive(events);
  return (
    <div className="grid" style={{ gap: 4, overflow: "auto", flex: 1 }}>
      {!activeId && <Empty title="No investigation running" hint="Start a chat and each agent step will stream here as it executes." />}
      {steps.map((s, i) => (
        <div className="step" key={i}>
          <span className="ic">{s.state === "run" ? <Loader2 size={12} className="spin" /> : s.state === "ok" ? <Check size={12} color="var(--ok)" /> : s.state === "error" ? <X size={12} color="var(--bad)" /> : <CircleDashed size={12} />}</span>
          <div><b className="small">{NAMES[s.node] ?? s.node}{s.attempt > 0 && <span className="muted"> · retry {s.attempt}</span>}</b>
            <div className={`small ${s.state === "error" ? "s-error" : "muted"}`}>{s.note ?? (s.state === "run" ? "Working…" : "")}{s.ms !== undefined && ` (${s.ms} ms)`}</div></div>
        </div>
      ))}
      {notes.map((n, i) => <div key={i} className="step"><span className="ic">{n.startsWith("Retrying") ? <RotateCcw size={12} /> : <ShieldCheck size={12} />}</span><span className="small">{n}</span></div>)}
      {running && <div className="small muted row" style={{ padding: 8 }}><Loader2 size={14} className="spin" />Streaming live from the API…</div>}
      {events.some((e) => e.type === "approval_required") && <div className="err row"><TriangleAlert size={16} />Human approval required before this report is marked complete.</div>}
      <style>{`.spin{animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}
