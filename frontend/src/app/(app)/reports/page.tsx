"use client";
import Link from "next/link";
import { useState } from "react";
import { Download } from "lucide-react";
import { Empty, StatusBadge, timeAgo } from "@/components/ui";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { Investigation } from "@/lib/types";

async function exportMd(id: string) {
  const i = await api<Investigation>(`/api/investigations/${id}`);
  const md = [`# ${i.question}`, "", `Status: ${i.status}`, `Overall confidence: ${Math.round((i.verification?.overall ?? 0) * 100)}%`, "", i.answer?.summary ?? "", "",
    "## Claims", ...(i.answer?.claims ?? []).map((c) => { const v = i.verification?.verdicts.find((x) => x.claim_id === c.claim_id); return `- [${v?.status ?? "unverified"}] ${c.text}`; }),
    "", "## Limitations", ...(i.answer?.limitations ?? []), ...(i.verification?.gaps ?? []).map((g) => `- ${g.status}: ${g.detail}`)].join("\n");
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" })); a.download = `report-${id.slice(0, 8)}.md`; a.click();
}
export default function Reports() {
  const { history } = useLive(); const [f, setF] = useState("all");
  const rows = history.filter((h) => f === "all" || h.status === f);
  return (
    <div className="page grid"><h2>Reports and history</h2>
      <div className="row" style={{ flexWrap: "wrap" }}>{["all", "completed", "needs_approval", "running", "failed"].map((s) => <button key={s} className={`btn ${f === s ? "btn-primary" : "btn-ghost"}`} onClick={() => setF(s)}>{s === "all" ? "All" : s.replace("_", " ")}</button>)}</div>
      <div className="card" style={{ padding: 8 }}>{!rows.length ? <Empty title="No reports here yet" hint="Completed investigations are saved automatically." /> :
        <table><thead><tr><th>Question</th><th>Status</th><th>Started</th><th /></tr></thead><tbody>{rows.map((h) => <tr key={h.id}><td><Link href={`/investigations/${h.id}`} style={{ color: "var(--accent-2)" }}>{h.question}</Link></td><td><StatusBadge status={h.status} /></td><td className="muted small">{timeAgo(h.created_at)}</td><td><button className="btn btn-ghost btn-icon" aria-label="Download report" onClick={() => exportMd(h.id)}><Download size={14} /></button></td></tr>)}</tbody></table>}</div>
    </div>
  );
}
