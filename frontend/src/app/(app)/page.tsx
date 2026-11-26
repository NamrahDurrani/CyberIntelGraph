"use client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowUp } from "lucide-react";
import { ErrorBox } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { useLive } from "@/lib/live";

const IDEAS = ["Which techniques does APT28 use?", "What is known about CVE-2023-23397?", "Which vulnerabilities are linked to a ransomware group?", "Show evidence for T1059 usage"];

export default function NewChat() {
  const { user } = useAuth(); const { start, reset } = useLive(); const router = useRouter();
  const [q, setQ] = useState(""); const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const [greet, setGreet] = useState("Hello");
  useEffect(() => { reset(); const h = new Date().getHours(); setGreet(h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening"); }, [reset]);
  async function go(text = q) {
    if (text.trim().length < 5) return setErr("Ask a complete question (at least 5 characters).");
    setBusy(true); setErr(null);
    try { router.push(`/investigations/${await start(text.trim())}`); } catch (e) { setErr((e as Error).message); setBusy(false); }
  }
  return (
    <section className="hero">
      <h1>{greet}, {user?.name.split(" ")[0]}</h1>
      <p className="muted" style={{ margin: "-14px 0 0" }}>What should we investigate? Every answer is checked against evidence.</p>
      <div className="composer">
        <textarea rows={1} value={q} placeholder="Ask a threat intelligence question…" aria-label="Question" onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); go(); } }} />
        <button className="btn btn-primary btn-icon" onClick={() => go()} disabled={busy} aria-label="Investigate"><ArrowUp size={18} /></button>
      </div>
      <ErrorBox msg={err} />
      <div className="suggest">{IDEAS.map((i) => <button key={i} onClick={() => { setQ(i); go(i); }}>{i}</button>)}</div>
    </section>
  );
}
