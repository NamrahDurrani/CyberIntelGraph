"use client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Composer } from "@/components/chat/Composer";
import { ErrorBox } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { useConv } from "@/lib/conversations";
import { useLive } from "@/lib/live";

const IDEAS = ["Which techniques does APT28 use?", "What is known about CVE-2023-23397?", "Which vulnerabilities are linked to a ransomware group?", "Show evidence for T1059 usage"];

/** First question of a new chat: the composer sits in the middle of the page. After sending, the chat opens with the composer docked at the bottom. */
export default function NewChat() {
  const { user } = useAuth(); const { start, reset } = useLive(); const { create } = useConv(); const router = useRouter();
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const [greet, setGreet] = useState("Hello");
  useEffect(() => { reset(); const h = new Date().getHours(); setGreet(h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening"); }, [reset]);
  async function go(text: string): Promise<boolean> {
    setBusy(true); setErr(null);
    try { const id = await start(text.trim()); router.push(`/chat/${create(text.trim(), id)}`); return true; }
    catch (e) { setErr((e as Error).message); setBusy(false); return false; }
  }
  return (
    <section className="hero">
      <h1>{greet}, {user?.name.split(" ")[0]}</h1>
      <p className="muted" style={{ margin: "-14px 0 0" }}>What should we investigate? Every answer is checked against evidence.</p>
      <div className="hero-composer"><Composer onSend={go} busy={busy} autoFocus /></div>
      {err && <ErrorBox msg={err} />}
      <div className="suggest">{IDEAS.map((i) => <button key={i} disabled={busy} onClick={() => void go(i)}>{i}</button>)}</div>
    </section>
  );
}
