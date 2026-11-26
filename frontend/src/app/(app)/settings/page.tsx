"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ErrorBox } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { User } from "@/lib/types";

export default function Settings() {
  const { user, setUser, signOut } = useAuth(); const router = useRouter();
  const [name, setName] = useState(user?.name ?? ""); const [hook, setHook] = useState(user?.prefs.webhook_url ?? "");
  const [msg, setMsg] = useState<string | null>(null); const [err, setErr] = useState<string | null>(null);
  async function save(e: React.FormEvent) {
    e.preventDefault(); setErr(null); setMsg(null);
    try { setUser(await api<User>("/api/auth/me", { method: "PATCH", body: JSON.stringify({ name, prefs: { webhook_url: hook } }) })); setMsg("Settings saved."); } catch (x) { setErr((x as Error).message); }
  }
  async function test() { setErr(null); setMsg(null); try { const r = await api<{ delivered: boolean }>("/api/webhooks/test", { method: "POST" }); r.delivered ? setMsg("Test event delivered.") : setErr("The endpoint did not accept the test event."); } catch (x) { setErr((x as Error).message); } }
  return (
    <div className="page grid" style={{ maxWidth: 640 }}><h2>Settings and profile</h2>
      <form className="card" onSubmit={save}>
        <ErrorBox msg={err} />{msg && <p className="s-ok small">{msg}</p>}
        <label className="field">Email<input className="input" value={user?.email} disabled /></label>
        <label className="field">Name<input className="input" value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="field">Webhook URL<input className="input" placeholder="https://example.com/hooks/cyberintel" value={hook} onChange={(e) => setHook(e.target.value)} />
          <span className="muted small" style={{ fontWeight: 400 }}>Receives a signed event when an investigation completes or needs approval.</span></label>
        <div className="row"><button className="btn btn-primary">Save changes</button><button type="button" className="btn btn-ghost" onClick={test}>Send test event</button></div>
      </form>
      <button className="btn btn-ghost" style={{ justifySelf: "start" }} onClick={() => { signOut(); router.replace("/login"); }}>Sign out</button>
    </div>
  );
}
