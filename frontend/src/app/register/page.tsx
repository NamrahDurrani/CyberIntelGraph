"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Brand } from "@/components/Logo";
import { ErrorBox } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { User } from "@/lib/types";

export default function Register() {
  const { signIn } = useAuth(); const router = useRouter();
  const [f, setF] = useState({ name: "", email: "", password: "" });
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(null);
    if (!f.name.trim()) return setErr("Enter your name.");
    if (!/^\S+@\S+\.\S+$/.test(f.email)) return setErr("Enter a valid email address.");
    if (f.password.length < 10) return setErr("Use a password of at least 10 characters.");
    setBusy(true);
    try { const r = await api<{ token: string; user: User }>("/api/auth/register", { method: "POST", body: JSON.stringify(f) }); signIn(r.token, r.user); router.replace("/"); }
    catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  }
  return (
    <main className="auth"><form className="card" onSubmit={submit} noValidate>
      <div style={{ marginBottom: 22 }}><Brand /></div>
      <h2 style={{ marginBottom: 4 }}>Create your account</h2><p className="muted small" style={{ marginTop: 0, marginBottom: 20 }}>Start investigating with verified evidence.</p>
      <ErrorBox msg={err} />
      <label className="field">Name<input className="input" autoComplete="name" value={f.name} onChange={set("name")} /></label>
      <label className="field">Email<input className="input" type="email" autoComplete="email" value={f.email} onChange={set("email")} /></label>
      <label className="field">Password<input className="input" type="password" autoComplete="new-password" value={f.password} onChange={set("password")} /></label>
      <button className="btn btn-primary" style={{ width: "100%", justifyContent: "center" }} disabled={busy}>{busy ? "Creating…" : "Create account"}</button>
      <p className="small muted" style={{ textAlign: "center", marginBottom: 0 }}>Already registered? <Link href="/login" style={{ color: "var(--accent-2)" }}>Sign in</Link></p>
    </form></main>
  );
}
