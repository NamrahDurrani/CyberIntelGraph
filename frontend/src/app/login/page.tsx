"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Brand } from "@/components/Logo";
import { ErrorBox } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { User } from "@/lib/types";

export default function Login() {
  const { signIn } = useAuth(); const router = useRouter();
  const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setErr(null);
    if (!/^\S+@\S+\.\S+$/.test(email)) return setErr("Enter a valid email address.");
    if (!password) return setErr("Enter your password.");
    setBusy(true);
    try { const r = await api<{ token: string; user: User }>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }); signIn(r.token, r.user); router.replace("/"); }
    catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  }
  return (
    <main className="auth"><form className="card" onSubmit={submit} noValidate>
      <div style={{ marginBottom: 22 }}><Brand /></div>
      <h2 style={{ marginBottom: 4 }}>Sign in</h2><p className="muted small" style={{ marginTop: 0, marginBottom: 20 }}>Continue your investigations.</p>
      <ErrorBox msg={err} />
      <label className="field">Email<input className="input" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
      <label className="field">Password<input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
      <button className="btn btn-primary" style={{ width: "100%", justifyContent: "center" }} disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      <p className="small muted" style={{ textAlign: "center", marginBottom: 0 }}>New here? <Link href="/register" style={{ color: "var(--accent-2)" }}>Create an account</Link></p>
    </form></main>
  );
}
