"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Activity, FileText, LayoutDashboard, Moon, Network, PanelLeft, PanelRight, Plus, Search, Settings, ShieldCheck, Sun, Telescope } from "lucide-react";
import { Brand } from "@/components/Logo";
import { PipelinePanel } from "@/components/PipelinePanel";
import { timeAgo } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { LiveProvider, useLive } from "@/lib/live";

const NAV = [["/dashboard", "Dashboard", LayoutDashboard], ["/explorer", "Intelligence explorer", Telescope], ["/graph", "Knowledge graph", Network],
  ["/evidence", "Evidence explorer", ShieldCheck], ["/reports", "Reports and history", FileText], ["/settings", "Settings", Settings]] as const;

function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname(); const router = useRouter();
  const { user } = useAuth(); const { history, reset, running } = useLive();
  const [left, setLeft] = useState(true); const [right, setRight] = useState(true); const [q, setQ] = useState("");
  const [theme, setTheme] = useState("dark");
  useEffect(() => {
    setTheme(document.documentElement.dataset.theme ?? "dark");
    const L = localStorage.getItem("cig_left"), R = localStorage.getItem("cig_right");
    if (L) setLeft(L === "1"); if (R) setRight(R === "1");
    if (window.innerWidth < 980) { setLeft(false); setRight(false); }
  }, []);
  useEffect(() => { document.documentElement.style.setProperty("--l", left ? "var(--left)" : "0px"); document.documentElement.style.setProperty("--r", right ? "var(--right)" : "0px"); }, [left, right]);
  const toggle = (side: "l" | "r") => { const v = side === "l" ? !left : !right; (side === "l" ? setLeft : setRight)(v); localStorage.setItem(side === "l" ? "cig_left" : "cig_right", v ? "1" : "0"); };
  const flip = () => { const t = theme === "dark" ? "light" : "dark"; setTheme(t); document.documentElement.dataset.theme = t; localStorage.setItem("cig_theme", t); };
  const list = history.filter((h) => h.question.toLowerCase().includes(q.toLowerCase()));
  const today = list.filter((h) => Date.now() - new Date(h.created_at).getTime() < 86400000), older = list.filter((h) => !today.includes(h));
  const Item = ({ h }: { h: (typeof list)[number] }) => (
    <Link href={`/investigations/${h.id}`} className={path.endsWith(h.id) ? "on" : ""} title={timeAgo(h.created_at)}>
      <span className={`dot s-${h.status}`} style={{ marginTop: 7 }} /><span className="t">{h.question}</span></Link>);
  return (
    <div className="shell">
      <aside className={`side left ${left ? "open" : ""}`} aria-label="Navigation and history"><div className="side-inner">
        <div className="row" style={{ justifyContent: "space-between" }}><Brand /></div>
        <button className="btn btn-primary" onClick={() => { reset(); router.push("/"); }}><Plus size={16} />New chat</button>
        <nav className="nav" aria-label="Main">{NAV.map(([href, label, Icon]) => <Link key={href} href={href} className={path.startsWith(href) ? "on" : ""}><Icon size={16} />{label}</Link>)}</nav>
        <div className="row" style={{ position: "relative" }}><Search size={14} style={{ position: "absolute", left: 14, opacity: .6 }} /><input className="input small" style={{ paddingLeft: 36 }} placeholder="Search snapshots" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <div className="hist" aria-label="Investigation snapshots">
          {!list.length && <div className="empty small">No snapshots yet. Your investigations appear here.</div>}
          {today.length > 0 && <div className="group">Today</div>}{today.map((h) => <Item key={h.id} h={h} />)}
          {older.length > 0 && <div className="group">Earlier</div>}{older.map((h) => <Item key={h.id} h={h} />)}
        </div>
      </div></aside>
      <div className="main">
        <header className="topbar">
          <button className="btn btn-ghost btn-icon" onClick={() => toggle("l")} aria-label={left ? "Close left sidebar" : "Open left sidebar"}><PanelLeft size={16} /></button>
          <div className="grow" />{running && <span className="chip s-running"><span className="dot s-running" />Investigation running</span>}
          <button className="btn btn-ghost btn-icon" onClick={flip} aria-label="Toggle theme">{theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</button>
          <span className="chip" title={user?.email}>{user?.name}</span>
          <button className="btn btn-ghost btn-icon" onClick={() => toggle("r")} aria-label={right ? "Close live pipeline" : "Open live pipeline"}><PanelRight size={16} /></button>
        </header>
        {children}
      </div>
      <aside className={`side right ${right ? "open" : ""}`} aria-label="Live pipeline"><div className="side-inner">
        <div className="row"><Activity size={16} /><h3 style={{ fontSize: 16 }}>Pipeline</h3><span className="muted small">live inference</span></div>
        <PipelinePanel />
      </div></aside>
    </div>
  );
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth(); const router = useRouter();
  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [loading, user, router]);
  if (loading || !user) return <div className="auth"><div className="skel" style={{ width: 220, height: 24 }} /></div>;
  return <LiveProvider><Shell>{children}</Shell></LiveProvider>;
}
