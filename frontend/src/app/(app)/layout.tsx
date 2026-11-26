"use client";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Activity, Moon, PanelLeft, PanelRight, Sun } from "lucide-react";
import { PipelinePanel } from "@/components/PipelinePanel";
import { Sidebar } from "@/components/Sidebar";
import { useAuth } from "@/lib/auth";
import { ConvProvider } from "@/lib/conversations";
import { LiveProvider, useLive } from "@/lib/live";

function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { running } = useLive();
  const [left, setLeft] = useState(true); const [right, setRight] = useState(true);
  const [theme, setTheme] = useState("dark");
  useEffect(() => {
    setTheme(document.documentElement.dataset.theme ?? "dark");
    const L = localStorage.getItem("cig_left"), R = localStorage.getItem("cig_right");
    if (L) setLeft(L === "1"); if (R) setRight(R === "1");
    if (window.innerWidth < 980) { setLeft(false); setRight(false); }
  }, []);
  // left: full panel when open, slim icon rail when closed. right: pipeline panel, fully hidden when closed.
  useEffect(() => { document.documentElement.style.setProperty("--l", left ? "var(--left)" : "var(--rail)"); document.documentElement.style.setProperty("--r", right ? "var(--right)" : "0px"); }, [left, right]);
  useEffect(() => { if (window.innerWidth < 980) setLeft(false); }, [path]); // phones: close the drawer after navigating
  const toggle = (side: "l" | "r") => { const v = side === "l" ? !left : !right; (side === "l" ? setLeft : setRight)(v); localStorage.setItem(side === "l" ? "cig_left" : "cig_right", v ? "1" : "0"); };
  const flip = () => { const t = theme === "dark" ? "light" : "dark"; setTheme(t); document.documentElement.dataset.theme = t; localStorage.setItem("cig_theme", t); };
  const fit = path === "/" || path.startsWith("/chat/"); // chat screens manage their own scrolling so the page never gets a second scrollbar
  return (
    <div className="shell">
      <Sidebar expanded={left} onToggle={() => toggle("l")} />
      <div className="main">
        <header className="topbar">
          <button className="btn btn-ghost btn-icon mobile-only" onClick={() => toggle("l")} aria-label={left ? "Close sidebar" : "Open sidebar"}><PanelLeft size={16} /></button>
          <div className="grow" />{running && <span className="chip s-running"><span className="dot s-running" />Investigation running</span>}
          <button className="btn btn-ghost btn-icon" onClick={flip} aria-label="Toggle theme">{theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</button>
          <button className="btn btn-ghost btn-icon" onClick={() => toggle("r")} aria-label={right ? "Close live pipeline" : "Open live pipeline"}><PanelRight size={16} /></button>
        </header>
        <div className={`content ${fit ? "fit" : ""}`}>{children}</div>
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
  return <LiveProvider><ConvProvider><Shell>{children}</Shell></ConvProvider></LiveProvider>;
}
