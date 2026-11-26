"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { FileText, LayoutDashboard, LogOut, MessageSquare, Network, PanelLeft, Search, Settings, ShieldCheck, SquarePen, Telescope } from "lucide-react";
import { Brand } from "@/components/Logo";
import { timeAgo } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { type ConvView, useConv } from "@/lib/conversations";
import { useLive } from "@/lib/live";

const NAV = [["/dashboard", "Dashboard", LayoutDashboard], ["/explorer", "Intelligence explorer", Telescope], ["/graph", "Knowledge graph", Network],
  ["/evidence", "Evidence explorer", ShieldCheck], ["/reports", "Reports and history", FileText]] as const;

function groupOf(iso: string) {
  const days = (Date.now() - new Date(iso).getTime()) / 86400000;
  return days < 1 ? "Today" : days < 2 ? "Yesterday" : days < 7 ? "Previous 7 days" : "Older";
}

/** expanded = full ChatGPT/Claude-style panel; collapsed = slim icon rail (Gemini-style). On small screens it is a drawer. */
export function Sidebar({ expanded, onToggle }: { expanded: boolean; onToggle: () => void }) {
  const path = usePathname(); const router = useRouter();
  const { user, signOut } = useAuth(); const { reset } = useLive(); const { list } = useConv();
  const [q, setQ] = useState(""); const [searching, setSearching] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (expanded && searching) input.current?.focus(); }, [expanded, searching]);

  const groups = useMemo(() => {
    const m = new Map<string, ConvView[]>();
    for (const c of list.filter((x) => x.title.toLowerCase().includes(q.toLowerCase()))) { const g = groupOf(c.updated_at); m.set(g, [...(m.get(g) ?? []), c]); }
    return [...m.entries()];
  }, [list, q]);

  const newChat = () => { reset(); router.push("/"); };
  const name = user?.name ?? "";
  const initials = name.split(/\s+/).filter(Boolean).map((w) => w[0]).slice(0, 2).join("").toUpperCase() || "?";
  const openSearch = () => { setSearching(true); if (!expanded) onToggle(); };
  const leave = () => { signOut(); router.replace("/login"); };

  return (
    <aside className={`side left ${expanded ? "open" : "rail"}`} aria-label="Navigation and chats">
      {expanded ? (
        <div className="side-inner">
          <div className="sb-head">
            <Brand /><span className="grow" />
            <button className="icon-btn" onClick={() => (searching ? (setSearching(false), setQ("")) : openSearch())} aria-label="Search chats" title="Search chats"><Search size={17} /></button>
            <button className="icon-btn" onClick={onToggle} aria-label="Close sidebar" title="Close sidebar"><PanelLeft size={17} /></button>
          </div>
          <nav className="sb-nav" aria-label="Main">
            <button className="sb-item" onClick={newChat}><SquarePen size={17} />New chat</button>
            {NAV.map(([href, label, Icon]) => <Link key={href} href={href} className={`sb-item ${path.startsWith(href) ? "on" : ""}`} aria-current={path.startsWith(href) ? "page" : undefined}><Icon size={17} />{label}</Link>)}
          </nav>
          {searching && <input ref={input} className="input small sb-search" placeholder="Search chats" aria-label="Search chats" value={q} onChange={(e) => setQ(e.target.value)} />}
          <div className="hist" aria-label="Chats">
            {!list.length && <div className="empty small">No chats yet. Ask your first question.</div>}
            {list.length > 0 && !groups.length && <div className="empty small">No chats match your search.</div>}
            {groups.map(([g, items]) => (
              <div key={g}><div className="group">{g}</div>
                {items.map((c) => (
                  <Link key={c.id} href={`/chat/${c.id}`} className={path === `/chat/${c.id}` ? "on" : ""} title={`${c.title} · ${timeAgo(c.updated_at)}`}>
                    <MessageSquare size={15} className="mi" /><span className="t">{c.title}</span>
                    {c.status !== "completed" && <span className={`dot s-${c.status}`} aria-label={c.status.replace(/_/g, " ")} />}
                  </Link>))}
              </div>))}
          </div>
          <div className="sb-foot">
            <Link href="/settings" className="profile" title="Settings and profile"><span className="avatar">{initials}</span>
              <span className="who"><b>{name}</b><small>{user?.email}</small></span></Link>
            <button className="icon-btn" onClick={leave} aria-label="Sign out" title="Sign out"><LogOut size={17} /></button>
          </div>
        </div>
      ) : (
        <div className="rail-inner">
          <button className="ri" data-tip="Open sidebar" aria-label="Open sidebar" onClick={onToggle}><PanelLeft size={19} /></button>
          <button className="ri" data-tip="New chat" aria-label="New chat" onClick={newChat}><SquarePen size={19} /></button>
          <button className="ri" data-tip="Search chats" aria-label="Search chats" onClick={openSearch}><Search size={19} /></button>
          <div className="rail-sep" />
          {NAV.map(([href, label, Icon]) => <Link key={href} href={href} className={`ri ${path.startsWith(href) ? "on" : ""}`} data-tip={label} aria-label={label}><Icon size={19} /></Link>)}
          <span className="grow" />
          <Link href="/settings" className={`ri ${path.startsWith("/settings") ? "on" : ""}`} data-tip="Settings" aria-label="Settings"><Settings size={19} /></Link>
          <Link href="/settings" className="avatar" data-tip={name || "Profile"} aria-label="Profile">{initials}</Link>
        </div>
      )}
    </aside>
  );
}
