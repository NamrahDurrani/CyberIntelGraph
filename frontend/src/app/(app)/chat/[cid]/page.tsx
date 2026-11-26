"use client";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { Composer } from "@/components/chat/Composer";
import { Turn } from "@/components/chat/Turn";
import { Empty, Skeleton } from "@/components/ui";
import { useConv } from "@/lib/conversations";
import { useLive } from "@/lib/live";

export default function ChatPage() {
  const { cid } = useParams<{ cid: string }>();
  const { find, addTurn, ready } = useConv(); const { start, running, activeId, watch } = useLive();
  const conv = find(cid);
  const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const thread = useRef<HTMLDivElement>(null); const inner = useRef<HTMLDivElement>(null);
  const stick = useRef(true); const watched = useRef<string | null>(null); const lastTop = useRef(0);
  const last = conv?.turns[conv.turns.length - 1];

  // opening a chat shows its newest question in the Pipeline panel (only once per chat, so sending a new question is never overridden)
  useEffect(() => {
    if (!last || watched.current === cid) return;
    watched.current = cid; stick.current = true;
    if (activeId !== last) watch(last);
  }, [cid, last, activeId, watch]);

  // keep the newest message in view, unless you scrolled up to read earlier answers
  const toBottom = useCallback(() => { const el = thread.current; if (el) el.scrollTo({ top: el.scrollHeight }); }, []);
  const hasConv = !!conv;
  useEffect(() => {
    const el = inner.current; if (!el) return;
    const ro = new ResizeObserver(() => { if (stick.current) toBottom(); }); ro.observe(el);
    return () => ro.disconnect();
  }, [hasConv, toBottom]);

  async function send(text: string): Promise<boolean> {
    setBusy(true); setErr(null); stick.current = true;
    try { const id = await start(text); addTurn(cid, id, text); return true; }
    catch (e) { setErr((e as Error).message); return false; }
    finally { setBusy(false); }
  }

  if (!conv) return ready
    ? <div className="page"><Empty title="Chat not found" hint="Chats are stored in this browser. Start a new chat from the sidebar." /><p style={{ textAlign: "center" }}><Link href="/" className="btn btn-primary">New chat</Link></p></div>
    : <div className="page grid"><Skeleton h={32} w="50%" /><Skeleton h={140} /></div>;

  return (
    <div className="chat">
      <div className="thread" ref={thread} onScroll={(e) => { const el = e.currentTarget; // follow the newest answer until you scroll UP; scrolling back near the bottom resumes it
          if (el.scrollHeight - el.scrollTop - el.clientHeight < 120) stick.current = true; else if (el.scrollTop < lastTop.current - 2) stick.current = false; lastTop.current = el.scrollTop; }}>
        <div className="thread-inner" ref={inner}>{conv.turns.map((id) => <Turn key={id} id={id} />)}</div>
      </div>
      <div className="dock"><div className="dock-inner">
        <Composer onSend={send} busy={busy || running} error={err} autoFocus
          placeholder={running ? "Wait for the current investigation to finish…" : "Ask another question…"} />
        <p className="dock-hint">Each question is investigated on its own, so name the CVE, actor or technique you mean.</p>
      </div></div>
    </div>
  );
}
