"use client";
import { ArrowUp } from "lucide-react";
import { useRef, useState } from "react";
import { ErrorBox } from "@/components/ui";

interface Props {
  onSend: (text: string) => Promise<boolean>; // resolve true when the question was accepted (the box is then cleared)
  busy?: boolean;
  placeholder?: string;
  error?: string | null;
  autoFocus?: boolean;
}

export function Composer({ onSend, busy = false, placeholder = "Ask a threat intelligence question…", error = null, autoFocus = false }: Props) {
  const [q, setQ] = useState(""); const [local, setLocal] = useState<string | null>(null);
  const ta = useRef<HTMLTextAreaElement>(null);
  const grow = () => { const el = ta.current; if (!el) return; el.style.height = "auto"; el.style.height = Math.min(el.scrollHeight, 160) + "px"; };
  async function submit() {
    if (busy) return;
    if (q.trim().length < 5) { setLocal("Ask a complete question (at least 5 characters)."); return; }
    setLocal(null);
    if (await onSend(q.trim())) { setQ(""); requestAnimationFrame(() => { grow(); ta.current?.focus(); }); }
  }
  return (
    <>
      <div className="composer">
        <textarea ref={ta} rows={1} value={q} placeholder={placeholder} aria-label="Question" autoFocus={autoFocus}
          onChange={(e) => { setQ(e.target.value); grow(); }}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); void submit(); } }} />
        <button className="btn btn-primary btn-icon" onClick={() => void submit()} disabled={busy} aria-label="Send"><ArrowUp size={18} /></button>
      </div>
      <ErrorBox msg={local ?? error} />
    </>
  );
}
