"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { api, streamSSE } from "./api";
import type { HistoryItem, LiveEvent } from "./types";

interface Live {
  activeId: string | null; events: LiveEvent[]; running: boolean;
  history: HistoryItem[]; refreshHistory: () => Promise<void>;
  watch: (id: string) => void; start: (q: string) => Promise<string>; reset: () => void;
}
const Ctx = createContext<Live>(null!);
export const useLive = () => useContext(Ctx);

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const [activeId, setActive] = useState<string | null>(null);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const ctl = useRef<AbortController | null>(null);

  const refreshHistory = useCallback(async () => { try { setHistory(await api<HistoryItem[]>("/api/investigations")); } catch {} }, []);
  useEffect(() => { refreshHistory(); }, [refreshHistory]);

  const watch = useCallback((id: string) => {
    ctl.current?.abort();
    const c = new AbortController(); ctl.current = c;
    setActive(id); setEvents([]); setRunning(true);
    streamSSE(`/api/investigations/${id}/events`, (e) => {
      if (e.type === "stream_end") { setRunning(false); refreshHistory(); return; }
      setEvents((p) => [...p, e]);
    }, c.signal).catch(() => setRunning(false)).finally(() => setRunning(false));
  }, [refreshHistory]);

  const start = useCallback(async (q: string) => {
    const { id } = await api<{ id: string }>("/api/investigations", { method: "POST", body: JSON.stringify({ question: q }) });
    watch(id); refreshHistory(); return id;
  }, [watch, refreshHistory]);

  const reset = useCallback(() => { ctl.current?.abort(); setActive(null); setEvents([]); setRunning(false); }, []);
  return <Ctx.Provider value={{ activeId, events, running, history, refreshHistory, watch, start, reset }}>{children}</Ctx.Provider>;
}
