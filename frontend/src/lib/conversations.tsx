"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "./auth";
import { useLive } from "./live";

/**
 * A conversation (chat) is an ordered list of investigations (one per question).
 * Conversations are kept in this browser (localStorage, per user). Investigations that were
 * created before this update appear as one-question chats with the id "i_<investigationId>".
 */
export interface Conversation { id: string; title: string; turns: string[]; created_at: string; updated_at: string }
export interface ConvView extends Conversation { status: string; stored: boolean }
interface Ctx {
  ready: boolean;
  list: ConvView[];
  find: (cid: string) => ConvView | null;
  byInvestigation: (invId: string) => ConvView;
  create: (question: string, invId: string) => string;
  addTurn: (cid: string, invId: string, question: string) => void;
}
const C = createContext<Ctx>(null!);
export const useConv = () => useContext(C);

const keyFor = (uid: string) => `cig_convs_${uid}`;
const MAX = 300;
function newId() {
  const r = globalThis.crypto?.randomUUID?.() ?? `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  return "c_" + r.replace(/-/g, "").slice(0, 16);
}

export function ConvProvider({ children }: { children: React.ReactNode }) {
  const { user } = useAuth(); const { history } = useLive();
  const uid = user?.id ?? null;
  const [store, setStore] = useState<{ uid: string | null; items: Conversation[] }>({ uid: null, items: [] });
  const hmap = useMemo(() => new Map(history.map((h) => [h.id, h] as const)), [history]);
  const hmapRef = useRef(hmap);
  useEffect(() => { hmapRef.current = hmap; }, [hmap]);

  useEffect(() => {
    if (!uid) return;
    let items: Conversation[] = [];
    try { const raw = localStorage.getItem(keyFor(uid)); if (raw) { const p = JSON.parse(raw); if (Array.isArray(p)) items = p; } } catch {}
    setStore({ uid, items });
  }, [uid]);
  useEffect(() => { // only write for the user whose data is loaded (never leak one user's chats into another's key)
    if (!uid || store.uid !== uid) return;
    try { localStorage.setItem(keyFor(uid), JSON.stringify(store.items)); } catch {}
  }, [store, uid]);

  const ready = !!uid && store.uid === uid;
  const stored = useMemo(() => (ready ? store.items : []), [ready, store.items]);

  const view = useCallback((c: Conversation, isStored: boolean): ConvView => {
    const latest = hmap.get(c.turns[c.turns.length - 1]);
    return { ...c, stored: isStored, status: latest?.status ?? "completed", updated_at: latest?.created_at ?? c.updated_at };
  }, [hmap]);

  const list = useMemo(() => {
    const inStored = new Set(stored.flatMap((c) => c.turns));
    const orphans = history.filter((h) => !inStored.has(h.id)).map((h) =>
      view({ id: "i_" + h.id, title: h.question, turns: [h.id], created_at: h.created_at, updated_at: h.created_at }, false));
    return [...stored.map((c) => view(c, true)), ...orphans].sort((a, b) => +new Date(b.updated_at) - +new Date(a.updated_at));
  }, [stored, history, view]);

  const find = useCallback((cid: string): ConvView | null => {
    const hit = list.find((c) => c.id === cid); if (hit) return hit;
    if (cid.startsWith("i_")) {
      const id = cid.slice(2); const h = hmap.get(id); const at = h?.created_at ?? new Date().toISOString();
      return view({ id: cid, title: h?.question ?? "Investigation", turns: [id], created_at: at, updated_at: at }, false);
    }
    return null;
  }, [list, hmap, view]);

  const byInvestigation = useCallback((invId: string): ConvView => list.find((c) => c.turns.includes(invId)) ?? find("i_" + invId)!, [list, find]);

  const create = useCallback((question: string, invId: string) => {
    const id = newId(); const now = new Date().toISOString();
    setStore((s) => ({ ...s, items: [{ id, title: question.slice(0, 120), turns: [invId], created_at: now, updated_at: now }, ...s.items].slice(0, MAX) }));
    return id;
  }, []);

  const addTurn = useCallback((cid: string, invId: string, question: string) => {
    const now = new Date().toISOString();
    setStore((s) => {
      if (s.items.some((c) => c.id === cid))
        return { ...s, items: s.items.map((c) => (c.id === cid ? { ...c, turns: c.turns.includes(invId) ? c.turns : [...c.turns, invId], updated_at: now } : c)) };
      if (cid.startsWith("i_")) { // an older single-question investigation becomes a stored chat the first time you continue it
        const first = cid.slice(2); const title = hmapRef.current.get(first)?.question ?? question;
        return { ...s, items: [{ id: cid, title: title.slice(0, 120), turns: [first, invId], created_at: now, updated_at: now }, ...s.items].slice(0, MAX) };
      }
      return s;
    });
  }, []);

  const value = useMemo(() => ({ ready, list, find, byInvestigation, create, addTurn }), [ready, list, find, byInvestigation, create, addTurn]);
  return <C.Provider value={value}>{children}</C.Provider>;
}
