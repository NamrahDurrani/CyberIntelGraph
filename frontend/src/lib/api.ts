import type { LiveEvent } from "./types";
export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const KEY = "cig_token";
export const token = {
  get: () => (typeof window === "undefined" ? null : localStorage.getItem(KEY)),
  set: (t: string) => localStorage.setItem(KEY, t),
  clear: () => localStorage.removeItem(KEY),
};
export class ApiError extends Error { constructor(public status: number, msg: string) { super(msg); } }

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const t = token.get();
  let res: Response;
  try {
    res = await fetch(API + path, { ...init, headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}), ...init.headers } });
  } catch { throw new ApiError(0, "Cannot reach the API. Check that the backend is running on " + API); }
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = typeof j.detail === "string" ? j.detail : j.detail?.[0]?.msg ?? msg; } catch {}
    throw new ApiError(res.status, msg);
  }
  return res.json();
}

/** Streams Server-Sent Events with the auth header (EventSource cannot send headers). */
export async function streamSSE(path: string, onEvent: (e: LiveEvent) => void, signal: AbortSignal) {
  const t = token.get();
  const res = await fetch(API + path, { headers: t ? { Authorization: `Bearer ${t}` } : {}, signal });
  if (!res.ok || !res.body) throw new ApiError(res.status, "Stream unavailable");
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const line = buf.slice(0, i).split("\n").find((l) => l.startsWith("data: "));
      buf = buf.slice(i + 2);
      if (line) { try { onEvent(JSON.parse(line.slice(6))); } catch {} }
    }
  }
}
