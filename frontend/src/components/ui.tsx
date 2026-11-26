import type { EvidenceStatus } from "@/lib/types";
const LABEL: Record<string, string> = { confirmed: "Confirmed", reported: "Reported", inferred: "Inferred", candidate: "Candidate", not_found: "Not found", unverified: "Unverified", unable_to_verify: "Unable to verify",
  running: "Running", completed: "Completed", needs_approval: "Needs approval", failed: "Failed" };
export function StatusBadge({ status }: { status: EvidenceStatus | string }) {
  return <span className={`chip s-${status}`}><span className={`dot s-${status}`} />{LABEL[status] ?? status}</span>;
}
export const Skeleton = ({ h = 18, w = "100%" }: { h?: number; w?: string }) => <div className="skel" style={{ height: h, width: w }} />;
export const ErrorBox = ({ msg }: { msg: string | null }) => (msg ? <div className="err" role="alert">{msg}</div> : null);
export const Empty = ({ title, hint }: { title: string; hint?: string }) => <div className="empty"><b>{title}</b>{hint && <div className="small">{hint}</div>}</div>;
export function timeAgo(iso: string) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now"; if (s < 3600) return `${Math.floor(s / 60)} min ago`; if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}
