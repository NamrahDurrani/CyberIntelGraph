export type EvidenceStatus = "confirmed" | "reported" | "inferred" | "candidate" | "not_found" | "unverified" | "unable_to_verify";
export interface Claim { claim_id: string; text: string; fact_ids: string[] }
export interface Verdict { claim_id: string; status: EvidenceStatus; confidence: number; issues: string[]; evidence_ids: string[] }
export interface Gap { agent: string; status: EvidenceStatus; detail: string }
export interface Verification { verdicts: Verdict[]; gaps: Gap[]; summary: Record<string, number>; overall: number; contradictions: string[]; needs_approval: boolean }
export interface Evidence { evidence_id: string; kind: "graph" | "document"; text: string; source?: string; date?: string; url?: string; is_candidate: boolean }
export type RunStatus = "running" | "completed" | "needs_approval" | "failed";
export interface Investigation {
  id: string; question: string; status: RunStatus; created_at: string; updated_at: string; error?: string;
  answer?: { summary: string; claims: Claim[]; limitations: string[]; generated_by: string };
  verification?: Verification; evidence?: Record<string, Evidence>; entity_ids?: string[];
}
export interface HistoryItem { id: string; question: string; status: RunStatus; created_at: string }
export interface User { id: string; email: string; name: string; prefs: { theme?: string; webhook_url?: string } }
export interface GNode { id: string; name: string; labels: string[]; candidate: boolean; props: Record<string, unknown> }
export interface GEdge { id: string; type: string; source: string; target: string; candidate: boolean; highlight?: boolean }
export interface Graph { nodes: GNode[]; edges: GEdge[] }
export interface LiveEvent { seq?: number; type: string; node?: string; status?: string; [k: string]: unknown }
export interface Dashboard {
  investigations: { total: number; by_status: Record<string, number> }; agent_runs: Record<string, number>;
  graph: { labels: Record<string, number>; relationships: Record<string, number>; nodes: number; edges: number } | null;
  recent: HistoryItem[]; system: { neo4j: boolean; mongodb: boolean; store: string; llm: boolean; webhook: boolean };
}
