// CyberIntel UI text helpers (Milestone 17 frontend changes). Pure functions, no dependencies.

const ACRONYMS = new Set(["cve", "cwe", "kev", "nvd", "ttp", "ioc", "cti"]);

/** "evidence_agent" -> "Evidence agent", "cve_agent" -> "CVE agent" */
export function humanizeAgent(id: string): string {
  const base = id.replace(/[_-]?agent$/i, "").replace(/[_-]+/g, " ").trim();
  if (!base) return "Agent";
  const words = base
    .split(" ")
    .map((w) => (ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(" ");
  return `${words} agent`;
}

const UNCOUNTABLE = new Set(["malware", "software", "intelligence"]);

/** pluralize("Vulnerability") -> "Vulnerabilities", pluralize("Malware") -> "Malware" */
export function pluralize(word: string): string {
  const w = word.trim();
  const lower = w.toLowerCase();
  if (UNCOUNTABLE.has(lower) || /ies$/i.test(w)) return w;
  if (/[^aeiou]y$/i.test(w)) return w.slice(0, -1) + "ies";
  if (/(s|x|z|ch|sh)$/i.test(w)) return /s$/i.test(w) ? w : w + "es";
  return w + "s";
}

/** Card label for a graph entity type, singular or plural input: "Threat Actor" -> "Threat Actors" */
export function entityLabel(type: string): string {
  const parts = type.trim().split(/\s+/);
  const last = parts.pop() as string;
  return [...parts, pluralize(last)].join(" ");
}

export type StepStatus = "success" | "warning" | "failed" | "running";

/**
 * Evidence step status. Fallback parser for the current detail text
 * ("3 passages, 0 mention the entities"). Better: have the API return
 * `relevant_passages` and pass it as the second argument.
 */
export function evidenceStatus(detail: string, relevantPassages?: number): StepStatus {
  if (typeof relevantPassages === "number") return relevantPassages > 0 ? "success" : "warning";
  const m = /(\d+)\s+passages?,\s*(\d+)\s+mention/i.exec(detail);
  if (m) return Number(m[2]) > 0 ? "success" : "warning";
  return "success";
}

/** "4 of 4 claims confirmed (graph facts: 4, documents: 0)" */
export function describeVerification(total: number, byGraph: number, byDocs: number): string {
  const confirmed = Math.min(total, byGraph + byDocs);
  return `${confirmed} of ${total} claims confirmed (graph facts: ${byGraph}, documents: ${byDocs})`;
}
