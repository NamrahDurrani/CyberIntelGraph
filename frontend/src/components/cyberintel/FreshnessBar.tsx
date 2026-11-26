import * as React from "react";

export interface FreshnessItem {
  label: string; // "CISA KEV catalog"
  value: string; // "2026.10.30"
}

/** One-line "data as of" strip. Stale CTI data is the real risk, so show it on the dashboard. */
export default function FreshnessBar({ items }: { items: FreshnessItem[] }) {
  if (!items.length) return null;
  return (
    <div role="status" style={{ color: "#C9B0F5", fontSize: 13, display: "flex", flexWrap: "wrap", gap: "4px 16px" }}>
      <span style={{ color: "#D1B8FF", fontWeight: 600 }}>Data as of</span>
      {items.map((i) => (
        <span key={i.label}>
          {i.label}: <strong style={{ color: "#F2E9FF", fontWeight: 600 }}>{i.value}</strong>
        </span>
      ))}
    </div>
  );
}
