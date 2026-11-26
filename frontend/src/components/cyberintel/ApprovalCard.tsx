"use client";
import * as React from "react";

export interface ApprovalCardProps {
  count: number;
  href?: string;
  onReview?: () => void;
}

/** First card on the dashboard: the one number that needs a human decision. */
export default function ApprovalCard({ count, href, onReview }: ApprovalCardProps) {
  const needsAction = count > 0;
  const buttonStyle: React.CSSProperties = {
    display: "inline-block",
    marginTop: 12,
    padding: "8px 18px",
    borderRadius: 999,
    background: "#6A2FC8",
    color: "#F2E9FF",
    border: "none",
    fontWeight: 600,
    cursor: "pointer",
    textDecoration: "none",
  };
  return (
    <section
      aria-label="Investigations awaiting approval"
      style={{
        borderRadius: 24,
        padding: 24,
        background: needsAction ? "#25134D" : "#160B33",
        border: `1px solid ${needsAction ? "#9D71E8" : "#25134D"}`,
      }}
    >
      <div style={{ fontSize: 44, fontWeight: 800, color: "#F2E9FF", lineHeight: 1 }}>{count}</div>
      <div style={{ color: "#D1B8FF", marginTop: 6 }}>
        {needsAction ? "Awaiting your approval" : "Nothing awaiting approval"}
      </div>
      {needsAction &&
        (href ? (
          <a href={href} style={buttonStyle}>Review now</a>
        ) : (
          <button type="button" onClick={onReview} style={buttonStyle}>Review now</button>
        ))}
    </section>
  );
}
