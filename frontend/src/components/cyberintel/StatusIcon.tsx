import * as React from "react";
import type { StepStatus } from "../../lib/ui-text";

const COLORS: Record<StepStatus, string> = {
  success: "#4ADE80",
  warning: "#FBBF24",
  failed: "#F87171",
  running: "#9D71E8",
};
const LABELS: Record<StepStatus, string> = {
  success: "Completed",
  warning: "Completed with a warning",
  failed: "Failed",
  running: "Running",
};

/** Status is conveyed by shape AND colour AND a text label for screen readers. */
export default function StatusIcon({ status, size = 22 }: { status: StepStatus; size?: number }) {
  const c = COLORS[status];
  return (
    <span role="img" aria-label={LABELS[status]} style={{ display: "inline-flex", flex: "none" }}>
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="10.5" stroke={c} strokeWidth="1.5" opacity="0.5" />
        {status === "success" && <path d="M7 12.5l3.2 3.2L17 9" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />}
        {status === "warning" && (
          <>
            <path d="M12 7v6" stroke={c} strokeWidth="2" strokeLinecap="round" />
            <circle cx="12" cy="16.5" r="1.2" fill={c} />
          </>
        )}
        {status === "failed" && <path d="M8 8l8 8M16 8l-8 8" stroke={c} strokeWidth="2" strokeLinecap="round" />}
        {status === "running" && <path d="M12 6a6 6 0 016 6" stroke={c} strokeWidth="2" strokeLinecap="round" />}
      </svg>
    </span>
  );
}
