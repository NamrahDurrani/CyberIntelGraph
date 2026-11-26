import * as React from "react";
import StatusIcon from "./StatusIcon";
import type { StepStatus } from "../../lib/ui-text";

export interface PipelineStepRowProps {
  title: string;
  detail?: string;
  status: StepStatus;
  ms?: number;
  note?: string; // e.g. "These passages were not used in the answer"
}

export default function PipelineStepRow({ title, detail, status, ms, note }: PipelineStepRowProps) {
  return (
    <div style={{ display: "flex", gap: 12, alignItems: "flex-start", padding: "12px 0" }}>
      <StatusIcon status={status} />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontWeight: 600, color: "#F2E9FF" }}>
          {title}
          {typeof ms === "number" && (
            <span style={{ fontWeight: 400, color: "#C9B0F5", marginLeft: 8, fontSize: 13 }}>{ms} ms</span>
          )}
        </div>
        {detail && <div style={{ color: status === "warning" ? "#FBBF24" : "#C9B0F5", fontSize: 14 }}>{detail}</div>}
        {note && <div style={{ color: "#C9B0F5", fontSize: 13, fontStyle: "italic" }}>{note}</div>}
      </div>
    </div>
  );
}
