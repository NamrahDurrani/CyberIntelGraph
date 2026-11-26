"use client";
import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Graph } from "@/lib/types";
const FG = dynamic(() => import("react-force-graph-2d"), { ssr: false });
const COLORS: Record<string, string> = { ThreatActor: "#ff7b8f", Vulnerability: "#f2c35b", AttackTechnique: "#9D71E8", Malware: "#7fb2ff", Tool: "#5fd6a3", Software: "#D1B8FF", Weakness: "#e69b5a", Campaign: "#6ee0e0" };

export function GraphView({ graph, onSelect }: { graph: Graph; onSelect?: (id: string) => void }) {
  const box = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 600, h: 400 });
  useEffect(() => {
    const el = box.current; if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight })); ro.observe(el); return () => ro.disconnect();
  }, []);
  const data = useMemo(() => ({
    nodes: graph.nodes.map((n) => ({ ...n })),
    links: graph.edges.map((e) => ({ ...e })),
  }), [graph]);
  const used = [...new Set(graph.nodes.map((n) => n.labels[0]))];
  return (
    <div className="graphbox" ref={box}>
      <FG graphData={data} width={size.w} height={size.h} backgroundColor="rgba(0,0,0,0)" cooldownTicks={80}
        nodeLabel={(n: any) => `${n.name} (${n.labels.join(", ")})${n.candidate ? " - candidate" : ""}`}
        nodeCanvasObject={(n: any, ctx, scale) => {
          const r = 5; ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
          ctx.fillStyle = COLORS[n.labels[0]] ?? "#9D71E8"; ctx.fill();
          if (n.candidate) { ctx.setLineDash([2, 2]); ctx.strokeStyle = "#F2E9FF"; ctx.lineWidth = 1.2 / scale; ctx.stroke(); ctx.setLineDash([]); }
          if (scale > 1.4) { ctx.font = `${11 / scale}px sans-serif`; ctx.fillStyle = "#D1B8FF"; ctx.fillText(String(n.name).slice(0, 24), n.x + 7, n.y + 3); }
        }}
        linkColor={(l: any) => (l.highlight ? "#F2E9FF" : l.candidate ? "rgba(242,195,91,.6)" : "rgba(157,113,232,.45)")}
        linkWidth={(l: any) => (l.highlight ? 2.4 : 1)} linkLineDash={(l: any) => (l.candidate ? [3, 3] : null)}
        linkDirectionalArrowLength={3.5} linkDirectionalArrowRelPos={1} linkLabel={(l: any) => l.type}
        onNodeClick={(n: any) => onSelect?.(n.id)} />
      <div className="legend">
        {used.map((l) => <span key={l} className="chip" style={{ background: "var(--panel)" }}><span className="dot" style={{ background: COLORS[l] ?? "#9D71E8" }} />{l}</span>)}
        <span className="chip" style={{ background: "var(--panel)" }}>dashed = candidate · bright edge = cited in answer</span>
      </div>
    </div>
  );
}
