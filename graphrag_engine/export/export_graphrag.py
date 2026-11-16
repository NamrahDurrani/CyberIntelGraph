"""Step 1 of Milestone 10 (run in .venv-graphrag): real GraphRAG parquet -> validated graph JSON.

    python graphrag_engine\\export\\export_graphrag.py

Reads data/graphrag_outputs/output/*.parquet, config/graphrag_export_rules.json, the canonical entities and the
input manifest; writes data/graphrag_outputs/export/graphrag_graph.json. Nothing is sent to Neo4j here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from graphrag_engine.export.mapping import build_export, load_rules       # noqa: E402

NAMES = ("entities", "relationships", "text_units", "documents", "communities", "community_reports")


def frame_to_rows(df) -> list[dict]:
    """parquet -> plain rows (numpy arrays become lists, NaN becomes None)."""
    rows = []
    for rec in df.to_dict("records"):
        clean = {}
        for k, v in rec.items():
            if hasattr(v, "tolist"):
                v = v.tolist()
            elif isinstance(v, float) and v != v:
                v = None
            clean[k] = v
        rows.append(clean)
    return rows


def read_json_records(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["records"]


def main():
    import pandas as pd
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join("data", "graphrag_outputs"))
    ap.add_argument("--rules", default=os.path.join("config", "graphrag_export_rules.json"))
    ap.add_argument("--canonical", default=os.path.join("data", "canonical", "entities.json"))
    ap.add_argument("--chunks", default=os.path.join("data", "processed", "advisory_chunks.jsonl"))
    a = ap.parse_args()
    out_dir = os.path.join(a.data, "output")
    frames = {}
    for n in NAMES:
        p = os.path.join(out_dir, f"{n}.parquet")
        if os.path.isfile(p):
            frames[n] = frame_to_rows(pd.read_parquet(p))
    for need in ("entities", "relationships"):
        if need not in frames:
            sys.exit(f"{need}.parquet not found in {out_dir} - has `graphrag index` finished?")
    manifest_path = os.path.join(a.data, "input_manifest.json")
    if not os.path.isfile(manifest_path):
        sys.exit(f"{manifest_path} not found - run scripts\\prepare_ms_graphrag_input.py")
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    chunk_report = {}
    if os.path.isfile(a.chunks):
        with open(a.chunks, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    c = json.loads(line)
                    if c.get("report_id"):
                        chunk_report[c["chunk_id"]] = c["report_id"]
    canonical = read_json_records(a.canonical)
    if not canonical:
        print(f"[warn] {a.canonical} not found or empty: nothing can be linked to canonical ids (all non-ID entities become candidates)")
    export = build_export(frames, load_rules(a.rules), canonical, manifest, os.path.join(a.data, "input"), chunk_report)
    export["metadata"]["generated_at"] = datetime.now(timezone.utc).isoformat()
    export["metadata"]["canonical_entities_used"] = len(canonical)
    target = os.path.join(a.data, "export", "graphrag_graph.json")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(export, fh, indent=1, ensure_ascii=False, sort_keys=True)
    os.makedirs(os.path.join("outputs", "reports"), exist_ok=True)
    with open(os.path.join("outputs", "reports", f"graphrag_export_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"), "w", encoding="utf-8") as fh:
        json.dump(export["report"], fh, indent=1)
    print(json.dumps(export["report"], indent=1))
    rep = export["report"]
    if canonical and rep["text_units"].get("mapped") and not rep["text_units_linked_to_report"]:
        reports = [e["canonical_id"] for e in canonical if e.get("entity_type") == "IntelligenceReport"][:2]
        print("[warn] no text unit could be linked to a canonical IntelligenceReport. chunk report_id example:",
              next(iter(chunk_report.values()), None), "| canonical report id examples:", reports)
    print("wrote", target)


if __name__ == "__main__":
    main()
