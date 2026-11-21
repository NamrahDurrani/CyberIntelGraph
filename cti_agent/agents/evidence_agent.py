"""Evidence Retrieval Agent: document passages and GraphRAG candidates, with
source metadata kept and duplicate passages removed. It returns evidence records,
not summaries. Candidates are always labelled 'candidate'."""

from __future__ import annotations

import hashlib
import re

from ..evidence import EvidenceStatus
from ..schemas import ClaimStatus
from ..tools import graph_tools as gt
from .base import SpecialistAgent, Workspace


class EvidenceAgent(SpecialistAgent):
    name = "evidence"

    def investigate(self, ws: Workspace, question: str) -> None:
        self._passages(ws, question)
        self._candidates(ws)

    def _passages(self, ws: Workspace, question: str) -> None:
        retriever = self.deps.retriever
        if retriever.name == "none":
            ws.limitations.append("No document retriever is configured (set RAG_RETRIEVER in .env); document search was skipped.")
            return
        hits = ws.tool(f"text_retriever({retriever.name})", retriever.retrieve, question, self.s.text_top_k)
        seen: set[str] = set()
        duplicates = 0
        for hit in hits or []:
            digest = hashlib.sha1(re.sub(r"\s+", " ", hit.text.strip().lower()).encode()).hexdigest()
            if digest in seen:
                duplicates += 1
                continue
            seen.add(digest)
            label = hit.doc_id or hit.chunk_id or "document passage"
            ws.book.add(EvidenceStatus.REPORTED_IN_DOCUMENT, "text_chunk", f"Passage from {label}", text=hit.text,
                        source=f"doc={hit.doc_id} chunk={hit.chunk_id}".strip(),
                        meta={"score": hit.score, "chunk_id": hit.chunk_id, "doc_id": hit.doc_id})
        if duplicates:
            ws.limitations.append(f"{duplicates} duplicate passage(s) removed")

    def _candidates(self, ws: Workspace) -> None:
        schema = self.deps.schema
        names = [v for vals in ws.task.identifiers.values() for v in vals] + list(ws.task.terms)
        seen: set[str] = set()
        for term in dict.fromkeys(names):
            if len(seen) >= self.s.candidate_limit:
                break
            rows = ws.tool(f"candidates_for({term})", gt.candidates_for, self.deps.runner, schema, term, self.s.candidate_limit)
            for row in rows or []:
                if row["eid"] in seen or len(seen) >= self.s.candidate_limit:
                    continue
                seen.add(row["eid"])
                p = row.get("props") or {}
                name = gt.display_name(p, schema)
                kind = next((str(p[k]) for k in ("type", "entity_type", "category") if p.get(k)), "entity")
                passage, chunk = "", ""
                for unit in row.get("units") or []:
                    passage = next((str(unit[k]) for k in schema.text_props if unit.get(k)), "")
                    chunk = str(unit.get("chunk_id") or unit.get("id") or "")
                    if passage:
                        break
                relations = []
                for rel in ws.tool(f"candidate_relations({name})", gt.candidate_relations, self.deps.runner, schema, row["eid"], 4) or []:
                    relations.append(f"{rel['rel']} {'->' if rel['outgoing'] else '<-'} {gt.display_name(rel.get('props') or {}, schema)}")
                text = gt.describe_props(p, schema, 6)
                if relations:
                    text += "\ncandidate relations: " + "; ".join(relations)
                if passage:
                    text += "\nsource passage: " + gt.trim(passage, 600)
                ev = ws.book.add(
                    EvidenceStatus.LLM_CANDIDATE, "graphrag_candidate",
                    f"GraphRAG candidate '{name}' (type: {kind}) - extracted by an LLM, not confirmed", text=text,
                    source=f"GraphRAG text unit {chunk}" if chunk else "GraphRAG extraction",
                    entities=[name], meta={"eid": row["eid"], "chunk_id": chunk})
                ws.claim(f"'{name}' was extracted as a possible {kind} (unconfirmed)", name, "extracted_candidate", kind,
                         ev.id, status=ClaimStatus.CANDIDATE, explanation="LLM-extracted by GraphRAG; not a confirmed fact.")
