"""Shared machinery for the specialist agents."""

from __future__ import annotations

import time
from typing import Any, Callable

from ..deps import Deps
from ..evidence import EvidenceBook, EvidenceStatus
from ..schemas import EVIDENCE_TO_CLAIM, AgentResult, Claim, ClaimStatus, ResearchTask
from ..tools import graph_tools as gt

ATTACK_LABELS = {"AttackTechnique", "AttackTactic", "Mitigation"}
ACTOR_LABELS = {"ThreatActor", "Malware", "Tool", "Campaign"}


def source_of(props: dict[str, Any]) -> str:
    for key in ("source", "sources", "origin", "url"):
        if props.get(key):
            value = props[key]
            return ", ".join(map(str, value[:3])) if isinstance(value, (list, tuple)) else str(value)
    return "canonical knowledge graph"


class Workspace:
    """Per-task scratchpad: evidence, claims, tool-call log, errors."""

    def __init__(self, task: ResearchTask, max_calls: int):
        self.task = task
        self.book = EvidenceBook()
        self.claims: list[Claim] = []
        self.errors: list[str] = []
        self.calls: list[dict[str, Any]] = []
        self.entities: list[dict[str, Any]] = []
        self.unresolved: list[str] = []
        self.limitations: list[str] = []
        self.max_calls = max_calls

    def tool(self, label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Call a tool. A failure is recorded and returns None: it is NOT 'no results'."""
        if len(self.calls) >= self.max_calls:
            note = f"tool-call budget of {self.max_calls} reached; remaining lookups were skipped"
            if note not in self.limitations:
                self.limitations.append(note)
            return None
        started = time.monotonic()
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            message = f"{label}: {type(exc).__name__}: {exc}"[:300]
            self.errors.append(message)
            self.calls.append({"tool": label, "ok": False, "error": message,
                               "ms": int((time.monotonic() - started) * 1000)})
            return None
        size = len(result) if hasattr(result, "__len__") else None
        self.calls.append({"tool": label, "ok": True, "rows": size, "ms": int((time.monotonic() - started) * 1000)})
        return result

    def claim(self, text: str, subject: str, predicate: str, obj: str | None, evidence_id: str,
              status: ClaimStatus | None = None, explanation: str = "") -> None:
        ev = self.book.get(evidence_id)
        status = status or (EVIDENCE_TO_CLAIM[ev.status] if ev else ClaimStatus.UNVERIFIED)
        try:
            self.claims.append(Claim(claim_id=f"{self.task.task_id}-C{len(self.claims) + 1}", text=text,
                                     subject=subject, predicate=predicate, object=obj,
                                     evidence_ids=[evidence_id], status=status, explanation=explanation))
        except ValueError as exc:  # a claim that breaks the contract is dropped, never invented
            self.errors.append(f"claim rejected: {exc}")


class SpecialistAgent:
    name = "base"
    labels: list[str] = []
    preferred_rels: list[str] = []

    def __init__(self, deps: Deps):
        self.deps = deps
        self.s = deps.settings

    # ------------------------------------------------------------- hooks to override
    def lookups(self, task: ResearchTask) -> list[tuple[str, bool]]:
        out = [(v, True) for vals in task.identifiers.values() for v in vals]
        return out + [(t, False) for t in task.terms]

    def group_filter(self, ref: gt.EntityRef, group: dict[str, Any]) -> bool:
        return True

    def investigate(self, ws: Workspace, question: str) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    # --------------------------------------------------------------------- driver
    def run(self, task: ResearchTask, question: str) -> AgentResult:
        started = time.monotonic()
        ws = Workspace(task, self.s.max_tool_calls)
        try:
            self.investigate(ws, question)
        except Exception as exc:  # noqa: BLE001
            ws.errors.append(f"{type(exc).__name__}: {exc}"[:300])
        has_content = ws.book.has_content()
        status = "ok" if has_content else ("failed" if ws.errors else "no_results")
        if ws.errors and has_content:
            ws.limitations.append(f"{len(ws.errors)} lookup(s) failed, so this result may be incomplete")
        if ws.unresolved:
            ws.limitations.append("no match in the knowledge graph for: " + ", ".join(ws.unresolved))
        summary = (f"{self.name}: {len(ws.entities)} entit(ies), {len(ws.claims)} claim(s), "
                   f"{len(ws.book.items)} evidence item(s)") if has_content else f"{self.name}: nothing found"
        return AgentResult(
            agent_name=self.name, task_id=task.task_id, status=status, summary=summary, entities=ws.entities,
            claims=ws.claims, evidence=ws.book.to_dicts(), unresolved=ws.unresolved, limitations=ws.limitations,
            errors=ws.errors, tool_calls=ws.calls, duration_ms=int((time.monotonic() - started) * 1000),
            attempt=task.attempt)

    # ------------------------------------------------------------ shared behaviours
    def resolve(self, ws: Workspace, labels: list[str] | None = None) -> list[gt.EntityRef]:
        refs: list[gt.EntityRef] = []
        seen: set[str] = set()
        for term, exact in self.lookups(ws.task):
            found = ws.tool(f"find_entities({term})", gt.find_entities, self.deps.runner, self.deps.schema, term,
                            exact=exact, labels=labels or self.labels or None, limit=3)
            if found is None:
                continue
            if exact and not found:
                found = ws.tool(f"find_entities({term},partial)", gt.find_entities, self.deps.runner,
                                self.deps.schema, term, exact=False, labels=labels or self.labels or None, limit=3) or []
            exact_refs = [r for r in found if r.match == "exact"]
            chosen = exact_refs[:3] if exact_refs else found[:2]
            if not chosen:
                ws.unresolved.append(term)
                continue
            for ref in chosen:
                if ref.eid not in seen:
                    seen.add(ref.eid)
                    refs.append(ref)
        return refs[: self.s.max_entities]

    def add_profile(self, ws: Workspace, ref: gt.EntityRef) -> str:
        ident = ", ".join(f"{k}={v}" for k, v in list(ref.ids.items())[:2])
        ev = ws.book.add(
            EvidenceStatus.CONFIRMED_AUTHORITATIVE, "entity_profile",
            f"{ref.label} '{ref.name}'" + (f" ({ident})" if ident else ""),
            text=gt.describe_props(ref.props, self.deps.schema), source=source_of(ref.props),
            entities=[ref.key()], meta={"eid": ref.eid, "label": ref.label, "ids": ref.ids})
        entry = ref.to_dict()
        entry["profile"] = ev.text
        entry["source"] = ev.source
        ws.entities.append(entry)
        ws.claim(f"{ref.name} is a {ref.label} in the knowledge graph", ref.name, "is_a", ref.label, ev.id)
        return ev.id

    def add_relations(self, ws: Workspace, ref: gt.EntityRef, max_claims_per_group: int = 8) -> None:
        schema = self.deps.schema
        groups = ws.tool(f"neighbor_summary({ref.name})", gt.neighbor_summary, self.deps.runner, schema, ref.eid, None)
        if not groups:
            return
        groups = [g for g in groups if self.group_filter(ref, g)]
        groups.sort(key=lambda g: (g["rel"] not in self.preferred_rels, -g["n"]))
        for g in groups[: self.s.neighbor_groups]:
            sample = ws.tool(f"neighbor_sample({ref.name},{g['rel']})", gt.neighbor_sample, self.deps.runner, schema,
                             ref.eid, g["rel"], bool(g["outgoing"]), g["label"], self.s.neighbor_sample)
            if not sample:
                continue
            outgoing = bool(g["outgoing"])
            from_report = g["label"] == schema.report_label or g["rel"] == "MENTIONS"
            names, lines = [], []
            for row in sample:
                p = row.get("props") or {}
                name = gt.display_name(p, schema)
                ids = next(iter(gt.identifier_values(p, schema).values()), "")
                names.append(name)
                lines.append(f"- {name}" + (f" ({ids})" if ids and ids != name else ""))
            arrow = f"{ref.name} -[{g['rel']}]-> {g['label']}" if outgoing else f"{g['label']} -[{g['rel']}]-> {ref.name}"
            ev = ws.book.add(
                EvidenceStatus.REPORTED_IN_DOCUMENT if from_report else EvidenceStatus.CONFIRMED_AUTHORITATIVE,
                "report_mentions" if from_report else "graph_relations",
                f"{arrow}: {g['n']} total, showing {len(lines)}", text="\n".join(lines),
                source="advisory reports in the knowledge graph" if from_report else source_of(ref.props),
                entities=[ref.key()], meta={"rel": g["rel"], "outgoing": outgoing, "label": g["label"], "total": g["n"]})
            for other in names[:max_claims_per_group]:
                subject, obj = (ref.name, other) if outgoing else (other, ref.name)
                ws.claim(f"{subject} {g['rel']} {obj}", subject, g["rel"], obj, ev.id)
