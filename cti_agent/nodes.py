"""Workflow steps other than planning: run_agent, collect, review, assess,
generate (synthesis), check_citations, finalize.

Nodes return only the keys they change. Lists written by several steps
(agent_results, trace, warnings) are append-only, so nodes return just NEW items."""

from __future__ import annotations

import itertools
import re
import time
from typing import Any, Callable

from .agents import execute_task
from .deps import Deps
from .evidence import STATUS_LABEL, STATUS_PRIORITY, EvidenceBook, EvidenceStatus
from .llm import LLMUnavailable
from .nlp import (ID_PATTERNS, INTENT_RELS, STOPWORDS, classify_intent, extract_identifiers,  # noqa: F401 (re-exported)
                  heuristic_terms, matching_intents)
from .schemas import EVIDENCE_TO_CLAIM, Claim, ClaimStatus
from .supervisor import now_iso
from .tools import graph_tools as gt

NodeFn = Callable[[dict], dict]

ANSWER_SYSTEM = """You are the answer writer of CyberIntelGraph, an evidence-first cyber threat intelligence assistant.
You are given a question and numbered evidence blocks [E1], [E2], ... Each block has a status.

STRICT RULES
1. Use ONLY the evidence blocks. Never add facts from your own knowledge.
2. After EVERY factual statement put the supporting evidence id in square brackets, e.g. [E3] or [E3, E5].
3. Keep the statuses apart. Say what is CONFIRMED by authoritative data, what is only REPORTED in a document,
   and what is a CANDIDATE extracted by an LLM. Never present a candidate or an inferred connection as confirmed.
4. If a block says NOT FOUND or UNABLE TO VERIFY, say so plainly. "Not found" is not proof that something does not exist.
5. If the evidence does not answer the question, say what is missing instead of guessing.
6. Be concise. Finish with a one-line "Limitations:" sentence."""


def latest_results(state: dict) -> list[dict[str, Any]]:
    """Newest result per task (a retry replaces the earlier attempt), in plan order."""
    best: dict[str, dict[str, Any]] = {}
    for r in state.get("agent_results", []):
        old = best.get(r["task_id"])
        if old is None or r.get("attempt", 0) >= old.get("attempt", 0):
            best[r["task_id"]] = r
    order = [t["task_id"] for t in state.get("research_tasks", [])]
    return sorted(best.values(), key=lambda r: order.index(r["task_id"]) if r["task_id"] in order else 99)


def make_nodes(deps: Deps) -> dict[str, NodeFn]:
    s = deps.settings

    # ---------------------------------------------------------------- run_agent
    def run_agent(payload: dict) -> dict:
        result = execute_task(deps, payload["task"], payload["question"], payload.get("deadline_ts"))
        line = f"agent {result['agent_name']} [{result['task_id']}]: {result['status']} in {result['duration_ms']} ms"
        if result["attempt"]:
            line += f" (retry {result['attempt']})"
        return {"agent_results": [result], "trace": [line]}

    # ------------------------------------------------------------------ collect
    def collect(state: dict) -> dict:
        book = EvidenceBook()
        claims: list[dict[str, Any]] = []
        entities: dict[str, dict[str, Any]] = {}
        unresolved: list[str] = []
        limitations: list[str] = []
        errors: list[dict[str, str]] = []
        seen_ev: dict[tuple, str] = {}
        seen_claims: set[tuple] = set()

        for r in latest_results(state):
            idmap: dict[str, str] = {}
            for ev in r["evidence"]:
                key = (ev["kind"], ev["summary"], ev["text"])
                if key in seen_ev:                       # duplicate evidence from two agents
                    idmap[ev["id"]] = seen_ev[key]
                    continue
                new = book.add(EvidenceStatus(ev["status"]), ev["kind"], ev["summary"], ev["text"], ev["source"],
                               ev["entities"], {**ev["meta"], "agent": r["agent_name"]})
                seen_ev[key] = idmap[ev["id"]] = new.id
            for c in r["claims"]:
                ids = [idmap[i] for i in c["evidence_ids"] if i in idmap]
                sig = (c["subject"], c["predicate"], c.get("object"), tuple(ids))
                if sig in seen_claims:
                    continue
                seen_claims.add(sig)
                claims.append({**c, "evidence_ids": ids, "agent": r["agent_name"]})
            for e in r["entities"]:
                entities.setdefault(e["eid"], e)
            unresolved += r["unresolved"]
            limitations += [f"{r['agent_name']}: {x}" for x in r["limitations"]]
            errors += [{"tool": r["agent_name"], "error": e} for e in r["errors"]]

        resolved = list(entities.values())[: s.max_entities]
        found_terms = {e.get("term", "").lower() for e in resolved}
        unresolved = [u for u in dict.fromkeys(unresolved) if u.lower() not in found_terms]

        # connections between entities found by different agents
        trace: list[str] = []
        if len(resolved) >= 2:
            for a, b in list(itertools.combinations(resolved[:4], 2))[:3]:
                try:
                    path = gt.shortest_path(deps.runner, deps.schema, a["eid"], b["eid"], 3)
                except Exception as exc:  # noqa: BLE001
                    errors.append({"tool": f"path({a['name']},{b['name']})", "error": f"{type(exc).__name__}: {exc}"[:300]})
                    continue
                if not path:
                    continue
                nodes, rels = path["nodes"], path["rels"]
                chain = nodes[0]["name"] + "".join(f" -[{rel}]- {n['name']}" for rel, n in zip(rels, nodes[1:]))
                status = EvidenceStatus.CONFIRMED_AUTHORITATIVE if len(rels) == 1 else EvidenceStatus.INFERRED
                ev = book.add(status, "graph_path", f"Connection between {a['name']} and {b['name']} in {len(rels)} step(s)",
                              text=chain, source="canonical knowledge graph", entities=[a["name"], b["name"]],
                              meta={"hops": len(rels)})
                claims.append(Claim(claim_id=f"path-{len(claims) + 1}", text=f"{a['name']} is connected to {b['name']} ({len(rels)} step(s))",
                                    subject=a["name"], predicate="connected_to", object=b["name"], evidence_ids=[ev.id],
                                    status=EVIDENCE_TO_CLAIM[status],
                                    explanation="" if len(rels) == 1 else "Derived from a multi-step path, not a stated fact.").model_dump(mode="json") | {"agent": "supervisor"})
        trace.append(f"collect: {len(book.items)} evidence, {len(claims)} claims, {len(resolved)} entities, {len(errors)} error(s)")
        return {"evidence": book.to_dicts(), "claims": claims, "retrieved_entities": resolved, "resolved": resolved,
                "unresolved": unresolved, "limitations": limitations, "errors": errors, "trace": trace}

    # ------------------------------------------------------------------- review
    def review(state: dict) -> dict:
        attempts = dict(state.get("task_attempts", {}))
        tasks = {t["task_id"]: t for t in state.get("research_tasks", [])}
        in_time = time.time() < state.get("deadline_ts", float("inf"))
        retry: list[dict[str, Any]] = []
        trace: list[str] = []
        for r in latest_results(state):
            tid = r["task_id"]
            if tid not in tasks or attempts.get(tid, 0) >= s.max_retries or not in_time:
                continue
            task = tasks[tid]
            tried = {t.lower() for t in task["terms"]}
            new_terms = list(task["terms"])
            if r["status"] == "failed":
                reason = "tool failure"
            elif r["status"] == "no_results" and r["agent_name"] != "evidence" and any(u in task["terms"] for u in r["unresolved"]):
                words = [w for u in r["unresolved"] if u in task["terms"]
                         for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9\-]{3,}", u)
                         if w.lower() not in STOPWORDS and w.lower() not in tried]
                new_terms = list(dict.fromkeys(words))
                if not new_terms:
                    continue
                reason = "no match; trying the single words of the name"
            else:
                continue
            attempts[tid] = attempts.get(tid, 0) + 1
            retry.append({**task, "terms": new_terms, "attempt": attempts[tid]})
            trace.append(f"review: retry {tid} ({reason}), attempt {attempts[tid]}/{s.max_retries}")
        return {"retry_tasks": retry, "task_attempts": attempts, "trace": trace}

    def gate(state: dict) -> dict:  # join point before the optional pre-assessment hooks
        return {}

    # ------------------------------------------------------------------- assess
    def assess(state: dict) -> dict:
        book = EvidenceBook(state.get("evidence", []))
        claims = list(state.get("claims", []))

        def add_claim(text, subject, predicate, status, ev_id):
            claims.append(Claim(claim_id=f"assess-{len(claims) + 1}", text=text, subject=subject, predicate=predicate,
                                evidence_ids=[ev_id], status=status).model_dump(mode="json") | {"agent": "supervisor"})

        unresolved = state.get("unresolved", [])
        if unresolved:
            ev = book.add(EvidenceStatus.NOT_FOUND, "lookup_miss", "No match in the knowledge graph for: " + ", ".join(unresolved),
                          text="These names or identifiers were searched in the canonical graph and found nothing. "
                               "This does not prove they do not exist.", source="knowledge graph search")
            for term in unresolved:
                add_claim(f"'{term}' was not found in the knowledge graph", term, "exists_in_graph", ClaimStatus.NOT_FOUND, ev.id)
        errors = state.get("errors", [])
        if errors:
            ev = book.add(EvidenceStatus.UNABLE_TO_VERIFY, "tool_failure",
                          f"{len(errors)} lookup(s) failed, so some information could not be checked",
                          text="; ".join(f"{e['tool']}: {e['error']}" for e in errors[:5]), source="agent tools")
            add_claim("Some lookups failed; the related information is unverified", "investigation", "could_not_check",
                      ClaimStatus.UNVERIFIED, ev.id)
        return {"evidence": book.to_dicts(), "claims": claims, "evidence_summary": book.counts()}

    # ----------------------------------------------------------------- generate
    def generate(state: dict) -> dict:
        book = EvidenceBook(state.get("evidence", []))
        warnings: list[str] = []
        if not book.has_content() and any(e.status == EvidenceStatus.UNABLE_TO_VERIFY for e in book.items):
            failure = next(e for e in book.items if e.status == EvidenceStatus.UNABLE_TO_VERIFY)
            return {"answer": ("I could not complete the lookups for this question because a tool failed, so nothing could be "
                               f"verified either way. This is not evidence that the information does not exist. [{failure.id}]"),
                    "warnings": warnings}
        if not book.has_content():
            return {"answer": ("I could not find supporting information for this question in the knowledge graph "
                               "or the indexed documents. That does not prove the information does not exist; "
                               "the source data may not cover it yet."), "warnings": warnings}
        rank = {st: i for i, st in enumerate(STATUS_PRIORITY)}
        ordered = sorted(book.items, key=lambda e: (rank[e.status], int(e.id[1:])))
        blocks, used = [], 0
        for ev in ordered:
            block = ev.prompt_block()
            if used + len(block) > s.max_prompt_chars:
                warnings.append(f"Evidence trimmed for the prompt: {ev.id} and later items were left out.")
                break
            blocks.append(block)
            used += len(block)
        user = (f"Question: {state['question']}\n\nEvidence blocks:\n\n" + "\n\n".join(blocks)
                + "\n\nWrite the answer now, following the strict rules.")
        try:
            answer = deps.llm.complete(ANSWER_SYSTEM, user).strip()
            if not answer:
                raise LLMUnavailable("empty answer")
        except LLMUnavailable as exc:
            warnings.append(f"LLM unavailable ({exc}); showing the evidence without a written synthesis.")
            answer = render_fallback_answer(book)
        return {"answer": answer, "warnings": warnings}

    # --------------------------------------------------------- check_citations
    CITE = re.compile(r"\[(E\d+(?:\s*,\s*E\d+)*)\]")

    def check_citations(state: dict) -> dict:
        book = EvidenceBook(state.get("evidence", []))
        valid_ids = {e.id for e in book.items}
        used: list[str] = []
        invalid: list[str] = []

        def fix(match: re.Match) -> str:
            ids = [i.strip() for i in match.group(1).split(",")]
            good = [i for i in ids if i in valid_ids]
            invalid.extend(i for i in ids if i not in valid_ids)
            used.extend(good)
            return f"[{', '.join(good)}]" if good else "[E?]"

        answer = CITE.sub(fix, state.get("answer", ""))
        used, invalid = list(dict.fromkeys(used)), list(dict.fromkeys(invalid))
        warnings: list[str] = []
        if invalid:
            warnings.append("The answer cited evidence that does not exist: " + ", ".join(invalid) + " (marked [E?]).")
        if book.has_content() and not used:
            warnings.append("The answer contains no evidence citations; treat it as unverified.")
        return {"answer": answer, "citations_used": used, "invalid_citations": invalid, "warnings": warnings}

    # ----------------------------------------------------------------- finalize
    def finalize(state: dict) -> dict:
        from .store import get_store

        book = EvidenceBook(state.get("evidence", []))
        results = latest_results(state)
        if not book.has_content():
            status = "no_results"
        elif any(r["status"] == "failed" for r in results) or state.get("errors"):
            status = "partial"
        else:
            status = "completed"
        final = {
            "investigation_id": state.get("investigation_id"), "question": state["question"],
            "workflow_status": status, "created_at": state.get("created_at"), "finished_at": now_iso(),
            "intent": state.get("intent"), "scope": state.get("investigation_scope"),
            "plan": state.get("investigation_plan"), "selected_agents": state.get("selected_agents"),
            "answer": state.get("answer", ""),
            "entities": [{"label": r["label"], "name": r["name"], "ids": r["ids"]} for r in state.get("resolved", [])],
            "unresolved": state.get("unresolved", []),
            "claims": state.get("claims", []),
            "evidence": book.to_dicts(), "evidence_counts": book.counts(),
            "citations_used": state.get("citations_used", []), "invalid_citations": state.get("invalid_citations", []),
            "agents": [{k: r[k] for k in ("agent_name", "task_id", "status", "summary", "attempt", "duration_ms",
                                          "tool_calls", "errors", "limitations")} for r in results],
            "limitations": state.get("limitations", []),
            "warnings": state.get("warnings", []), "errors": state.get("errors", []),
            "verification": state.get("verification"), "fresh": state.get("fresh"),
            "trace": state.get("trace", []),
        }
        saved = get_store(deps).save(final)
        if saved:
            final["trace_file"] = saved
        return {"final": final, "workflow_status": status, "updated_at": now_iso()}

    return {"run_agent": run_agent, "collect": collect, "review": review, "gate": gate, "assess": assess,
            "generate": generate, "check_citations": check_citations, "finalize": finalize}


def render_fallback_answer(book: EvidenceBook) -> str:
    """Deterministic answer used when no LLM is available: evidence grouped by status."""
    lines = ["Evidence found (no written synthesis available):"]
    for status in STATUS_PRIORITY:
        group = [e for e in book.items if e.status == status]
        if not group:
            continue
        lines.append(f"\n{STATUS_LABEL[status]}:")
        for ev in group:
            lines.append(f"- {ev.summary} [{ev.id}]")
    lines.append("\nLimitations: this list is raw evidence; relationships marked CANDIDATE or INFERRED are not confirmed.")
    return "\n".join(lines)
