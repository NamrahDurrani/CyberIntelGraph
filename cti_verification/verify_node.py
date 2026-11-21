"""Workflow step that runs the verification agent after the answer is written
('post_generate' hook). On a FAIL outcome it asks the writer for ONE corrected
answer (bounded by VERIFY_MAX_REWRITES) and keeps it only if it verifies better."""

from __future__ import annotations

import re
from typing import Any, Callable

from cti_agent.deps import Deps
from cti_agent.evidence import EvidenceBook, STATUS_PRIORITY
from cti_agent.llm import LLMUnavailable, NullLLM
from cti_agent.nodes import ANSWER_SYSTEM, latest_results

from .settings import VerifySettings
from .verification_agent import FAIL_, run_verification
from .verifier import CITE

NodeFn = Callable[[dict], dict]


def _badness(rep: dict[str, Any]) -> float:
    c = rep["answer_counts"]
    return c["unsupported"] + c["uncited"] + 0.5 * c["partial"] + len(rep["claim_checks"])


def _rewrite(deps: Deps, state: dict, rep: dict[str, Any]) -> str | None:
    book = EvidenceBook(state.get("evidence", []))
    rank = {st: i for i, st in enumerate(STATUS_PRIORITY)}
    blocks, used = [], 0
    for ev in sorted(book.items, key=lambda e: (rank[e.status], int(e.id[1:]))):
        block = ev.prompt_block()
        if used + len(block) > deps.settings.max_prompt_chars:
            break
        blocks.append(block)
        used += len(block)
    flagged = [f"- {r['text']}  (problem: {'; '.join(r['reasons']) or r['verdict']})"
               for r in rep["answer_results"] if r["verdict"] != "supported"][:10]
    user = (f"Question: {state['question']}\n\nEvidence blocks:\n\n" + "\n\n".join(blocks)
            + "\n\nA reviewer found these statements in your previous answer NOT supported by their cited evidence:\n"
            + "\n".join(flagged) + "\n\nWrite a corrected answer. Remove or clearly qualify every flagged statement, "
              "keep only what the evidence states, cite [E#] after every statement, follow the strict rules.")
    try:
        text = deps.llm.complete(ANSWER_SYSTEM, user).strip()
    except LLMUnavailable:
        return None
    valid = {e.id for e in book.items}

    def fix(m: re.Match) -> str:
        ids = [i.strip() for i in m.group(1).split(",")]
        good = [i for i in ids if i in valid]
        return f"[{', '.join(good)}]" if good else "[E?]"

    return CITE.sub(fix, text) if text else None


def make_verify_node(deps: Deps) -> NodeFn:
    vs: VerifySettings = deps.extras.get("verify_settings") or VerifySettings.from_env()

    def verify(state: dict) -> dict:
        failures = sum(1 for r in latest_results(state) if r["status"] == "failed")

        def run(answer: str) -> dict[str, Any]:
            return run_verification(
                question=state["question"], answer=answer, claims=state.get("claims", []),
                evidence=state.get("evidence", []), fresh=state.get("fresh"), unresolved=state.get("unresolved", []),
                agent_failures=failures, llm=deps.llm, use_llm_judge=vs.use_llm_judge, min_overlap=vs.min_overlap)

        rep = run(state.get("answer", ""))
        rewrites = 0
        if rep["outcome"] == FAIL_ and not isinstance(deps.llm, NullLLM) and EvidenceBook(state.get("evidence", [])).has_content():
            for _ in range(vs.max_rewrites):
                new_answer = _rewrite(deps, state, rep)
                if not new_answer:
                    break
                candidate = run(new_answer)
                if _badness(candidate) < _badness(rep):
                    rep, rewrites = candidate, rewrites + 1
                else:
                    break
        answer = rep.pop("annotated_answer")
        rep["rewrites"] = rewrites
        bad_ids = {c["claim_id"]: c for c in rep["claim_checks"]}
        claims = [{**c, "verified_status": bad_ids[c["claim_id"]]["effective_status"] if c["claim_id"] in bad_ids else c["status"],
                   "verification_issues": bad_ids[c["claim_id"]]["issues"] if c["claim_id"] in bad_ids else []}
                  for c in state.get("claims", [])]
        warnings = [rep["headline"]] if rep["outcome"] != "PASS" else []
        return {"answer": answer, "verification": rep, "claims": claims, "warnings": warnings}

    return verify
