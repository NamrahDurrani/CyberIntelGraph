"""Evidence model. Every fact the agent may use carries a status, so the
final answer can distinguish a confirmed fact from an LLM-extracted candidate.

Statuses follow the project roadmap (section 9, step 6)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class EvidenceStatus(str, Enum):
    CONFIRMED_AUTHORITATIVE = "confirmed_authoritative"  # canonical KEV/NVD/ATT&CK/CWE data
    REPORTED_IN_DOCUMENT = "reported_in_document"  # stated in an advisory / report passage
    LLM_CANDIDATE = "llm_candidate"  # extracted by GraphRAG, NOT confirmed
    INFERRED = "inferred"  # derived from a multi-hop path
    NOT_FOUND = "not_found"  # searched, nothing found (not proof of absence)
    UNABLE_TO_VERIFY = "unable_to_verify"  # a tool failed or data was unavailable


STATUS_LABEL = {
    EvidenceStatus.CONFIRMED_AUTHORITATIVE: "CONFIRMED (authoritative source)",
    EvidenceStatus.REPORTED_IN_DOCUMENT: "REPORTED in a document",
    EvidenceStatus.LLM_CANDIDATE: "CANDIDATE (LLM-extracted, unconfirmed)",
    EvidenceStatus.INFERRED: "INFERRED (multi-step connection)",
    EvidenceStatus.NOT_FOUND: "NOT FOUND (not proof of absence)",
    EvidenceStatus.UNABLE_TO_VERIFY: "UNABLE TO VERIFY",
}

# Order used when building prompts and reports (strongest first).
STATUS_PRIORITY = [
    EvidenceStatus.CONFIRMED_AUTHORITATIVE,
    EvidenceStatus.REPORTED_IN_DOCUMENT,
    EvidenceStatus.INFERRED,
    EvidenceStatus.LLM_CANDIDATE,
    EvidenceStatus.UNABLE_TO_VERIFY,
    EvidenceStatus.NOT_FOUND,
]


@dataclass
class Evidence:
    id: str
    status: EvidenceStatus
    kind: str
    summary: str
    text: str = ""
    source: str = ""
    entities: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        return cls(
            id=d["id"],
            status=EvidenceStatus(d["status"]),
            kind=d.get("kind", ""),
            summary=d.get("summary", ""),
            text=d.get("text", ""),
            source=d.get("source", ""),
            entities=list(d.get("entities", [])),
            meta=dict(d.get("meta", {})),
        )

    def prompt_block(self, max_text: int = 900) -> str:
        text = self.text.strip()
        if len(text) > max_text:
            text = text[: max_text - 3].rstrip() + "..."
        lines = [f"[{self.id}] status={STATUS_LABEL[self.status]} | kind={self.kind}"]
        lines.append(f"summary: {self.summary}")
        if self.source:
            lines.append(f"source: {self.source}")
        if text:
            lines.append(f"text: {text}")
        return "\n".join(lines)


class EvidenceBook:
    """Collects evidence and hands out stable ids (E1, E2, ...)."""

    def __init__(self, items: Iterable[dict[str, Any]] | None = None):
        self._items: list[Evidence] = [Evidence.from_dict(d) for d in (items or [])]

    def add(
        self,
        status: EvidenceStatus,
        kind: str,
        summary: str,
        text: str = "",
        source: str = "",
        entities: list[str] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Evidence:
        ev = Evidence(
            id=f"E{len(self._items) + 1}",
            status=status,
            kind=kind,
            summary=summary,
            text=text,
            source=source,
            entities=entities or [],
            meta=meta or {},
        )
        self._items.append(ev)
        return ev

    @property
    def items(self) -> list[Evidence]:
        return list(self._items)

    def get(self, evidence_id: str) -> Evidence | None:
        for ev in self._items:
            if ev.id == evidence_id:
                return ev
        return None

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in STATUS_PRIORITY}
        for ev in self._items:
            out[ev.status.value] += 1
        return out

    def has_content(self) -> bool:
        """True if anything other than a miss / failure was found."""
        return any(
            ev.status not in (EvidenceStatus.NOT_FOUND, EvidenceStatus.UNABLE_TO_VERIFY)
            for ev in self._items
        )

    def to_dicts(self) -> list[dict[str, Any]]:
        return [ev.to_dict() for ev in self._items]
