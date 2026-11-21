"""Typed contracts between the supervisor and the specialist agents (Pydantic).

State stored in the graph is plain JSON (model_dump), so checkpoints stay
serialisable; the models are used to VALIDATE what an agent returns."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from .evidence import EvidenceStatus


class ClaimStatus(str, Enum):
    DOCUMENTED = "documented"
    INFERRED = "inferred"
    CANDIDATE = "candidate"
    UNSUPPORTED = "unsupported"
    NOT_FOUND = "not_found"
    UNVERIFIED = "unverified"


EVIDENCE_TO_CLAIM = {
    EvidenceStatus.CONFIRMED_AUTHORITATIVE: ClaimStatus.DOCUMENTED,
    EvidenceStatus.REPORTED_IN_DOCUMENT: ClaimStatus.DOCUMENTED,
    EvidenceStatus.INFERRED: ClaimStatus.INFERRED,
    EvidenceStatus.LLM_CANDIDATE: ClaimStatus.CANDIDATE,
    EvidenceStatus.NOT_FOUND: ClaimStatus.NOT_FOUND,
    EvidenceStatus.UNABLE_TO_VERIFY: ClaimStatus.UNVERIFIED,
}


class Claim(BaseModel):
    claim_id: str
    text: str
    subject: str
    predicate: str
    object: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    status: ClaimStatus
    explanation: str = ""

    @model_validator(mode="after")
    def documented_needs_evidence(self) -> "Claim":
        if self.status in (ClaimStatus.DOCUMENTED, ClaimStatus.INFERRED, ClaimStatus.CANDIDATE) and not self.evidence_ids:
            raise ValueError(f"claim {self.claim_id} is '{self.status.value}' but cites no evidence")
        return self


class ResearchTask(BaseModel):
    task_id: str
    agent: Literal["threat_actor", "vulnerability", "attack", "evidence"]
    objective: str
    terms: list[str] = Field(default_factory=list)
    identifiers: dict[str, list[str]] = Field(default_factory=dict)
    attempt: int = 0


class AgentResult(BaseModel):
    agent_name: str
    task_id: str
    status: Literal["ok", "no_results", "failed"]
    summary: str = ""
    entities: list[dict[str, Any]] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)   # Evidence.to_dict(), agent-local ids
    unresolved: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0
    attempt: int = 0
