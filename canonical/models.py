"""Canonical entities, relationships and evidence (Pydantic v2).

One real-world thing = one entity with one stable canonical_id of the form
"<EntityType>:<natural key>", e.g. "Vulnerability:CVE-2024-3400".
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CANONICAL_ID_RE = re.compile(r"^[A-Za-z]+:\S+$")


class EvidenceType(str, Enum):
    """The five evidence types from the project guide (section 8.13)."""
    STATED_IN_SOURCE = "stated_in_source"
    STRUCTURED_AUTHORITATIVE = "structured_authoritative"
    LLM_EXTRACTED_CANDIDATE = "llm_extracted_candidate"
    HUMAN_REVIEWED = "human_reviewed"
    INFERRED = "inferred"


class Evidence(BaseModel):
    """Where a fact came from (provenance)."""
    model_config = ConfigDict(extra="forbid")

    source: str                      # cisa_kev | nvd | mitre_attack | cwe | advisories
    evidence_type: EvidenceType
    record_ref: str | None = None    # id of the record inside that source
    raw_file_reference: str | None = None
    source_url: str | None = None
    retrieved_at: str | None = None


class CanonicalEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_id: str
    entity_type: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_id(self) -> "CanonicalEntity":
        if not CANONICAL_ID_RE.match(self.canonical_id):
            raise ValueError(f"bad canonical_id: {self.canonical_id!r}")
        if not self.canonical_id.startswith(self.entity_type + ":"):
            raise ValueError(
                f"canonical_id {self.canonical_id!r} does not start with "
                f"entity_type {self.entity_type!r}")
        return self


class Vulnerability(CanonicalEntity):
    entity_type: Literal["Vulnerability"] = "Vulnerability"
    cve_id: str
    description: str | None = None
    cvss_primary: Any = None
    severity: str | None = None
    in_kev: bool = False
    kev_date_added: str | None = None
    kev_ransomware_use: bool | str | None = None   # real KEV data uses a bool
    kev_required_action: str | None = None
    # True when the CVE is only known from an advisory (no KEV/NVD record yet)
    stub: bool = False


class Weakness(CanonicalEntity):
    entity_type: Literal["Weakness"] = "Weakness"
    cwe_id: str
    element_type: str | None = None      # weakness | grouping | category
    abstraction: str | None = None
    status: str | None = None
    description: str | None = None


class Software(CanonicalEntity):
    entity_type: Literal["Software"] = "Software"
    vendor: str
    product: str


class _AttackBase(CanonicalEntity):
    attack_id: str | None = None
    stix_id: str | None = None
    description: str | None = None


class AttackTactic(_AttackBase):
    entity_type: Literal["AttackTactic"] = "AttackTactic"
    shortname: str | None = None


class AttackTechnique(_AttackBase):
    entity_type: Literal["AttackTechnique"] = "AttackTechnique"
    is_subtechnique: bool = False
    tactics: list[str] = Field(default_factory=list)   # tactic shortnames


class ThreatActor(_AttackBase):
    entity_type: Literal["ThreatActor"] = "ThreatActor"


class Malware(_AttackBase):
    entity_type: Literal["Malware"] = "Malware"


class Tool(_AttackBase):
    entity_type: Literal["Tool"] = "Tool"


class Campaign(_AttackBase):
    entity_type: Literal["Campaign"] = "Campaign"


class Mitigation(_AttackBase):
    entity_type: Literal["Mitigation"] = "Mitigation"


class IntelligenceReport(CanonicalEntity):
    entity_type: Literal["IntelligenceReport"] = "IntelligenceReport"
    url: str | None = None
    published: str | None = None


class Organization(CanonicalEntity):
    """Defined for completeness; no collected source populates it yet."""
    entity_type: Literal["Organization"] = "Organization"


ENTITY_CLASSES: dict[str, type[CanonicalEntity]] = {
    c.model_fields["entity_type"].default: c
    for c in (Vulnerability, Weakness, Software, AttackTactic, AttackTechnique,
              ThreatActor, Malware, Tool, Campaign, Mitigation,
              IntelligenceReport, Organization)
}


class Relationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rel_id: str                      # "<REL_TYPE>|<source_id>|<target_id>"
    rel_type: str
    source_id: str
    target_id: str
    evidence_type: EvidenceType
    evidence: list[Evidence] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> "Relationship":
        if self.rel_id != f"{self.rel_type}|{self.source_id}|{self.target_id}":
            raise ValueError("rel_id must be REL|source|target")
        return self
