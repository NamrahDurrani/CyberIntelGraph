"""Threat Actor Research Agent: actors, groups, malware, tools, campaigns, aliases.
Technique mappings belong to the ATT&CK agent; vulnerability links to the
vulnerability agent. This agent never infers an exploitation link."""

from __future__ import annotations

from ..evidence import EvidenceStatus
from .base import ACTOR_LABELS, ATTACK_LABELS, SpecialistAgent, Workspace

ALIAS_KEYS = ("aliases", "alias", "aka", "x_mitre_aliases", "associated_groups", "also_known_as")


class ThreatActorAgent(SpecialistAgent):
    name = "threat_actor"
    labels = ["ThreatActor", "Campaign", "Malware", "Tool"]
    preferred_rels = ["USES", "CONDUCTS", "RELATED_TO"]

    def group_filter(self, ref, group) -> bool:
        return group["label"] not in ATTACK_LABELS

    def investigate(self, ws: Workspace, question: str) -> None:
        for ref in self.resolve(ws):
            profile_id = self.add_profile(ws, ref)
            for key in ALIAS_KEYS:
                value = ref.props.get(key)
                if not value:
                    continue
                aliases = [str(a) for a in (value if isinstance(value, (list, tuple)) else str(value).split(","))]
                aliases = [a.strip() for a in aliases if a.strip() and a.strip().lower() != ref.name.lower()]
                if aliases:
                    ev = ws.book.add(EvidenceStatus.CONFIRMED_AUTHORITATIVE, "aliases",
                                     f"Aliases of {ref.name} recorded in the source data",
                                     text=", ".join(aliases[:15]), source=ref.props.get("source", "canonical knowledge graph"),
                                     entities=[ref.key()])
                    for alias in aliases[:10]:
                        ws.claim(f"{alias} is recorded as an alias of {ref.name}", alias, "alias_of", ref.name, ev.id)
                break
            self.add_relations(ws, ref)
