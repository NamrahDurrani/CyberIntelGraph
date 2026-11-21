"""MITRE ATT&CK Research Agent: tactics, techniques, sub-techniques, mitigations and
the groups / malware / tools documented as using them. Identifiers come from the
graph; this agent never invents a technique id."""

from __future__ import annotations

from .base import ACTOR_LABELS, ATTACK_LABELS, SpecialistAgent, Workspace


class AttackAgent(SpecialistAgent):
    name = "attack"
    labels = ["AttackTechnique", "AttackTactic", "Mitigation", "ThreatActor", "Malware", "Tool", "Campaign"]
    preferred_rels = ["USES", "SUBTECHNIQUE_OF", "PART_OF_TACTIC", "MITIGATES"]

    def group_filter(self, ref, group) -> bool:
        if group["label"] in ATTACK_LABELS:
            return True
        # for a technique, "who uses it" is the interesting direction
        return ref.label in ATTACK_LABELS and group["label"] in ACTOR_LABELS

    def investigate(self, ws: Workspace, question: str) -> None:
        for ref in self.resolve(ws):
            self.add_profile(ws, ref)
            self.add_relations(ws, ref)
