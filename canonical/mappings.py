"""Explicit mapping decisions: source type -> entity type, relationship names
and directions. Nothing here is copied blindly from a source."""

STIX_TO_ENTITY = {
    "x-mitre-tactic": "AttackTactic",
    "attack-pattern": "AttackTechnique",
    "intrusion-set": "ThreatActor",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
    "course-of-action": "Mitigation",
}

# Allowed (source entity type, relationship, target entity type).
ALLOWED = {
    ("Vulnerability", "HAS_WEAKNESS", "Weakness"),
    ("Vulnerability", "AFFECTS", "Software"),
    ("Weakness", "CHILD_OF", "Weakness"),
    ("AttackTechnique", "PART_OF_TACTIC", "AttackTactic"),
    ("AttackTechnique", "SUBTECHNIQUE_OF", "AttackTechnique"),
    ("ThreatActor", "USES", "AttackTechnique"),
    ("ThreatActor", "USES", "Malware"),
    ("ThreatActor", "USES", "Tool"),
    ("Campaign", "USES", "AttackTechnique"),
    ("Campaign", "USES", "Malware"),
    ("Campaign", "USES", "Tool"),
    ("Malware", "USES", "AttackTechnique"),
    ("Tool", "USES", "AttackTechnique"),
    ("Mitigation", "MITIGATES", "AttackTechnique"),
    ("ThreatActor", "CONDUCTS", "Campaign"),
    ("IntelligenceReport", "MENTIONS", "Vulnerability"),
    ("IntelligenceReport", "MENTIONS", "AttackTechnique"),
}

# STIX relationship_type -> (canonical rel, reverse?)
# ATT&CK stores "Campaign --attributed-to--> Group"; we model the natural
# direction "ThreatActor --CONDUCTS--> Campaign", hence reverse=True.
STIX_REL = {
    "uses": ("USES", False),
    "mitigates": ("MITIGATES", False),
    "subtechnique-of": ("SUBTECHNIQUE_OF", False),
    "attributed-to": ("CONDUCTS", True),
}

# Placeholders NVD uses instead of a real CWE id; kept as a property, not a node.
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}

# Tolerated alternative field names in the processed files (first match wins).
ALIASES = {
    "stix_id": ("stix_id", "id", "object_id", "stix_ref"),
    "rel_source": ("source_ref", "source_stix_id", "source_id", "source"),
    "rel_target": ("target_ref", "target_stix_id", "target_id", "target"),
    "rel_type": ("relationship_type", "rel_type", "type"),
    "kev_ransomware": ("known_ransomware_campaign_use", "ransomware_use",
                       "known_ransomware_use"),
    "nvd_cwes": ("cwe_ids", "cwes", "weaknesses", "cwe"),
    "kev_cwes": ("cwes", "cwe_ids", "cwe"),          # Milestone 5.1
    "nvd_products": ("affected_products", "products"),
    "cwe_id": ("cwe_id", "id", "identifier"),
    "cwe_rels": ("related_weaknesses", "relationships", "related"),
    "doc_id": ("advisory_id", "doc_id", "id", "url"),
}
