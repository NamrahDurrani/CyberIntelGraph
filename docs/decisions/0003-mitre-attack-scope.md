# 0003 - MITRE ATT&CK scope and release handling

- Date: 2026-11-02
- Status: accepted as implemented

## Context
The master prompt asks for a "relevant subset of STIX objects" from MITRE ATT&CK and says not to download everything.

## Decision
- **Domain:** Enterprise only. Mobile and ICS are not downloaded (not needed for the ransomware / initial access / exploited-vulnerability focus).
- **Release:** the highest Enterprise release listed in `index.json`, downloaded as that one versioned file (no `git clone`).
  The version is stored in every record and can be pinned with `--version`.
- **Object types kept:** attack-pattern, x-mitre-tactic, intrusion-set, malware, tool, campaign, course-of-action.
  **Relationship types kept:** uses, mitigates, subtechnique-of, attributed-to.
- **Active objects only.** Revoked and deprecated objects and `revoked-by` pointers are left out of the normalized files (they stay in the raw file).
- **No further narrowing to "ransomware only".** ATT&CK is already a curated, compact structured source (about 1,800 objects and 21,000 relationships),
  and it is imported deterministically into the graph. Narrowing would remove context for questions like "which groups use this technique".
  Focus on ransomware is applied through the KEV / NVD / advisory selection, and can be applied again at query time.
- **STIX direction preserved.** Mapping to canonical relationships (for example reversing `campaign attributed-to intrusion-set`
  into `ThreatActor CONDUCTS Campaign`) is a Milestone 5 job.
- **Detection content** (x-mitre-analytic, detection strategies, data sources and components) is not normalized yet; it stays in the raw file.

## Consequences
- ATT&CK data does not need GraphRAG's LLM extraction: structured records get `evidence_type = structured_authoritative_record`.
- Disk use is about 100 MB (raw + processed); both are outside Git.
- New ATT&CK releases are picked up by simply running the collector again (a new raw file is kept next to the old one).
