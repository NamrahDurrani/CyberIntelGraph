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

## Amendment (2026-11-10): ICS technique ids in advisories
The first audit found 15 technique-style ids in advisory text (T0801, T0803, T0804, T0807, T0809, T0812 ...) that are not active Enterprise techniques.
Ids T0800-T0899 belong to the **ATT&CK for ICS** matrix, which this decision deliberately does not collect (Enterprise only).
The audit now classifies them as INFO ("ICS matrix, not collected") and keeps WARN for ids that are neither Enterprise nor ICS (retired, Mobile, or not really ATT&CK ids).
**Open question for Milestone 5:** if questions about industrial control systems matter for the project, add the ICS domain with the same collector (`index.json` lists it);
otherwise advisory mentions of ICS techniques stay as lexical mentions without an ATT&CK record to link to.

