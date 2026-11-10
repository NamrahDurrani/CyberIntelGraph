# Pipeline step: MITRE ATT&CK collector

Milestone 3 - third collector. Files: `ingestion/collectors/mitre_attack/collector.py`,
`tests/unit/test_mitre_attack_collector.py`, `scripts/check_attack_output.py`.

## In plain words
KEV and NVD describe **vulnerabilities**. ATT&CK describes **behaviour**: the tactics (the attacker's goals), techniques
(how they achieve them), and which groups, malware, tools and campaigns have been seen using them.
Analogy: KEV/NVD are the list of unlocked doors; ATT&CK is the catalogue of burglars' methods and who used which.
It is published as **STIX 2.1**, a standard JSON format where every object has a type and an id and links are separate
`relationship` objects (like a list of "A uses B" cards).

## Steps
| # | Step | Why |
|---|---|---|
| 1 | Download `index.json` (small) and pick the latest "Enterprise ATT&CK" release | Reproducible: we always know which release we hold |
| 2 | Download that one versioned bundle (about 55 MB), save it **unchanged** + `.meta.json` (URL, time, SHA-256, version) | Evidence locker |
| 3 | If that release is already on disk and still matches its SHA-256, skip the download; if it was modified, stop with an error | Releases never change; raw files must never be edited |
| 4 | Validate: bundle type, unique ids, id/type agreement, ATT&CK id format per type, unique ATT&CK ids, relationship endpoints exist, tactics exist, every sub-technique has exactly one parent | Catch broken data early |
| 5 | Normalize active in-scope objects and relationships into two files in `data/processed/` | Separate from raw |
| 6 | Report in `outputs/reports/`, log in `logs/mitre_attack_collector.log` | Audit trail |

## Run it
```powershell
cig                              # or: cd to your project folder
.\.venv\Scripts\Activate.ps1
python ingestion\collectors\mitre_attack\collector.py
python scripts\check_attack_output.py
```
Takes a few seconds to a minute depending on your connection (one 55 MB download). Disk use: about 55 MB raw + 45 MB processed.

**Expected for release 20.0** (these numbers come from running the collector on the real v20.0 file in the development environment;
your run should match if the latest release is still 20.0, otherwise use `--version 20.0`):
```
=== MITRE ATT&CK collection summary ===
  Status                        : SUCCESS
  Release                       : Enterprise ATT&CK 20.0
  Objects in bundle             : 26690
  Excluded revoked/deprecated   : 403
  Objects normalized            : 1842      (technique 706, campaign 57, mitigation 44, group 178, malware 747, tool 95, tactic 15)
  Relationships in bundle       : 21819
  Relationships normalized      : 20957
  Warnings : 0   Errors : 0
```
Then `check_attack_output.py` should print 15 `[PASS]` lines and `ALL CHECKS PASSED`; run the collector a second time and it prints
`(reused, already on disk)`.

## If it fails
| Message | Meaning / fix |
|---|---|
| `Giving up ... ConnectionError` | No internet or GitHub blocked: open the index URL in a browser |
| `ReadTimeout` on the bundle | Slow connection: `--bundle-timeout 600` |
| `no longer matches its recorded SHA-256` | A raw file was edited or corrupted: delete that raw bundle + its `.meta.json`, run again |
| `unexpected ATT&CK id format` / `no 'mitre-attack' external id` | The data format changed in a new release: paste me the output |
| `[FAIL] relationship type/direction combinations` | A new release added a relationship kind: tell me, we extend the dictionary |

## Next
After ATT&CK is validated and committed: CWE (XML), then CISA advisories (RSS + HTML, then Docling in Milestone 6).
