# 09 - Canonical model (Milestone 5)

## Purpose
Turn five audited source files into one graph-ready set of entities and
relationships with stable ids and provenance.

## Files
| Path | Role |
|---|---|
| `canonical/models.py` | Pydantic v2 schemas: 12 entities, Relationship, Evidence, EvidenceType |
| `canonical/ids.py` | Deterministic id and normalisation helpers |
| `canonical/mappings.py` | Type mapping, relationship allow-list, direction rules, field aliases |
| `canonical/build.py` | Reads `data/processed/*.json`, writes `data/canonical/*.json` |
| `scripts/inspect_processed_schema.py` | Prints real field names of every processed file |
| `scripts/check_canonical_output.py` | Independent check of the output |
| `tests/unit/test_canonical.py` | 12 unit tests (synthetic fixtures) |

## Pipeline
processed JSON -> (1) CWE -> (2) KEV -> (3) NVD -> (4) ATT&CK objects ->
(5) ATT&CK relationships -> (6) advisories -> entities.json, relationships.json,
unresolved_references.json + `outputs/reports/canonical_build_<ts>.json`.
Order matters: CWE must exist before NVD links to it; objects before relationships.

## Run
```
python scripts\inspect_processed_schema.py
python -m unittest discover -s tests\unit
python canonical\build.py
python scripts\check_canonical_output.py
```

## Output
`data/canonical/entities.json`, `relationships.json`, `unresolved_references.json`
(each: `metadata` + `records`; metadata holds schema version, input SHA-256s, counts).
