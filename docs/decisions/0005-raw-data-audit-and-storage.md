# 0005 - Raw data audit and storage rules (Milestone 4)

- Date: 2026-11-04
- Status: accepted as implemented

## Context
Each collector validates its own output and has an independent check script. That proves each source on its own; it does not prove the whole raw data layer
(complete, untouched, fresh, consistent across sources, documented, not leaking into Git). Milestone 4 adds that gate before we build the canonical model on top.

## Decision
- **One audit command** (`ingestion/validation/audit_raw_data.py`) re-reads everything from disk. It does not trust collector summaries. It also runs the five check scripts.
- **Severity model.** FAIL = integrity or storage problems (missing or changed raw file, processed file missing, data or `.env` tracked by Git, failing check script). Only FAIL gives exit code 1.
  WARN = quality questions (targets not met, stale data, unknown mentions, undocumented state). INFO = facts.
- **Targets are data, not code:** `config/dataset_targets.json` holds the initial targets from the master prompt. They are initial targets, not permanent limits ("above target" is INFO).
- **Field inventory:** the audit counts which fields really occur in the raw data and compares them with the fields our normalizers read. Ignored fields are listed (nothing is silently dropped without being visible);
  a field we read that occurs nowhere in the source is a WARN.
- **Cross-source checks** that later become evaluation material: NVD vs KEV membership, CWE ids vs the CWE catalog, advisory mentions vs KEV / NVD / ATT&CK / CWE,
  and NVD's embedded CISA dates vs KEV (the first real conflict-detection test).
- **Storage:** raw data is outside Git (`.gitignore`); the audit verifies that nothing from `data/`, `outputs/`, `logs/` or `.env` is tracked.
  Optional `scripts/protect_raw_data.ps1` marks raw files read-only (the append-only `manifest.jsonl` stays writable).
- **Generated documentation:** `--write-doc` writes `docs/data_dictionary/RAW_DATA_AUDIT.md`. It is tracked by Git so changes in the data layer are visible in history.

## Consequences
- Milestone 4 is complete when the audit prints no FAIL on your PC, the advisories reach their target (or the shortfall is explained), and the generated document is committed.
- Future collectors only need to register in `SOURCES`, `CONSUMED` and `config/dataset_targets.json` to join the audit.
