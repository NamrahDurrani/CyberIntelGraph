# Project Status

**Current milestone:** 4 - Raw data audit: run on your PC; one follow-up fix delivered (CWE check); then commit and close

## Completed
- [x] Milestones 1 and 3 (gate passed on your PC); problems found in that run fixed
- [x] Advisories: 53 documents, all dated, derived dates validated (19/19 agree with stated dates), target 50-75 met
- [x] Milestone 4 audit run on your PC: all five dataset targets MET, sources agree (NVD vs KEV dates 150/150), no data tracked by Git, 211 raw files verified
- [x] CWE parser fix works for the data (8 missing ids found); CWE check wording fixed (any non-weakness kind counts) and ICS technique ids classified in the audit
- [ ] Patch installed; `python scripts\check_cwe_output.py` passes; `python ingestion\validation\audit_raw_data.py --write-doc` prints **no FAIL**
- [ ] `docs/data_dictionary/RAW_DATA_AUDIT.md` read (field inventory) and committed
- [ ] Everything committed and pushed (code, docs, audit document)
- [ ] `cig doctor` output seen (location tooling confirmed on your PC)

## Working functionality
- Five collectors, five check scripts, the gate, the audit, doctor and `cig`

## Pending

## Known issues
- None blocking. The real name of the CWE grouping entries is shown by the collector (`Other entry kinds`)

## Next exact task
Install the patch, run the CWE check and the audit, paste the audit summary, then commit and push.

## Milestone 5.1 - done (2026-11-10)
- Canonical graph now links KEV and NVD CWE ids: HAS_WEAKNESS 171 -> 1755.
- ATT&CK sub-technique parents verified (479/479).
- Next: Milestone 6 (Docling + chunking of the advisories).

## Milestone 6 - done
- 2734 advisory chunks from 53 documents (Docling HTML).
- Next: Milestone 7 (naive RAG).

## Milestone 7 - done
- Naive RAG baseline: 2734 chunks indexed, Groq gpt-oss-20b answers with citations.
- Next: Milestone 8 (hybrid retrieval: BM25 + semantic).
