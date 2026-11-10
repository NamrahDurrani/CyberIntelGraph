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
- Milestone 5: canonical schemas and cross-source deduplication. Decisions needed first: ATT&CK `tool` and `malware` mapping; whether to add the ICS matrix; adding some non-KEV CVEs to the NVD set
- Milestone 6: Docling and chunking

## Known issues
- None blocking. The real name of the CWE grouping entries is shown by the collector (`Other entry kinds`)

## Next exact task
Install the patch, run the CWE check and the audit, paste the audit summary, then commit and push.
