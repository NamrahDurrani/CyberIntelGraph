# CyberIntelGraph - Project Guide

*Status as of 2026-11-04. Read this once top to bottom; afterwards use it as a reference.
Save it in your project as `docs\PROJECT_GUIDE.md` (command at the end).*

**Contents**
1. The big picture
2. Where we are
3. What we built, step by step (Milestones 1 and 3: KEV, NVD, ATT&CK, CWE, advisories)
4. What is on your disk and what is in Git
5. Results at a glance
6. See the data with your own eyes (hands-on)
7. Everyday commands
8. Key ideas explained
9. What comes next (every remaining milestone)
10. Decisions and open items
11. Problems we already met (and the fixes)
12. How we work

---

## 1. The big picture

**What CyberIntelGraph will be:** a research assistant for cyber threat intelligence. You ask a question such as
*"Which techniques does this ransomware group use, and which exploited vulnerabilities are linked to it?"* and it answers with
**evidence**: source links, dates, what is confirmed, what is only inferred, and what it could not find.

**Analogy: a detective agency.**

| Agency part | Project part |
|---|---|
| Couriers bring in original documents | **Collectors** download official data (CISA, NVD, MITRE) |
| Evidence locker (never touched) | `data/raw/` |
| Filing clerk who rewrites everything on one standard form | **Normalization** into `data/processed/` |
| One official case file per subject, even if five sources mention it | **Canonical model** (Milestone 5) |
| Analysts reading reports and pinning notes on a corkboard | **GraphRAG** (Milestone 9) |
| The official case-file database with exact lookups | **Neo4j** (Milestones 10-11) |
| Front-desk logbook | **MongoDB** (Milestone 12) |
| The lead detective who plans, picks tools, double-checks, and phones sources to confirm | **LangGraph agent** (Milestones 13-14) |
| The written case report with citations | **Reports + API + web app** (Milestones 15-16) |
| Auditing which method really works best | **Evaluation** (Milestone 17) |

**The three golden rules of this project**
1. **Evidence first.** Every fact keeps its source, dates and original text. Nothing is invented. A tool error is never reported as "does not exist".
2. **Raw data is sacred.** We never edit downloaded files; everything derived goes to a different folder.
3. **One step at a time, verified.** We run it, inspect it, test it, document it, commit it, and only then move on.

---

## 2. Where we are

| # | Milestone | Status |
|---|---|---|
| 1 | Environment and project structure | **Done and verified** (venv, structure, GitHub) |
| 2 | Data source selection and dataset scope | **Done** (decision records 0002 and 0003) |
| 3 | Collectors | **Done: all five built and the gate passed on your PC** (KEV, NVD, ATT&CK, CWE, advisories). The run exposed four problems (CWE categories, advisory dates, advisory discovery, dead seed addresses); fixes are delivered, re-run to confirm |
| 4 | Raw data validation and storage | **Built:** one audit command for all five sources; run it on your PC |
| 5 | Canonical schemas and normalization | Not started |
| 6 | Document processing and chunking (Docling) | Not started |
| 7 | Naive RAG baseline | Not started |
| 8 | Hybrid RAG | Not started |
| 9 | Microsoft GraphRAG indexing | Not started |
| 10 | GraphRAG output inspection and Neo4j sync | Not started |
| 11 | Neo4j schema and Cypher retrieval | Not started |
| 12 | MongoDB application persistence | Not started |
| 13 | LangGraph supervisor and research tools | Not started |
| 14 | Evidence verification and live fallback | Not started |
| 15 | Report generation and FastAPI | Not started |
| 16 | Frontend (Next.js) | Not started |
| 17 | Evaluation and benchmarking | Not started |
| 18 | Integration testing, security review, deployment | Not started |

```
 BUILT                                                               NOT YET BUILT
 ┌─────────────┐   ┌──────────────┐   ┌───────────────────┐         ┌──────────────┐
 │ Collectors  │──>│ data/raw     │──>│ data/processed    │──(M5)──>│ Canonical    │
 │ KEV NVD     │   │ (untouched,  │   │ (normalized,      │         │ model +      │──> GraphRAG ──> Neo4j ──> Agent ──> API ──> Web app
 │ ATT&CK      │   │  SHA-256)    │   │  provenance)      │         │ evidence     │
 └─────────────┘   └──────────────┘   └───────────────────┘         └──────────────┘
   CWE + advisories built (first real run pending)        Docling + chunking for advisories (M6)
```

---

## 3. What we built, step by step

### 3.1 Milestone 1: environment and structure

**What:** Python 3.12 virtual environment in the project folder (`.venv`), a 61-leaf-folder project structure
(76 folders in total), starter docs, helper scripts, Git repository on GitHub (`NamrahDurrani/CyberIntelGraph`).

**Why each piece exists**
- **Virtual environment** = a separate toolbox for this project. Packages installed in it can't clash with other projects.
- **Folder structure** = the building's floor plan. Every later milestone has a room waiting for it.
- **`.gitkeep`** = a placeholder so Git tracks empty folders.
- **`.gitignore`** = a list of things Git must never store: `.env` (secrets), `.venv`, and everything inside `data/`, `outputs/`, `logs/`.
- **Scripts** (`scripts\setup_env.ps1`, `verify_structure.ps1`, `git_init.ps1`) automate the repeatable setup.

**What went wrong and why it matters:** you extracted the zip into OneDrive, and PowerShell blocked the unsigned downloaded scripts.
We moved the project to `C:\CyberIntelGraph` (outside OneDrive, so it doesn't sync thousands of files) and unblocked the scripts. A later mix-up (commands run in an old, empty OneDrive copy) led to location-independent tooling: the `cig` shortcut and the doctor (`docs/PROJECT_LOCATION.md`).

**Verified:** Python 3.12.10, `STRUCTURE OK`, first commit pushed (`d41efb8`).

### 3.2 Milestone 3, collector 1: CISA KEV

**What it is.** KEV is CISA's list of vulnerabilities **confirmed to be exploited in the wild**. This is the only source in the
project that proves exploitation; NVD does not.

**Analogy.** A library card catalog: one cover sheet (version, date, count) plus one card per vulnerability.

**What the collector does** (`ingestion\collectors\cisa_kev\collector.py`)
1. Downloads the official JSON catalog with retries on network problems.
2. Saves the response **unchanged** to `data\raw\cisa_kev\` with a `.meta.json` sidecar (URL, time, size, **SHA-256**).
3. Validates: envelope keys, declared count equals real count, required fields, CVE-ID format, dates, duplicates.
4. Writes a normalized copy `data\processed\cisa_kev_normalized.json` (all valid records, with provenance fields).
5. Writes `cisa_kev_initial_subset.json`: **75 records**, ransomware-linked first, newest first (decision 0002).
6. Writes a validation report and a log.

**Verified on your PC (real feed):** catalog `2026.10.30`, **1,766 records**, 0 rejected, 0 duplicates, 0 warnings;
361 records with known ransomware campaign use; dates added from 2021-11-03 to 2026-10-30; top vendors Microsoft (390), Cisco (102),
Apple (95), Adobe (83), Google (76). A second run reused the unchanged raw file. Committed as `d74e626`.

### 3.3 Milestone 3, collector 2: NVD

**What it is.** The National Vulnerability Database: the detailed **dossier** for each CVE (description, severity scores, weakness type,
affected products, references). Analogy: KEV is the wanted list, NVD is the file behind each name.

**What the collector does** (`ingestion\collectors\nvd\collector.py`)
1. Builds the list of CVEs: the top 150 of the KEV ordering (the first 75 are exactly the KEV subset), plus any `--cve-id` you give.
2. One request per CVE to the NVD API. It pauses between requests to respect NVD's rate limits (about 0.7 s with an API key, 6.5 s without).
   Rate-limit answers (HTTP 403/429) and server errors are retried slowly.
3. Saves each response unchanged to `data\raw\nvd\` and appends a line to `manifest.jsonl` (file, time, status, SHA-256).
   **Already-downloaded CVEs are skipped, so an interrupted run resumes** where it stopped.
4. Validates each response (envelope, exactly one record, returned ID equals requested ID, required fields).
5. Normalizes to `data\processed\nvd_normalized.json`: description, status, **all CVSS scores plus a primary one** (newest CVSS version),
   weaknesses (CWE IDs), affected products (vendor / product / version range split out of the CPE strings), references, and any CISA fields NVD carries.
6. Reports three outcomes separately: **ok**, **"NVD returned 0 records"** (never treated as "does not exist"), **failed**.

**API key safety.** The key lives in `.env` (ignored by Git), is sent only as an HTTP header over HTTPS, and is never written to logs, manifest or reports.
Analogy: a library card tied to your email: don't lend it, and request a new one if it ever leaks.

**Verified on your PC:** 150 requested, 150 downloaded, 0 failed, 150 normalized (all with CVSS, CWE and affected products);
severity 86 CRITICAL / 53 HIGH / 10 MEDIUM / 1 LOW; all 150 are also in KEV, and the 75/75 KEV subset is covered;
the check script passed all 7 checks. NVD carried CISA fields on all 150 records, which we can later compare with KEV.

### 3.4 Milestone 3, collector 3: MITRE ATT&CK

**What it is.** ATT&CK describes **attacker behaviour**: *tactics* (goals, e.g. Initial Access), *techniques* (how, e.g. phishing),
and which *groups, malware, tools and campaigns* have been seen using which techniques.
Analogy: KEV and NVD list the unlocked doors; ATT&CK is the burglars' methods book and who used which method.

**Format.** STIX 2.1 JSON: every object has a type and an id, and each link is a separate `relationship` object ("A uses B" cards).

**What the collector does** (`ingestion\collectors\mitre_attack\collector.py`)
1. Reads the official `index.json` and picks the **latest Enterprise ATT&CK release** (numerically: 19.2 is lower than 20.0). Mobile and ICS are skipped.
2. Downloads that one versioned bundle (about 55 MB) and saves it unchanged with its SHA-256. A release that is already on disk and still matches
   its recorded hash is **not downloaded again**; if it was edited, the collector refuses to run.
3. Validates: bundle type, unique ids, ID formats (T1234, G0001, S0001, ...), relationship endpoints, tactics, one parent for every sub-technique.
4. Keeps only **active** objects (not revoked, not deprecated) of 7 types, and 4 relationship types, in two files:
   `attack_objects_normalized.json` and `attack_relationships_normalized.json`.

**Verified on your PC:** `check_attack_output.py` passed all checks. Profile: 706 techniques (479 sub-techniques), 15 tactics, 178 groups, 747 malware,
95 tools, 57 campaigns, 44 mitigations; 20,957 relationships (18,975 `uses`, 1,477 `mitigates`, 479 `subtechnique-of`, 26 `attributed-to`);
22 Initial Access techniques; 26 of 57 campaigns attributed to a group. These match what I measured on the real v20.0 file.

**Worth knowing:** in this release the tactic names include `stealth` and `defense-impairment`. Older ATT&CK versions (and many articles) say "Defense Evasion".
We always read tactics from the data, never from memory.

### 3.5 Milestone 3, collector 4: CWE

**What it is.** The dictionary behind the weakness codes (`CWE-79`) that NVD gave us, plus the family tree that organizes them
(Pillar, Class, Base, Variant). Analogy: a CVE is one specific break-in; a CWE is the *kind* of lock weakness it exploited.

**What the collector does** (`ingestion\collectors\cwe\collector.py`)
1. Downloads the official `cwec_latest.xml.zip` and saves the zip **unchanged** with its SHA-256 (an identical zip is reused).
2. Reads the XML inside the zip in memory (nothing is extracted to disk); refuses a non-zip answer, a zip without XML, or an oversize archive.
3. Normalizes weaknesses, categories and views: names, abstraction, status (including **Deprecated**), descriptions, relationships (`ChildOf`, ...),
   platforms, CAPEC links, taxonomy mappings and **mapping notes** (whether the id is appropriate for mapping vulnerabilities).
4. Counts how many of our NVD and KEV records use each id, and writes an **initial subset**: the ids we use plus their ancestors in view 1000.
5. Reports ids that NVD uses but the catalog does not hold, as warnings; NVD placeholders (`NVD-CWE-Other`, `NVD-CWE-noinfo`) are counted, not mapped.

**Status:** validated on your PC (CWE v5.0, 2026-10-28). The run exposed a bug (0 categories found) that is fixed in the current version: see section 3.7.

### 3.6 Milestone 3, collector 5: CISA advisories

**What it is.** The first *unstructured* source: advisory pages written like case reports (how a named group broke in, which tools and
vulnerabilities it used, what to do). This is the text GraphRAG will read in Milestone 9.
Analogy: KEV/NVD/ATT&CK/CWE are the police database; advisories are the investigators' case reports.

**What the collector does** (`ingestion\collectors\advisories\collector.py`)
1. Builds the list of pages: your `--url`s, the official RSS feed (newest first), then a seed list (`config\advisory_seed_urls.txt`); only `www.cisa.gov`; at most 75.
2. Checks robots.txt, waits 2 s between pages, retries only timeouts, 429 and 5xx. **HTTP 403 is reported and never bypassed.**
3. Saves each page unchanged (`data\raw\advisories`, with `manifest.jsonl` and SHA-256) and resumes where it stopped.
4. Extracts the readable text with BeautifulSoup: title, release date, last revised, alert code, headings and lists, attachment links, and CVE / ATT&CK / CWE ids that are
   **mentioned** in the text. Mentions are lexical matches, **not relationships**.
5. Reports status **SUCCESS / PARTIAL / FAILED** and flags very short pages, missing dates and changed raw files.

**Status:** validated on your PC (46 documents). The run showed undated archived pages, a refused RSS feed (HTTP 403) and two dead seed addresses; the fixes (derived dates, `--discover`, cleaned seed list) are described in section 3.7.

### 3.7 What your real run taught us (Milestone 3 gate, 2026-11-03)
The gate said "all five passed", and it was right about what it checked. But your output also showed four things the checks did not catch. This is the value of looking at real data:

| What your output showed | Cause | Fix |
|---|---|---|
| CWE: **0 categories**, and 8 ids used by NVD/KEV (CWE-189, 19, 254, 255, 264 ...) "not in the catalog" | The parser looked for categories in one fixed place; CWE's own site lists several hundred, and those 8 ids are categories | Parser now finds entries in any section, reports the sections it saw, and the check fails if there are no categories |
| Advisories: **28 of 46 without a date** | Older pages carry the banner "Archived Content" and show only "Last Revised" | Date derived from the alert code (AA21-131A = year 21, day 131 = 2021-05-11), always marked as derived and cross-checked against pages that state the date |
| Advisories: RSS feed **403** and only **46** documents (target 50-75) | CISA refused this connection; we do not bypass refusals | `--discover` reads advisory links from CISA listing pages; more seed candidates |
| 2 seed addresses returned **404** | Candidates were unverified (as announced) | Removed from the seed list |

Lesson in one line: **a check can only prove what it was written to ask.** That is why Milestone 4 adds a combined audit that looks at the data from other angles (counts against targets, cross-source consistency, field inventory).

### 3.8 Milestone 4: the raw data audit
**Analogy:** the surveyor's visit before the architect designs the house. One command (`python ingestion\validation\audit_raw_data.py --write-doc`) checks: every raw file still matches its fingerprint,
freshness, record counts against the targets, whether the sources agree with each other (NVD vs KEV, CWE ids vs the catalog, advisory mentions vs KEV/NVD/ATT&CK/CWE, NVD's embedded CISA dates vs KEV),
which raw fields we use and which we ignore, that nothing from `data\`, `outputs\`, `logs\` or `.env` is tracked by Git, and that the five check scripts and the documentation are in order.
Severity: **FAIL** (integrity or storage problem) makes it exit with 1; **WARN** is a question to answer; **INFO** is a fact. It also writes `docs\data_dictionary\RAW_DATA_AUDIT.md`, which you commit.

### 3.9 What all five collectors have in common (the "collector pattern")

Every collector follows the same recipe:

| Step | Why |
|---|---|
| Fetch with timeouts and retries; clear errors | Networks fail; a failure must be visible, not silent |
| Save the raw response untouched + SHA-256 | Evidence locker; tamper detection |
| Skip what is already downloaded | Resumable and polite to the source |
| Validate: **errors reject a record, warnings keep it** | Bad data must not spread |
| Normalize into a separate file with **provenance fields** (`source_name`, `source_url`, `source_record_id`, `retrieved_at`, `published_at`, `last_modified_at`, `original_format`, `raw_file_reference`, `collection_method`) | Any later claim can be traced to its source |
| Validation report in `outputs\reports\`, log in `logs\` | Audit trail |
| An independent **check script** that re-reads the files and trusts nothing | Collector self-reports are not proof |
| Unit tests with clearly fake data | Logic is tested without inventing real records |
| Docs: data dictionary, pipeline page, decision record, CHANGELOG, PROJECT_STATUS | Nothing is "done" until it is written down and tested |

---

## 4. What is on your disk and what is in Git

```
<your project folder>\
├─ ingestion\collectors\{cisa_kev,nvd,mitre_attack}\collector.py    code      -> Git
├─ scripts\check_{kev,nvd,attack,cwe,advisories,all}_output.py       checks    -> Git (check_all = the Milestone 3 gate)
├─ scripts\{setup_env,verify_structure,git_init}.ps1                helpers   -> Git
├─ tests\unit\test_*_collector.py   (95 tests in total)             tests     -> Git
├─ config\advisory_seed_urls.txt   (candidate advisory addresses)     config    -> Git
├─ docs\ (guides, data dictionary, decisions, pipeline pages)       docs      -> Git
├─ README.md  CHANGELOG.md  PROJECT_STATUS.md  requirements.txt     project   -> Git
├─ data\raw\...        original downloads (about 60 MB plus advisories) NOT in Git
├─ data\processed\...  normalized copies (about 50 MB)              NOT in Git
├─ outputs\reports\... validation reports                           NOT in Git
├─ logs\...            run logs                                     NOT in Git
├─ .env                your secrets (NVD API key)                   NOT in Git, ever
└─ .venv\              Python toolbox                               NOT in Git
```

*Rule of thumb:* **code and docs go to GitHub; data, secrets and the venv never do.** Data can be rebuilt by re-running the collectors.
Sizes are approximate (the ATT&CK raw bundle is about 55 MB, the processed relationships file about 38 MB).

---

## 5. Results at a glance

| Source | What we hold | Key numbers |
|---|---|---|
| **CISA KEV** | Known exploited vulnerabilities | 1,766 records (catalog 2026.10.30); 75 in the initial subset; 361 with known ransomware use |
| **NVD** | Detailed CVE dossiers | 150 CVEs, all with CVSS + CWE + affected products; all in KEV |
| **MITRE ATT&CK** | Behaviour knowledge (Enterprise) | 1,842 objects, 20,957 relationships (release 20.0 figures) |
| **CWE** | Weakness catalogue | v5.0 (2026-10-28): 984 weaknesses, 62 views; categories fix delivered, re-run to confirm |
| **CISA advisories** | Unstructured reports | 46 documents so far (target 50-75); 238,398 words; 167 distinct CVEs mentioned, 155 of them in KEV |

---

## 6. See the data with your own eyes (hands-on)

Understanding comes from looking at real records. Run these from the project folder with the venv active (type `cig`).
I have not run them on your data, so I describe what to look for, not exact output.

**One KEV record: the "wanted list" card**
```powershell
python -c "import json; d=json.load(open('data/processed/cisa_kev_normalized.json',encoding='utf-8')); print(json.dumps(d['records'][0],indent=2))"
```
*Look for:* the original KEV fields (`cve_id`, `vendor_project`, `required_action`...) next to the added provenance fields (`source_url`, `retrieved_at`, `raw_file_reference`).

**The same CVE in two sources: why Milestone 5 exists**
```powershell
python -c "import json; k={r['cve_id']:r for r in json.load(open('data/processed/cisa_kev_normalized.json',encoding='utf-8'))['records']}; n={r['cve_id']:r for r in json.load(open('data/processed/nvd_normalized.json',encoding='utf-8'))['records']}; c='CVE-2024-3400'; print('KEV :',k[c]['vendor_project'],'|',k[c]['product'],'| added',k[c]['date_added']); print('NVD :',sorted({(p['vendor'],p['product']) for p in n[c]['affected_products']})); print('NVD score:',n[c]['cvss_primary'])"
```
*Look for:* KEV writes vendor and product as free text; NVD writes them as CPE codes (lowercase, underscores). Same vulnerability, two spellings.
Teaching them to be one canonical `Vulnerability` and `Software` is the job of Milestone 5.

**ATT&CK: top-level Initial Access techniques**
```powershell
python -c "import json; d=json.load(open('data/processed/attack_objects_normalized.json',encoding='utf-8'))['records']; [print(r['attack_id'],r['name']) for r in d if r['stix_type']=='attack-pattern' and 'initial-access' in r['tactics'] and not r['is_subtechnique']]"
```

**Open the raw files in VS Code:** `code data\raw\cisa_kev` shows the untouched original and its `.meta.json` seal.

---

## 7. Everyday commands

| Task | Command |
|---|---|
| Go to the project and activate `.venv` (any terminal, after `install_shortcut.ps1`) | `cig` |
| Health check: location, environment, files, data | `cig doctor`, or `python <project folder>\scripts\doctor.py` from any folder |
| Activate the environment (every new terminal) | `.\.venv\Scripts\Activate.ps1` |
| If scripts are blocked in a new window | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| Run all unit tests | `python -m unittest discover -s tests\unit` |
| KEV: collect, then check | `python ingestion\collectors\cisa_kev\collector.py` then `python scripts\check_kev_output.py` |
| NVD: small test, full run, check | `... nvd\collector.py --limit 3`, then without `--limit`, then `python scripts\check_nvd_output.py` |
| NVD: add one specific CVE | `python ingestion\collectors\nvd\collector.py --no-kev --cve-id CVE-2024-3400` |
| ATT&CK: collect, then check | `python ingestion\collectors\mitre_attack\collector.py` then `python scripts\check_attack_output.py` |
| CWE: collect, then check | `python ingestion\collectors\cwe\collector.py` then `python scripts\check_cwe_output.py` |
| Advisories: small test, full run, check | `... advisories\collector.py --limit 3`, then without `--limit`, then `python scripts\check_advisories_output.py` |
| Advisories when the feed refuses you | `... advisories\collector.py --no-feed --urls-file my_urls.txt --no-seed` |
| **Milestone 3 gate (all five sources)** | `python scripts\check_all_outputs.py` |
| **Milestone 4 audit** | `python ingestion\validation\audit_raw_data.py --write-doc` |
| Advisories without the RSS feed | `... advisories\collector.py --discover https://www.cisa.gov/news-events/cybersecurity-advisories --discover-pages 5` |
| Lock raw files read-only (optional) | `.\scripts\protect_raw_data.ps1` (undo with `-Unprotect`) |
| Verify the folder structure | `.\scripts\verify_structure.ps1` |
| Save work to GitHub | `git add .` then `git status --short` then `git commit -m "Milestone N: ..."` then `git push` |
| Is `.env` safe from Git? | `git check-ignore -v .env` (prints a rule) and `git ls-files .env` (prints nothing) |

**Before every commit:** read the `git status --short` list. It should contain code and docs only: no `.env`, no `.venv`, no files from `data\`.

---

## 8. Key ideas explained

| Idea | Plain explanation |
|---|---|
| **API vs scraping** | An API hands you data in a stable structure; scraping copies a web page and breaks when the layout changes. We use official APIs and downloads wherever they exist. |
| **Raw vs processed** | Raw = the original photocopy in the locker. Processed = our cleaned working copy. If cleaning has a bug, we re-run from raw. |
| **SHA-256** | A fingerprint of a file. Change one byte and the fingerprint changes, so we can prove a raw file was not altered. |
| **Manifest** | An append-only logbook of downloads (which file, when, what fingerprint). It makes runs resumable. |
| **Provenance** | The paper trail on every record: where it came from, when we fetched it, and which raw file holds the original. |
| **Validation error vs warning** | Error: the record is unusable, so it is rejected. Warning: usable but unusual, so it is kept and reported. |
| **Rate limit** | How fast a server lets you ask. Going too fast gets you blocked; we pause and retry politely. |
| **Idempotent** | Running it twice gives the same result as once. Our collectors reuse what exists; the Neo4j sync (M10) must behave the same way. |
| **CVE** | A public ID for a specific vulnerability (CVE-2024-3400). |
| **CVSS** | A 0-10 severity score, with versions (2.0, 3.0, 3.1, 4.0). We keep all of them. |
| **CWE** | The *type* of weakness (for example "injection"), not a specific bug. |
| **CPE** | A coded product name such as `cpe:2.3:a:vendor:product:version...`. |
| **KEV** | CISA's list of vulnerabilities confirmed exploited in the wild. **NVD alone never proves exploitation.** |
| **STIX** | A standard JSON format for threat intelligence; links between things are separate objects. |
| **Revoked / deprecated** | ATT&CK retires objects without deleting them. We keep them in raw, drop them from normalized. |
| **Canonical entity** | One official record per real-world thing, however many sources mention it. |
| **Evidence node** | A record that says *which text, from which source, supports which claim*. It is what makes answers checkable. |
| **RAG** | Retrieval-Augmented Generation: find relevant passages first, then let the language model answer from them. |
| **GraphRAG** | RAG that first turns documents into a graph of entities and relationships, groups them into communities, and summarizes each community. Good at "big picture" questions. |
| **Neo4j / Cypher** | A graph database and its query language. Good at exact multi-hop questions ("technique -> group -> campaign"). |
| **Why both GraphRAG and Neo4j** | GraphRAG *discovers* structure in text and summarizes. Neo4j stores the *official, exact* graph with provenance. They need connecting through shared IDs, not duplicating. |
| **Evidence types** | (1) stated in a source, (2) structured authoritative record, (3) LLM-extracted candidate, (4) human-reviewed, (5) inferred. An LLM-extracted claim is **never** "verified" just because a model said it. |

---

## 9. What comes next

### Milestone 3: done, with fixes to confirm
The gate passed on your PC. The fixes from section 3.7 are delivered; re-run CWE (categories must appear) and the advisories collector with `--discover` (at least 50 documents, all dated).

### Milestone 4: raw data audit
Built (section 3.8). It is complete when the audit prints no FAIL on your PC, the advisories reach their target or the shortfall is explained, the generated `RAW_DATA_AUDIT.md` is committed,
and the data dictionary pages stop saying "not verified".

### Milestone 5: canonical model and normalization (the heart of the data layer)
- *Goal:* **one record per real-world thing**, with every source attached as evidence.
- *Example:* CVE-2024-3400 appears in KEV, NVD, and later in advisories. It becomes **one** `Vulnerability`, linked to its `Weakness`, its `Software`, and several `Evidence` records.
- *Tool:* Pydantic schemas for the entities (ThreatActor, Campaign, Malware, AttackTechnique, AttackTactic, Vulnerability, Software, Weakness, Organization, IntelligenceReport, Evidence).
- *Hard parts we already spotted:*
  - KEV vendor/product free text vs NVD CPE codes (needs a careful normalization rule).
  - ATT&CK direction: `campaign attributed-to group` becomes canonical `ThreatActor -CONDUCTS-> Campaign`.
  - ATT&CK `tool` vs `malware` vs canonical `Software`: needs a decision (see section 10).
  - Stable, repeatable IDs so re-runs never create duplicates.
- *Rule:* two things appearing in the same document is **not** a relationship.

### Milestone 6: document processing and chunking (Docling)
- *Goal:* turn advisories into clean text pieces ("chunks") with stable IDs, headings, page numbers, and tables preserved.
- *Analogy:* photocopying the key pages of every report, numbering each page, and highlighting the passages we may quote.
- *New package (large):* Docling. We check Python 3.12 compatibility and disk space on C: first.

### Milestone 7: naive RAG baseline
- *Goal:* the simplest "search then answer" system. Embed chunks, find the closest ones, answer with sources.
- *Why:* every smarter method must beat this baseline, and we cannot claim "better" without measuring.
- *Needs:* a hosted embedding service (BGE-M3 or compatible) and a vector index. No local model downloads.

### Milestone 8: hybrid RAG
- Combine meaning-based search (vectors) with exact-text search (BM25), so that "CVE-2024-3400" is found exactly *and* "remote code execution in a VPN gateway" is found by meaning.
- *New package:* a small BM25 library.

### Milestone 9: Microsoft GraphRAG
- *Goal:* GraphRAG reads a **small** set of advisories (start with 5-10) and produces entities, relationships, communities and community reports.
- *Care:* it makes many LLM calls, so we watch cost; we check the installed version's real commands and output files instead of assuming them;
  if it conflicts with Python 3.12 packages, it gets its own environment.
- *Why communities:* groups of related entities get a short summary, which lets us answer "what patterns appear across these reports?".

### Milestone 10: GraphRAG output to Neo4j
- *Goal:* a one-way, **repeatable** sync (using `MERGE`, so running it twice changes nothing) from our canonical data and GraphRAG output into Neo4j.
- *Rules:* map to canonical types, validate every relationship's endpoints, keep the TextUnit/source reference on everything, batch the writes, log counts.
  Never run two disconnected graphs.
- *Needs:* a Neo4j instance (hosted free tier or local; see section 10) and the `neo4j` Python driver.

### Milestone 11: Neo4j schema and Cypher retrieval
- Constraints and indexes, then ready-made queries: find an entity, one hop, several hops, evidence for a relationship, provenance, "what changed since".
- *Test question:* "Which techniques are documented for this threat actor?" must return techniques **with evidence**, marking *documented* vs *inferred*.

### Milestone 12: MongoDB for the application
- Users, conversations, messages, research jobs, reports, feedback, agent traces. MongoDB holds the *application's* memory, not a copy of the graph. No SQLite.

### Milestone 13: LangGraph supervisor
- *Goal:* one planning agent that chooses the right tool for each question: GraphRAG searches, Neo4j queries, CVE / KEV / CWE / ATT&CK lookups, evidence retrieval.
- *Rule:* research and analysis only. No exploits, no scanning, no destructive actions.
- We start with **one** agent and make it reliable before adding more.

### Milestone 14: evidence verification and live fallback
- *Evidence sufficiency check:* is there relevant, recent, sufficient, non-conflicting evidence from an authoritative source? Zero results is not the only trigger for looking further.
- *Live tools:* ask NVD / KEV / CWE / ATT&CK directly when stored knowledge is stale or missing.
- *Honesty rules:* an API error is reported as a limitation. NVD never proves exploitation. Live results are validated and are not automatically added to the permanent graph.
- *Cool use of what we have:* NVD's CISA fields vs the KEV catalog = a built-in test for detecting conflicting information.

### Milestone 15: reports and FastAPI
- A structured research report (summary, findings, evidence table, source URLs, dates, conflicts, evidence gaps, limitations, references) served through the planned API endpoints
  (`/api/chat`, `/api/research`, `/api/reports/{id}`, `/api/graph/...`, `/api/health`, ...). Only now do we create `backend\main.py`.
- Run with `python -m uvicorn backend.main:app --reload` and open the automatic API docs page.

### Milestone 16: frontend
- Next.js + TypeScript pages: dashboard, research chat, history, report viewer, graph explorer, vulnerability explorer, evidence viewer, analytics.
- Needs Node.js. Every page must show **real** backend data, not mock dashboards.

### Milestone 17: evaluation
- Compare five approaches: naive RAG, hybrid RAG, GraphRAG, Neo4j retrieval, and the combined agentic system.
- A hand-reviewed set of 30-50 questions; measure retrieval quality, answer correctness and faithfulness, citation correctness, tool-selection accuracy, latency, tokens and cost.
- **We never claim one approach is better without measured results.** (A natural place for your thesis-style write-up.)

### Milestone 18: testing, security, deployment
- Integration tests, a security review (authentication, authorization, rate limiting, tenant isolation, secrets), dependency review, then deployment.
- Advisory text is **untrusted input**: it may contain instructions aimed at the language model. The agent treats it as data, never as commands.

---

## 10. Decisions and open items

**Open items from the work so far**

| Item | What is needed |
|---|---|
| NVD and ATT&CK commits | Confirm `git commit` and `git push` succeeded for the NVD and ATT&CK work |
| Real field lists | Run the three field-check commands from the earlier message and paste the output so I can finish the KEV, NVD and ATT&CK data dictionary pages ("verified: NO" today); the CWE and advisories pages follow after their first runs |
| Terms of use | Read each source's usage terms and paste the wording into its data dictionary page |
| Subset rule | The KEV subset (ransomware-linked first, newest first) was kept as the default; tell me if you want a different rule |
| CWE re-run | After the update: run the CWE collector again; categories must show up (several hundred) |
| Advisories re-run | Run with `--discover` (section 7); at least 50 documents, every document dated, Status SUCCESS |
| Seed list | Delete lines for addresses that fail (HTTP 404); the list holds unverified candidates |
| Milestone 4 audit | `python ingestion\validation\audit_raw_data.py --write-doc` must print no FAIL; commit `RAW_DATA_AUDIT.md` |

**Decisions coming up**

| When | Decision | Notes |
|---|---|---|
| Before Milestone 5 | How to map ATT&CK `tool` and `malware` to the canonical model | Option A: both become `Malware` with a `kind` field. Option B: add a separate `Tool` entity. I will recommend one with reasons. |
| Milestone 5 | Add non-KEV CVEs to the NVD set | Today all 150 are KEV-listed, so questions about unexploited vulnerabilities have no data. Easy with `--cve-id`. |
| Milestone 7 | Which hosted embedding and LLM provider | Prefer free or low-cost hosted inference; no large local models. Needs an API key stored in `.env`. |
| Milestone 9 | Cost budget for GraphRAG indexing | Start with 5-10 documents and look at the bill before scaling. |
| Milestone 10 | Neo4j hosting | A hosted free tier avoids using local disk; a local install is also possible. |
| Milestone 12 | MongoDB hosting | Same trade-off: hosted free tier vs local. |
| Before Docling (M6) | Disk space on C: | C: had about 9.46 GB free at the start; Docling and GraphRAG are big. We check before every large install. |

---

## 11. Problems we already met (and the fixes)

| Problem | Cause | Fix |
|---|---|---|
| `cd D:\CyberIntelGraph` failed | Project was extracted elsewhere | Copy it to the chosen drive; scripts use relative paths so they work anywhere |
| "not digitally signed" on every `.ps1` | Files from a downloaded zip are marked as untrusted | `Get-ChildItem -Recurse -File \| Unblock-File`, plus `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| Project inside OneDrive | OneDrive would sync the venv and datasets | Prefer a folder outside OneDrive; the doctor warns, `docs/PROJECT_LOCATION.md` explains the trade-off and how to move |
| `Ran 0 tests`, `can't open file ... [Errno 2]`, `.venv\... not recognized` | The terminal was in the wrong folder (for example an old empty copy still open in VS Code). The update had been extracted elsewhere | `cig`, `cig doctor`; `docs/PROJECT_LOCATION.md`. All scripts find the project from their own location; only your terminal can be in the wrong place |
| `git push` said "Repository not found" | The GitHub repo did not exist yet | Create the empty private repo first, then push |
| Prompt has no `(.venv)` | Environment not activated | `.\.venv\Scripts\Activate.ps1` |
| NVD `403` / `429` | Rate limit | Wait and re-run (it resumes); use the API key |
| Collector crashed when two downloads landed in the same second | Raw files are never overwritten | Found in testing; fixed with a numbered suffix |
| LF/CRLF warnings from Git | Windows line endings | Harmless, ignore |
| CISA feed answers HTTP 403 (reported by other RSS readers too) | The site refuses some connections | Never bypassed: the collector continues with the seed list or `--url` pages; you can copy addresses from your browser into a file |

---

## 12. How we work

For every step, in this order: **current milestone, what and why, exact files, complete code, exact PowerShell commands, expected output,
validation and tests, documentation updates, next step.**

- One milestone at a time; no jumping ahead.
- Nothing is called finished until it ran, was inspected and tested.
- I say plainly what I tested (and where) and what I could not.
- After every verified step: update `CHANGELOG.md` and `PROJECT_STATUS.md`, then commit and push.
- Install only what the current milestone needs, after checking Python 3.12 compatibility and disk space.

**Save this guide inside your project** (after downloading it):
```powershell
cig
Copy-Item "$HOME\Downloads\CyberIntelGraph_Project_Guide.md" .\docs\PROJECT_GUIDE.md
git add docs\PROJECT_GUIDE.md
git commit -m "Add project guide"
git push
```
