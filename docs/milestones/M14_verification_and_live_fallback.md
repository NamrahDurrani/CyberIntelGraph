# Milestone 14 - Independent verification, live fallback and MongoDB persistence

## The idea in one picture
Milestone 13 produced an answer written by a "writer". Milestone 14 adds a **separate auditor** who never saw the
analysts' confidence and only looks at the exhibits (evidence). The auditor asks of every statement: *is it written in
the exhibit it points to?* If the stored files might be old, a **fact-checker** phones the official source (CISA KEV and
NVD) and adds the fresh answer as a new, dated, hash-stamped exhibit. If the phone line is dead, the file says
"could not check" - never "does not exist".

## What was added
| Part | File | What it does |
|---|---|---|
| Live fallback | `cti_verification/fresh.py`, `nodes.py` | live CISA KEV + NVD for CVEs in the question (or "latest KEV additions"); cached under `data/fresh_cache/` with URL, time and SHA-256; stale cache is used only if the download fails, and is labelled stale; compares the graph copy with the live record (last-modified date, CVSS) |
| Verification agent | `verification_agent.py`, `verifier.py`, `claims.py` | checks structured claims, the written answer sentence by sentence, contradictions and sufficiency |
| Corrective rewrite | `verify_node.py` | on FAIL, asks the writer for ONE corrected answer; kept only if it verifies better |
| Persistence | `persistence.py` | saves the investigation and per-agent traces to MongoDB (idempotent upsert) |
| Hooks | `hooks.py` | plugs into the three Milestone 13 hook points; no Milestone 13 file is edited |

## Outcomes
| Outcome | Meaning |
|---|---|
| `PASS` | claims meet the evidence and validation requirements |
| `PARTIAL` | some claims supported; others are marked `[CHECK]` (partly backed / stated too strongly) or `[UNVERIFIED]` and explained |
| `FAIL` | critical claims lack evidence, cite evidence that does not exist, or use invalid / absent identifiers (CVE, CWE, ATT&CK) - or at least half the answer is unsupported |
| `TOOL_ERROR` | a live source needed for verification could not be reached. Not a verdict on the claims, and not evidence of absence |

## What the verification agent checks
1. **Structured claims:** cited evidence exists; a `documented` claim is backed by authoritative / document evidence (otherwise it is
   downgraded to candidate / inferred / unverified); every CVE / CWE / ATT&CK id has a valid format and appears in the cited evidence;
   evidence has a source; dates parse.
2. **The written answer:** identifiers, names, numbers and wording must be present in the cited evidence; candidate or inferred evidence
   may not be stated as fact; "confirmed" needs authoritative evidence. The optional LLM judge (`VERIFY_USE_LLM_JUDGE=true`) can only
   downgrade a verdict, never upgrade it.
3. **Contradictions:** found vs not found; stored vs live (date, CVSS, KEV listing).
4. **Sufficiency:** relevance, freshness, authority, completeness, consistency, each ok / warn / fail.

## MongoDB persistence - read this
Saved to two NEW collections, `investigation_runs` and `investigation_traces`, not to your Milestone 12 `reports` / `agent_traces`
repositories. Reason: those collections have server-side schema validators and their code could not be inspected when this was built;
writing to them blindly could be rejected. Milestone 15 (reports + FastAPI) should move this data into the validated repositories.
The JSON file under `outputs/investigations/` is written first, so a database problem never loses a result.
Only ids, summaries, sources and excerpts of at most 1,000 characters are stored; credentials are scrubbed; the graph is not copied.

## Settings (`.env`, all optional)
`FRESH_LOOKUP_ENABLED` (true), `NVD_API_KEY`, `FRESH_CACHE_TTL_HOURS` (12), `FRESH_MAX_CVES` (5), `FRESH_RECENT_KEV_COUNT` (5),
`FRESH_HTTP_TIMEOUT` (30), `VERIFY_USE_LLM_JUDGE` (false), `VERIFY_MIN_OVERLAP` (0.5), `VERIFY_MAX_REWRITES` (1), `PERSIST_MONGO` (true),
`MONGODB_URI` / `MONGODB_DATABASE`. Without an NVD key the agent waits 6.5 s between NVD calls (public limit).

## Known limits
- On FAIL the agent rewrites the answer once; it does **not** re-run specialist agents. Missing or stale evidence is handled earlier by
  the live fallback.
- Verification is lexical and identifier based: it catches invented ids, names, numbers and unsupported wording, not subtle reasoning errors.
- The live fallback covers CISA KEV and NVD only. CWE, ATT&CK and advisory refreshes are not live-checked.
- Comparing graph vs live needs the graph node to store a last-modified date or a CVSS score; otherwise it records "nothing to compare".
- Live runs of the new scripts need your internet / Atlas; they could not be run where this was built, only the offline checks were.
