# Change report - Milestone 9: GraphRAG indexing (own extraction pipeline)

## What was built
`graphrag_engine/` - select a small advisory subset, extract entities and relationships with the LLM
(every item grounded in the text and tagged `llm_extracted_candidate`), merge and link to the canonical
graph, detect communities (Louvain), write community reports, answer broad questions with global search.
Decision 0011 explains why this is our own lightweight implementation of the GraphRAG method rather than
the `graphrag` package.

## Run summary (model openai/gpt-oss-20b, prompt v1, seed 42)
| Item | Value |
|---|---|
| Advisories read | 5 |
| Extraction windows (= calls) | 20 (ok 22, failed 0) |
| New LLM calls this run / cache hits | 3 / 32 |
| Tokens used this run | 14982 |
| Entities | 220 (linked to canonical ids 101, found in canonical graph 101, ambiguous 1) |
| Relationships | 165 |
| LLM output before grounding | 328 entities, 204 relationships |
| Dropped by grounding checks | {"entity_not_in_text": 18, "rel_unknown_endpoint": 23, "entity_bad_type": 1} |
| Communities | 62 (singletons 37, reported 12) |

## Community reports
- **C000** (30 entities): Russian Military Cyber Actors Exploit Multiple High‑Impact Vulnerabilities Against Critical Infrastructure - Russian Military Cyber Actors (RMCA) are actively exploiting a suite of CVEs—including ZeroLogon (CVE‑2020‑1472), JetBrains TeamCity (CVE‑2023‑42793), Citrix NetScaler (CVE‑2023‑35
- **C001** (29 entities): Russian State‑Sponsored APT Tactics and Targeting Overview - Russian state‑sponsored APT actors employ a broad arsenal of techniques—including credential theft via Kerberoasting, multi‑hop proxies, password guessing/spraying, and private key
- **C002** (26 entities): APT40 Operational Profile and Tactics - APT40, a China MSS‑affiliated threat actor, employs a broad malware library—including China Chopper, Gh0stRAT, Cobalt Strike, and others—to conduct cyber‑espionage. The group lever
- **C003** (12 entities): APT Tool for Schneider Electric Exploits Multi‑Stage Attack Techniques - The APT tool used against Schneider Electric ICs leverages a broad spectrum of ATT&CK techniques, spanning discovery, persistence, lateral movement, execution, collection, and comm
- **C004** (11 entities): Iranian APT Exploitation of Microsoft Exchange Vulnerabilities - Iranian government‑sponsored APT actors have been observed exploiting multiple Microsoft Exchange Server vulnerabilities, including CVE‑2021‑34473, CVE‑2021‑26855, CVE‑2021‑26857, 
- **C005** (8 entities): Accellion File Transfer Appliance Vulnerabilities (CVE-2021-27101 to CVE-2021-27104) - The Accellion File Transfer Appliance (FTA) is affected by four critical CVEs (27101‑27104). All four vulnerabilities impact FTA versions 9.12.411 and earlier, with CVE‑27104 also 
- **C006** (7 entities): CVE-2021-42237 Exploitation Across Sitecore XP Versions - CVE-2021-42237 is a critical vulnerability affecting multiple Sitecore XP releases from 7.5.0 through 8.2.7. The advisory confirms that the flaw is exploitable in each affected ver
- **C007** (6 entities): APT Actors Deploy Custom Tools Against OMRON, Schneider, and OPC UA Systems - Advanced persistent threat actors have engineered custom tools to compromise industrial control systems, specifically targeting OMRON and Schneider Electric PLCs as well as OPC UA 
- **C008** (5 entities): CVE-2021-35464 Impact on Oracle Access Management Products - CVE-2021-35464 is a critical vulnerability that affects multiple versions of Oracle Access Management (AM) and OpenAM. The flaw allows attackers to exploit the systems, potentially
- **C009** (4 entities): Log4j and ADSelfService Vulnerability Landscape - The advisory highlights two critical CVEs impacting Apache Log4j and ADSelfService Plus. CVE-2021-44228 (Log4Shell) directly exploits Log4j, while CVE-2021-40539 both exploits Log4
- **C010** (4 entities): CVE-2023-27997: Remote Code Execution in Fortinet FortiOS and FortiProxy SSL‑VPN - CVE‑2023‑27997 is a critical remote code execution vulnerability affecting Fortinet FortiOS firmware (including FortiOS‑6K7K) and FortiProxy SSL‑VPN. The flaw allows attackers to e
- **C011** (4 entities): CVE-2021-34527 Exploitation Across Microsoft Exchange Server Versions - CVE-2021-34527, a critical vulnerability, is confirmed to exploit Microsoft Exchange Server 2013, 2016, and 2019. The same advisory indicates that all three versions are affected, 
