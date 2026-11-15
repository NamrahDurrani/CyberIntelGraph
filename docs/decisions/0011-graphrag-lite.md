# Decision 0011 - GraphRAG method, own lightweight implementation (Milestone 9)

Status: accepted - 2026-11-14

## Context
The roadmap says "Microsoft GraphRAG on a small advisory subset". A dry-run of `pip install graphrag`
(version 3.3.0) lists about 100 packages, including spaCy, LanceDB, LiteLLM, PyArrow, FastAPI and the Azure
and AWS SDKs, on a machine whose free disk space was a recurring problem (decision 0007). The package also
needs an embeddings endpoint (Groq offers none) and makes hundreds of LLM calls, against free-tier limits
that were never verified (project report, section 15).

## Decisions
1. Implement the same METHOD ourselves in `graphrag_engine/`: extract entities and relationships with an LLM,
   build a graph, detect communities, write community reports, answer broad questions by map-reduce over the
   reports (global search). One new small dependency: `networkx`.
2. Differences from Microsoft's package, stated openly: Louvain (one level) instead of hierarchical Leiden; no
   local-search / embedding index; extraction prompt and report format are ours. Keeping the name
   "GraphRAG-style" in documents; the official package stays possible later as a comparison (Milestone 17).
3. Cost control is part of the design: 5 advisories by default, text packed into ~1,400-word windows
   (about 7 calls per advisory instead of one per chunk), a hard `--max-calls` budget, pacing between calls,
   an on-disk cache so a rate-limit stop resumes without repeating work, and `--dry-run` that estimates cost first.
4. Everything the LLM returns is a CANDIDATE: evidence type `llm_extracted_candidate`, grounded in the text
   (entity names must occur; relationship quotes must occur) before it is kept; dropped counts are reported.
5. Candidates are never written into the canonical graph here. CVE and ATT&CK ids reuse the canonical id format;
   names are linked only when exactly one compatible canonical entity matches; otherwise the id is
   `<Type>:cand-<slug>`. Merging into Neo4j is Milestone 10.
