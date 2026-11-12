# Decision 0007 - Advisory parsing with Docling (HTML only) and own chunker

Status: accepted - 2026-11-11

## Context
The 61 raw advisory files are HTML (53 become documents). Docling is the tool named
in the project guide. It installs PyTorch (about 2 GB); the machine had under 1 GB
free, then about 5 GB, so install size mattered.

## Decisions
1. **Docling for parsing, HTML only.** `DocumentConverter(allowed_formats=[HTML])`
   loads no layout/table AI models, so no model download (those add 0.5-1.4 GB and
   are only needed for PDFs).
2. **Own chunker, not Docling's HybridChunker.** HybridChunker downloads a tokenizer
   and ties chunk sizes to it. Our chunker works on a parser-independent `Block`
   list, is deterministic, and is unit-tested without Docling.
3. **Chunk rules:** never cross a heading; max 250 words (sentence boundaries; a
   table is its own chunk, split by rows with the header repeated); chunks under 8
   words are dropped unless they contain a CVE or ATT&CK id; no overlap.
4. **Stable ids:** `advisory_<last URL segment>_chunk_NNN`; collisions get a short hash.
   `report_id` equals the canonical `IntelligenceReport:<slug>` id so chunks link to the graph.
5. **Traceability:** every chunk stores source URL, published/retrieved dates, raw file
   reference, raw-file SHA-256, parser version and a content hash.
6. **Embedding text** = heading path + text, so each chunk carries its context.

## Consequences
PDFs later will need Docling's models (extras / model download) and a re-run.
The parser interface (`parse(path) -> list[Block]`) lets another parser be swapped in.
