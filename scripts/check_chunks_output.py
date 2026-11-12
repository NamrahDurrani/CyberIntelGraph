"""Independent check of data/processed/advisory_chunks.jsonl (trusts nothing)."""
import hashlib
import json
import os
import re
import sys

OUT = os.path.join("data", "processed", "advisory_chunks.jsonl")
MAN = os.path.join("data", "processed", "advisory_chunks_manifest.json")
CANON = os.path.join("data", "canonical", "entities.json")
fails = 0


def check(ok, msg, level="FAIL"):
    global fails
    print(f"  [{'PASS' if ok else level}] {msg}")
    if not ok and level == "FAIL":
        fails += 1


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


print("Checking advisory chunks ...")
with open(OUT, encoding="utf-8") as fh:
    rows = [json.loads(line) for line in fh if line.strip()]
with open(MAN, encoding="utf-8") as fh:
    man = json.load(fh)
max_words = man["params"]["max_words"]

ids = [r["chunk_id"] for r in rows]
check(bool(rows), f"{len(rows)} chunks written")
check(len(ids) == len(set(ids)), "chunk ids unique")
check(all(re.match(r"^advisory_[a-z0-9-]+_chunk_\d{3,}$", i) for i in ids), "chunk ids follow advisory_<doc>_chunk_NNN")
check(len(rows) == man["chunks"], "chunk count matches the manifest")
docs = {r["doc_id"] for r in rows}
check(len(docs) == man["documents_chunked"], f"{len(docs)} documents chunked, as the manifest says")
check(all(r["text"].strip() for r in rows), "no empty chunk text")
check(all(r["source_url"] for r in rows), "every chunk has a source_url", "WARN")
check(all(isinstance(r["heading_path"], list) for r in rows), "heading_path is always a list")
over = [r["chunk_id"] for r in rows if r["word_count"] > max_words * 1.2 and "table" not in r["kinds"]]
check(not over, f"no text chunk is more than 20% over {max_words} words")
check(all(r["word_count"] == len(r["text"].split()) for r in rows), "word_count is accurate")
check(all(hashlib.sha256(r["text"].encode("utf-8")).hexdigest() == r["content_sha256"] for r in rows),
      "content_sha256 matches the text")

# every doc has consecutive chunk numbers starting at 1
by = {}
for r in rows:
    by.setdefault(r["doc_id"], []).append(r["chunk_index"])
check(all(sorted(v) == list(range(1, len(v) + 1)) for v in by.values()), "chunk numbers are 1..n per document")

# traceability: the raw HTML each chunk came from still matches its recorded hash
missing, changed = set(), set()
seen = {}
for r in rows:
    ref = r["raw_file_reference"]
    if not ref:
        missing.add(r["doc_id"])
        continue
    p = ref if os.path.isfile(ref) else os.path.join("data", "raw", "advisories", os.path.basename(ref.replace("\\", "/")))
    if not os.path.isfile(p):
        missing.add(r["doc_id"])
        continue
    if p not in seen:
        seen[p] = sha(p)
    if seen[p] != r["raw_sha256"]:
        changed.add(r["doc_id"])
check(not missing, "every chunk's raw HTML file still exists")
check(not changed, "every raw HTML file still matches its recorded SHA-256")

if os.path.exists(CANON):
    with open(CANON, encoding="utf-8") as fh:
        reports = {e["canonical_id"] for e in json.load(fh)["records"] if e["entity_type"] == "IntelligenceReport"}
    unlinked = {r["report_id"] for r in rows} - reports
    check(not unlinked, f"every chunk's report_id exists in the canonical graph ({len(reports)} reports)", "WARN")
else:
    print("  (info) data/canonical not found - report_id link check skipped")

print(f"  (info) failed documents: {man['documents_failed']}  | words/chunk: {man['words_per_chunk']}")
print(f"  (info) chunks mentioning a CVE: {sum(1 for r in rows if r['cve_ids'])}; a technique id: {sum(1 for r in rows if r['technique_ids'])}")
print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
