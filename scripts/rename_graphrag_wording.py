"""Remove the "GraphRAG-style" wording from files already committed (idempotent). Run from the project root."""
import glob
import os

REPL = [("GraphRAG-style indexing", "GraphRAG indexing (own extraction pipeline)"),
        ("GraphRAG-style index", "GraphRAG index (own extraction pipeline)"),
        ('Keeping the name\n   "GraphRAG-style" in documents; ', "Superseded for the official run by decision 0012; "),
        ("## Milestone 9 - done", "## Milestone 9 - own pipeline done; official GraphRAG run pending (decision 0012)"),
        ("GraphRAG-style", "GraphRAG")]
FILES = ["CHANGELOG.md", "PROJECT_STATUS.md", "graphrag_engine/__init__.py", "scripts/apply_milestone_9_docs.py",
         "docs/pipeline/13_graphrag.md", "docs/decisions/0011-graphrag-lite.md", "docs/decisions/0011-own-graphrag-pipeline.md"]
FILES += glob.glob("docs/CHANGE_REPORT_*_M9_graphrag.md")

old, new = "docs/decisions/0011-graphrag-lite.md", "docs/decisions/0011-own-graphrag-pipeline.md"
if os.path.exists(old) and not os.path.exists(new):
    os.replace(old, new)
    print(f"renamed {old} -> {new}")
changed = 0
for path in FILES:
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8", newline="") as fh:
        text = fh.read()
    t = text
    for a, b in REPL:
        t = t.replace(a, b)
    if path.endswith("0011-own-graphrag-pipeline.md"):
        t = t.replace("Status: accepted - 2026-11-14",
                      "Status: partly superseded by decision 0012 (the official GraphRAG run). This pipeline stays as our grounded-extraction baseline.")
        t = t.replace("# Decision 0011 - GraphRAG method, own lightweight implementation (Milestone 9)",
                      "# Decision 0011 - Our own GraphRAG extraction pipeline (baseline)")
    if t != text:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(t)
        changed += 1
        print("updated", path)
print(f"done: {changed} file(s) changed")
