"""Print the real field names of every processed file, so the canonical
builder's field aliases can be confirmed. Run before the first canonical build."""
import glob
import json
import os
from collections import Counter

for path in sorted(glob.glob(os.path.join("data", "processed", "*.json"))):
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    recs = d.get("records", []) if isinstance(d, dict) else d
    keys = Counter(k for r in recs[:200] if isinstance(r, dict) for k in r)
    print(f"\n{os.path.basename(path)}  ({len(recs)} records)")
    print("  fields:", ", ".join(f"{k}" for k, _ in keys.most_common()))
    if recs and isinstance(recs[0], dict):
        for k, v in list(recs[0].items())[:30]:
            print(f"    {k}: {str(v)[:70]!r}")
