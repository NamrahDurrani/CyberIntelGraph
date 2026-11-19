"""Find out WHERE a Milestone 10 command waits. Run it exactly like the export:

    python scripts\\diagnose_export_hang.py            # times every import and file read, then runs the real export
    python scripts\\diagnose_export_hang.py --timeout 40

If anything is still running after --timeout seconds, Python prints the stack of the line it is stuck on and exits,
so the last lines of this output say exactly which step (import, file read, mapping, write) is the slow one.
"""
from __future__ import annotations

import argparse
import faulthandler
import glob
import os
import runpy
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--timeout", type=float, default=60.0)
ap.add_argument("--data", default=os.path.join("data", "graphrag_outputs"))
ap.add_argument("--canonical", default=os.path.join("data", "canonical", "entities.json"))
a = ap.parse_args()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
faulthandler.dump_traceback_later(a.timeout, exit=True)
T0 = time.time()


def step(name, fn):
    t = time.time()
    print(f"[{time.time() - T0:6.1f}s] start : {name}", flush=True)
    fn()
    print(f"[{time.time() - T0:6.1f}s] done  : {name} ({time.time() - t:.1f}s)", flush=True)


print(f"python {sys.version.split()[0]} | prefix {sys.prefix} | cwd {os.getcwd()}", flush=True)
step("import pandas", lambda: __import__("pandas"))
step("import pyarrow.parquet", lambda: __import__("pyarrow.parquet"))
step("import pydantic", lambda: __import__("pydantic"))
step("import canonical.models", lambda: __import__("canonical.models"))
step("import graphrag_engine.export.mapping", lambda: __import__("graphrag_engine.export.mapping"))
for pattern in (os.path.join(a.data, "output", "*.parquet"), a.canonical, os.path.join(a.data, "input", "*")):
    for f in sorted(glob.glob(pattern)):
        print(f"           file  : {os.path.relpath(f)}  {os.path.getsize(f) / 1e6:.2f} MB", flush=True)
sys.argv = [os.path.join("graphrag_engine", "export", "export_graphrag.py")]
step("run the real export_graphrag.py", lambda: runpy.run_path(os.path.join(ROOT, "graphrag_engine", "export", "export_graphrag.py"),
                                                                run_name="__main__"))
faulthandler.cancel_dump_traceback_later()
print("finished without hanging", flush=True)
