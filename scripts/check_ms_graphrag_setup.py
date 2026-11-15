"""Preflight for Microsoft GraphRAG (Milestone 9). Run it in the GRAPHRAG venv, from the project root.

    python scripts\\check_ms_graphrag_setup.py              # checks only
    python scripts\\check_ms_graphrag_setup.py --init-prompts   # copy GraphRAG's default prompt files into the workspace
It never prints your API key.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--root", default=os.path.join("graphrag_engine", "indexing", "ms"))
ap.add_argument("--data", default=os.path.join("data", "graphrag_outputs"))
ap.add_argument("--embed-url", default="http://127.0.0.1:8008/v1")
ap.add_argument("--init-prompts", action="store_true")
a = ap.parse_args()
# GraphRAG's config loader changes the working directory, so every path is made absolute FIRST
a.root, a.data = os.path.abspath(a.root), os.path.abspath(a.data)
fails = 0


def check(ok, msg, level="FAIL"):
    global fails
    print(f"  [{'PASS' if ok else level}] {msg}")
    if not ok and level == "FAIL":
        fails += 1


print("Checking the Microsoft GraphRAG setup ...")
print(f"  (info) python {sys.version.split()[0]} in {sys.prefix}")
try:
    from importlib.metadata import version
    gv = version("graphrag")
except Exception:                                                        # noqa: BLE001
    gv = None
check(gv is not None, f"graphrag is installed ({gv})" if gv else "graphrag is NOT installed in this environment (use the dedicated .venv-graphrag)")

prompts = os.path.join(a.root, "prompts")
if a.init_prompts and not os.path.isdir(prompts) and gv:
    tmp = tempfile.mkdtemp()
    try:                                  # "python -m graphrag" works without the venv's Scripts folder on PATH
        subprocess.run([sys.executable, "-m", "graphrag", "init", "--root", tmp, "--model", "gpt-4.1",
                        "--embedding", "text-embedding-3-large"], check=True, capture_output=True, timeout=300)
        shutil.copytree(os.path.join(tmp, "prompts"), prompts)
        print(f"  (info) copied GraphRAG's default prompts into {prompts}")
    except (subprocess.SubprocessError, OSError) as ex:
        print(f"  [FAIL] could not create the prompt files with `graphrag init`: {str(ex)[:150]}")
        fails += 1
check(os.path.isfile(os.path.join(a.root, "settings.yaml")), "settings.yaml exists in the workspace")
check(os.path.isdir(prompts) and len(glob.glob(os.path.join(prompts, "*.txt"))) >= 5,
      "prompt files exist" + ("" if os.path.isdir(prompts) else "  -> run this script with --init-prompts"))

key = os.environ.get("GROQ_API_KEY", "")
check(bool(key) and "paste_your_key" not in key, "GROQ_API_KEY is set in this PowerShell session")
if gv and os.path.isfile(os.path.join(a.root, "settings.yaml")) and os.path.isdir(prompts):
    try:
        from graphrag.config.load_config import load_config
        cfg = load_config(root_dir=a.root)
        m = cfg.completion_models["default_completion_model"]
        rl = m.rate_limit
        check(True, f"settings.yaml loads in GraphRAG: {m.model_provider}/{m.model}, chunks of {cfg.chunking.size} tokens, "
                    f"{len(cfg.extract_graph.entity_types)} entity types")
        print(f"  (info) rate limits in settings: {getattr(rl, 'requests_per_period', None)} requests and "
              f"{getattr(rl, 'tokens_per_period', None)} tokens per {getattr(rl, 'period_in_seconds', 60)}s - compare with "
              "console.groq.com/settings/limits")
    except Exception as ex:                                              # noqa: BLE001
        check(False, f"settings.yaml failed to load: {str(ex)[:200]}")

files = sorted(glob.glob(os.path.join(a.data, "input", "*.txt")))
check(bool(files), f"{len(files)} advisory file(s) in {os.path.join(a.data, 'input')}  (run scripts\\prepare_ms_graphrag_input.py)")
check(os.path.isfile(os.path.join(a.data, "input_manifest.json")), "input_manifest.json exists (maps text back to our chunk ids)")
if files:
    chars = sum(os.path.getsize(f) for f in files)
    units = math.ceil(chars / 4 / 450)
    print(f"  (info) ~{chars // 4:,} input tokens -> about {units} extraction calls; GraphRAG adds description-summary "
          "and community-report calls (count unknown until it runs)")

try:
    req = urllib.request.Request(a.embed_url.rstrip("/") + "/embeddings", method="POST",
                                 data=json.dumps({"model": "bge-small-en-v1.5", "input": ["ping"]}).encode(),
                                 headers={"Content-Type": "application/json"})
    dim = len(json.load(urllib.request.urlopen(req, timeout=10))["data"][0]["embedding"])
    check(True, f"embeddings server answers at {a.embed_url} (dimension {dim})")
except Exception as ex:                                                  # noqa: BLE001
    check(False, f"embeddings server not reachable at {a.embed_url} ({type(ex).__name__}) - start scripts\\serve_local_embeddings.py in another window")

free = shutil.disk_usage(a.data if os.path.isdir(a.data) else os.path.dirname(a.data)).free / 1e9
check(free >= 3.0, f"free disk space {free:.1f} GB (GraphRAG's own environment alone is about 1.3 GB)", "WARN")
try:
    import tiktoken
    tiktoken.get_encoding("o200k_base")
    check(True, "tiktoken encoding o200k_base is available")
except Exception as ex:                                                  # noqa: BLE001
    check(False, f"tiktoken could not load o200k_base ({type(ex).__name__}); the first run downloads it, so internet is needed", "WARN")

print("\nRESULT:", "READY" if not fails else f"{fails} CHECK(S) FAILED")
sys.exit(1 if fails else 0)
