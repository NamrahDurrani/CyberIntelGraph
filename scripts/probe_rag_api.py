r"""Lists retrieval-like functions in your rag package (Milestones 7-8) so the
agent can be connected to your existing hybrid retriever through RAG_RETRIEVER.

  python scripts\probe_rag_api.py
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys

import _bootstrap  # noqa: F401

KEYWORDS = ("retriev", "search", "hybrid", "query", "ask")


def main() -> int:
    try:
        pkg = importlib.import_module("rag")
    except ImportError as exc:
        print(f"Cannot import the 'rag' package: {exc}")
        return 2
    print("Candidate retrieval functions (use as RAG_RETRIEVER=module:function):\n")
    found = 0
    for info in pkgutil.walk_packages(pkg.__path__, prefix="rag."):
        try:
            module = importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001
            print(f"  (skipped {info.name}: {type(exc).__name__})")
            continue
        for name, fn in inspect.getmembers(module, inspect.isfunction):
            if fn.__module__ != module.__name__ or name.startswith("_"):
                continue
            if any(k in name.lower() for k in KEYWORDS):
                found += 1
                print(f"  {info.name}:{name}{inspect.signature(fn)}")
    if not found:
        print("  none found")
    print("\nNext: add  RAG_RETRIEVER=module:function  to .env, or send this list back.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
