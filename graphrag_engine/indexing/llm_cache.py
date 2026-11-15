"""Cached, paced, budgeted LLM calls.

Every response is stored on disk keyed by a hash of (kind, model, prompts), so
  * re-running the index costs nothing for work already done (resume after a rate-limit stop),
  * changing the validator or the graph code never needs new LLM calls,
  * a hard `max_calls` budget protects the free-tier quota.
Prompts are not stored (they can be rebuilt); only the answer text, usage and bookkeeping.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone


class CallBudgetExceeded(RuntimeError):
    pass


class CachedLLM:
    def __init__(self, llm, cache_dir: str, model: str, min_interval: float = 2.5,
                 max_calls: int | None = None, sleep=time.sleep, clock=time.monotonic):
        self.llm, self.dir, self.model = llm, cache_dir, model
        self.min_interval, self.max_calls = min_interval, max_calls
        self._sleep, self._clock = sleep, clock
        self.calls = 0
        self.cache_hits = 0
        self.tokens = 0
        self._last: float | None = None

    def key(self, kind: str, system: str, user: str) -> str:
        h = hashlib.sha256()
        for part in (kind, self.model, system, user):
            h.update(part.encode("utf-8"))
            h.update(b"\x00")
        return h.hexdigest()

    def path(self, key: str) -> str:
        return os.path.join(self.dir, key[:2], f"{key}.json")

    def complete(self, kind: str, system: str, user: str, label: str = "") -> dict:
        """Returns the stored record: {kind, label, key, text, usage, ..., from_cache}."""
        key = self.key(kind, system, user)
        path = self.path(key)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                rec = json.load(fh)
            self.cache_hits += 1
            rec["from_cache"] = True
            return rec
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise CallBudgetExceeded(f"call budget of {self.max_calls} reached; re-run to resume "
                                     "(finished work is cached)")
        if self._last is not None:
            wait = self.min_interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        res = self.llm.complete(system, user)
        self._last = self._clock()
        self.calls += 1
        self.tokens += int((res.usage or {}).get("total_tokens") or 0)
        rec = {"kind": kind, "label": label, "key": key, "model": res.model, "text": res.text,
               "finish_reason": res.finish_reason, "usage": res.usage, "user_chars": len(user),
               "created_at": datetime.now(timezone.utc).isoformat()}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(rec, fh, ensure_ascii=False)
        os.replace(tmp, path)
        rec["from_cache"] = False
        return rec

    def relpath(self, rec: dict) -> str:
        return os.path.relpath(self.path(rec["key"])).replace(os.sep, "/")
