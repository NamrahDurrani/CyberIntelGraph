"""LLM access (Groq, OpenAI-compatible endpoint). Kept behind a tiny interface
so the whole agent can be tested offline with a fake LLM."""

from __future__ import annotations

import json
import re
import time
from typing import Protocol

from .config import Settings

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


class LLMUnavailable(RuntimeError):
    """Raised when no LLM can be used (no key, disabled, or the API failed)."""


class LLM(Protocol):
    def complete(self, system: str, user: str, *, max_tokens: int | None = None) -> str: ...


class NullLLM:
    def complete(self, system: str, user: str, *, max_tokens: int | None = None) -> str:
        raise LLMUnavailable("LLM disabled or GROQ_API_KEY missing")


class GroqLLM:
    def __init__(self, settings: Settings):
        self._s = settings

    def complete(self, system: str, user: str, *, max_tokens: int | None = None) -> str:
        import requests

        payload = {
            "model": self._s.groq_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_completion_tokens": max_tokens or self._s.llm_max_tokens,
        }
        if self._s.groq_reasoning_effort:
            payload["reasoning_effort"] = self._s.groq_reasoning_effort
        headers = {"Authorization": f"Bearer {self._s.groq_api_key}", "Content-Type": "application/json"}

        last_error = "unknown error"
        for attempt in range(3):
            try:
                resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=self._s.llm_timeout)
            except requests.RequestException as exc:
                last_error = f"network error: {exc}"
                time.sleep(1.5 * (attempt + 1))
                continue
            if resp.status_code == 400 and "max_completion_tokens" in resp.text and "max_completion_tokens" in payload:
                payload["max_tokens"] = payload.pop("max_completion_tokens")
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                last_error = f"HTTP {resp.status_code}"
                time.sleep(2.0 * (attempt + 1))
                continue
            if resp.status_code != 200:
                raise LLMUnavailable(f"Groq HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                return resp.json()["choices"][0]["message"]["content"] or ""
            except (KeyError, IndexError, ValueError) as exc:
                raise LLMUnavailable(f"Unexpected Groq response: {exc}") from exc
        raise LLMUnavailable(f"Groq request failed: {last_error}")


def build_llm(settings: Settings) -> LLM:
    if not settings.use_llm or not settings.groq_api_key:
        return NullLLM()
    return GroqLLM(settings)


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model reply (tolerates code fences)."""
    if not text:
        raise ValueError("empty reply")
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE)
    try:
        return json.loads(cleaned)
    except ValueError:
        pass
    match = _JSON_OBJECT.search(cleaned)
    if not match:
        raise ValueError("no JSON object found")
    return json.loads(match.group(0))
