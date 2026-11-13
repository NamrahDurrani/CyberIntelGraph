"""LLM clients. The answer step only needs  complete(system, user) -> LLMResult,
so Groq can be swapped for Anthropic, OpenAI or a local model without other changes."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"
RETRY_STATUS = {429, 500, 502, 503, 504}


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    text: str
    model: str
    finish_reason: str | None = None
    usage: dict = field(default_factory=dict)
    latency_s: float = 0.0


def load_api_key(name: str = "GROQ_API_KEY", env_path: str = ".env") -> str:
    """Key from the environment, else from a .env file. Never printed or stored."""
    v = os.environ.get(name, "").strip()
    if v:
        return v
    if os.path.isfile(env_path):
        with open(env_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, val = line.partition("=")
                    if k.strip() == name and val.strip().strip("'\""):
                        return val.strip().strip("'\"")
    raise LLMError(f"{name} is not set. In PowerShell:  $env:{name}=\"<your key>\"   "
                   f"(this window only) or add a line {name}=<your key> to .env (ignored by Git).")


class GroqClient:
    """Groq's OpenAI-compatible chat API using only the standard library."""
    name = "groq"

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_GROQ_MODEL,
                 max_completion_tokens: int = 1500, reasoning_effort: str | None = "low",
                 temperature: float = 0.2, timeout: float = 90, max_retries: int = 4,
                 urlopen=None, sleep=None):
        self._key = api_key
        self.model = model
        self.max_completion_tokens = max_completion_tokens
        self.reasoning_effort = reasoning_effort
        self.temperature = temperature
        self.timeout, self.max_retries = timeout, max_retries
        self._urlopen = urlopen or urllib.request.urlopen
        self._sleep = sleep or time.sleep

    def _scrub(self, text: str) -> str:
        return text.replace(self._key, "***") if self._key else text

    def complete(self, system: str, user: str) -> LLMResult:
        if not self._key:
            self._key = load_api_key()
        payload = {"model": self.model, "temperature": self.temperature,
                   "max_completion_tokens": self.max_completion_tokens,
                   "messages": [{"role": "system", "content": system},
                                {"role": "user", "content": user}]}
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        body = json.dumps(payload).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json",
                   "User-Agent": "CyberIntelGraph/1.0"}
        t0 = time.time()
        last = ""
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(GROQ_URL, data=body, headers=headers, method="POST")
            try:
                with self._urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as ex:
                detail = self._scrub(ex.read().decode("utf-8", "replace")[:300]) if hasattr(ex, "read") else ""
                last = f"Groq HTTP {ex.code}: {detail}"
                if ex.code not in RETRY_STATUS or attempt == self.max_retries:
                    raise LLMError(last) from None
                try:
                    wait = float(ex.headers.get("retry-after")) if ex.headers else None
                except (TypeError, ValueError):
                    wait = None
                self._sleep(min(wait if wait is not None else 2 ** attempt * 2, 60))
            except (urllib.error.URLError, TimeoutError) as ex:
                last = f"network error: {self._scrub(str(ex))}"
                if attempt == self.max_retries:
                    raise LLMError(last) from None
                self._sleep(min(2 ** attempt * 2, 60))
        choice = (data.get("choices") or [{}])[0]
        text = ((choice.get("message") or {}).get("content") or "").strip()
        finish = choice.get("finish_reason")
        if not text:
            hint = (" The model used all its tokens on reasoning; raise --max-tokens."
                    if finish == "length" else "")
            raise LLMError(f"empty answer (finish_reason={finish}).{hint}")
        return LLMResult(text=text, model=data.get("model", self.model), finish_reason=finish,
                         usage=data.get("usage") or {}, latency_s=round(time.time() - t0, 2))
