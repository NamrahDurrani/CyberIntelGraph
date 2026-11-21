"""Live lookups of CISA KEV and NVD.

Rules (project principles):
  * Fresh data is cached under data/fresh_cache/ ONLY. data/raw/ is never touched.
  * Every cached payload keeps its URL, retrieval time and SHA-256 hash.
  * A failed download is reported as "unable to verify", never as "not found".
  * If a download fails but an older cached copy exists, the old copy is used and
    clearly marked stale.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from .settings import VerifySettings

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class FetchError(RuntimeError):
    pass


@dataclass
class FetchResult:
    payload: Any
    sha256: str
    url: str
    retrieved_at: str


class Fetcher(Protocol):
    def get_json(self, url: str, params: dict | None = None, headers: dict | None = None) -> FetchResult: ...


class HttpFetcher:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def get_json(self, url: str, params: dict | None = None, headers: dict | None = None) -> FetchResult:
        import requests

        try:
            resp = requests.get(url, params=params, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise FetchError(f"network error for {url}: {exc}") from exc
        if resp.status_code != 200:
            raise FetchError(f"HTTP {resp.status_code} from {url}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise FetchError(f"{url} did not return JSON") from exc
        return FetchResult(payload, hashlib.sha256(resp.content).hexdigest(), resp.url,
                           datetime.now(timezone.utc).isoformat())


@dataclass
class Cached:
    payload: Any
    sha256: str
    url: str
    retrieved_at: str
    stale: bool = False


class LiveSources:
    """KEV + NVD access with a file cache and an injectable fetcher / clock."""

    def __init__(self, settings: VerifySettings, cache_root: Path, fetcher: Fetcher | None = None,
                 now: Callable[[], datetime] | None = None, sleep: Callable[[float], None] = time.sleep):
        self.s = settings
        self.root = Path(cache_root)
        self.fetcher = fetcher or HttpFetcher(settings.http_timeout)
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep
        self._last_nvd_call = 0.0

    # ------------------------------------------------------------------ cache
    def _read(self, path: Path) -> Cached | None:
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return Cached(d["payload"], d["sha256"], d["url"], d["retrieved_at"])
        except (OSError, ValueError, KeyError):
            return None

    def _write(self, path: Path, res: FetchResult) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"url": res.url, "retrieved_at": res.retrieved_at,
                                        "sha256": res.sha256, "payload": res.payload}), encoding="utf-8")
        except OSError:
            pass  # caching is an optimisation; the live result is still returned

    def _fresh_enough(self, cached: Cached) -> bool:
        try:
            when = datetime.fromisoformat(cached.retrieved_at)
        except ValueError:
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return self.now() - when <= timedelta(hours=self.s.cache_ttl_hours)

    def _get_cached_or_fetch(self, path: Path, fetch: Callable[[], FetchResult]) -> Cached:
        cached = self._read(path)
        if cached and self._fresh_enough(cached):
            return cached
        try:
            res = fetch()
        except FetchError:
            if cached:
                cached.stale = True
                return cached
            raise
        self._write(path, res)
        return Cached(res.payload, res.sha256, res.url, res.retrieved_at)

    # -------------------------------------------------------------------- KEV
    def kev_catalog(self) -> Cached:
        return self._get_cached_or_fetch(self.root / "kev_live.json",
                                         lambda: self.fetcher.get_json(self.s.kev_url))

    @staticmethod
    def kev_entry(catalog: Cached, cve_id: str) -> dict | None:
        for item in catalog.payload.get("vulnerabilities", []):
            if str(item.get("cveID", "")).upper() == cve_id.upper():
                return item
        return None

    @staticmethod
    def kev_recent(catalog: Cached, count: int) -> list[dict]:
        items = sorted(catalog.payload.get("vulnerabilities", []), key=lambda i: i.get("dateAdded", ""), reverse=True)
        return items[:count]

    # -------------------------------------------------------------------- NVD
    def nvd_record(self, cve_id: str) -> tuple[Cached, dict | None]:
        """Returns (cache record, parsed summary or None if NVD has no such CVE)."""
        if not CVE_RE.match(cve_id.upper()):
            raise FetchError(f"{cve_id!r} is not a valid CVE id")
        path = self.root / "nvd" / f"{cve_id.upper()}.json"

        def fetch() -> FetchResult:
            wait = self.s.nvd_delay_seconds - (time.monotonic() - self._last_nvd_call)
            if self._last_nvd_call and wait > 0:
                self.sleep(wait)
            headers = {"apiKey": self.s.nvd_api_key} if self.s.nvd_api_key else None
            try:
                return self.fetcher.get_json(self.s.nvd_url, {"cveId": cve_id.upper()}, headers)
            finally:
                self._last_nvd_call = time.monotonic()

        cached = self._get_cached_or_fetch(path, fetch)
        return cached, parse_nvd(cached.payload)


def parse_nvd(payload: Any) -> dict | None:
    vulns = (payload or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    metric = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if cve.get("metrics", {}).get(key):
            metric = cve["metrics"][key][0].get("cvssData", {})
            break
    cwes = sorted({d.get("value", "") for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    return {
        "id": cve.get("id"), "status": cve.get("vulnStatus"), "published": cve.get("published"),
        "last_modified": cve.get("lastModified"), "description": desc,
        "cvss_score": (metric or {}).get("baseScore"), "cvss_severity": (metric or {}).get("baseSeverity"),
        "cvss_vector": (metric or {}).get("vectorString"), "cwes": cwes,
        "reference_count": len(cve.get("references", [])),
    }
