"""Settings for Milestone 14, read from environment variables / .env."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cti_agent.config import load_env

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _num(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class VerifySettings:
    fresh_enabled: bool = True
    cache_dir: str = "data/fresh_cache"
    cache_ttl_hours: float = 12.0
    kev_url: str = KEV_URL
    nvd_url: str = NVD_URL
    nvd_api_key: str = ""
    nvd_delay_seconds: float = 0.7
    http_timeout: int = 30
    max_fresh_cves: int = 5
    recent_kev_count: int = 5
    use_llm_judge: bool = False
    min_overlap: float = 0.5
    max_rewrites: int = 1
    persist_mongo: bool = True
    runs_collection: str = "investigation_runs"
    traces_collection: str = "investigation_traces"

    @classmethod
    def from_env(cls, load_dotenv_file: bool = True) -> "VerifySettings":
        if load_dotenv_file:
            load_env()
        key = os.environ.get("NVD_API_KEY", "")
        return cls(
            fresh_enabled=_bool("FRESH_LOOKUP_ENABLED", True),
            cache_dir=os.environ.get("FRESH_CACHE_DIR", "data/fresh_cache"),
            cache_ttl_hours=_num("FRESH_CACHE_TTL_HOURS", 12.0),
            nvd_api_key=key,
            nvd_delay_seconds=0.7 if key else 6.5,  # NVD public rate limits
            http_timeout=int(_num("FRESH_HTTP_TIMEOUT", 30)),
            max_fresh_cves=int(_num("FRESH_MAX_CVES", 5)),
            recent_kev_count=int(_num("FRESH_RECENT_KEV_COUNT", 5)),
            use_llm_judge=_bool("VERIFY_USE_LLM_JUDGE", False),
            min_overlap=_num("VERIFY_MIN_OVERLAP", 0.5),
            max_rewrites=int(_num("VERIFY_MAX_REWRITES", 1)),
            persist_mongo=_bool("PERSIST_MONGO", True),
            runs_collection=os.environ.get("INVESTIGATION_RUNS_COLLECTION", "investigation_runs"),
            traces_collection=os.environ.get("INVESTIGATION_TRACES_COLLECTION", "investigation_traces"),
        )
