"""Settings for the research agent. Everything comes from environment
variables (normally the git-ignored .env file). Secrets are never hard-coded."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def project_root() -> Path:
    """Project root = the folder that contains the cti_agent package."""
    return Path(__file__).resolve().parents[1]


def load_env(path: Path | str | None = None) -> None:
    """Load KEY=VALUE pairs from .env without overriding real environment variables."""
    env_path = Path(path) if path else project_root() / ".env"
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(env_path, override=False)
        return
    except ImportError:
        pass
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = field(default="", repr=False)
    neo4j_database: str = ""
    groq_api_key: str = field(default="", repr=False)
    groq_model: str = "openai/gpt-oss-20b"
    groq_reasoning_effort: str = ""
    llm_timeout: int = 60
    llm_max_tokens: int = 2000
    use_llm: bool = True
    max_entities: int = 6
    neighbor_sample: int = 12
    neighbor_groups: int = 6
    candidate_limit: int = 8
    text_top_k: int = 6
    max_retries: int = 1
    max_prompt_chars: int = 14000
    max_parallel: int = 4
    max_duration_seconds: int = 120
    max_tool_calls: int = 60
    checkpoint: str = "memory"
    mongo_uri: str = field(default="", repr=False)
    mongo_database: str = "cyberintel"
    rag_retriever: str = ""
    trace_dir: str = "outputs/investigations"
    schema_cache: str = "data/agent/graph_schema.json"

    @classmethod
    def from_env(cls, load_dotenv_file: bool = True) -> "Settings":
        if load_dotenv_file:
            load_env()
        return cls(
            neo4j_uri=_first_env("NEO4J_URI"),
            neo4j_user=_first_env("NEO4J_USERNAME", "NEO4J_USER"),
            neo4j_password=_first_env("NEO4J_PASSWORD"),
            neo4j_database=_first_env("NEO4J_DATABASE"),
            groq_api_key=_first_env("GROQ_API_KEY"),
            groq_model=_first_env("GROQ_MODEL", default="openai/gpt-oss-20b"),
            groq_reasoning_effort=_first_env("GROQ_REASONING_EFFORT"),
            llm_timeout=_int("AGENT_LLM_TIMEOUT", 60),
            llm_max_tokens=_int("AGENT_LLM_MAX_TOKENS", 2000),
            use_llm=_bool("AGENT_USE_LLM", True),
            max_entities=_int("AGENT_MAX_ENTITIES", 6),
            neighbor_sample=_int("AGENT_NEIGHBOR_SAMPLE", 12),
            neighbor_groups=_int("AGENT_NEIGHBOR_GROUPS", 6),
            candidate_limit=_int("AGENT_CANDIDATE_LIMIT", 8),
            text_top_k=_int("AGENT_TEXT_TOP_K", 6),
            max_retries=_int("AGENT_MAX_RETRIES", 1),
            max_prompt_chars=_int("AGENT_MAX_PROMPT_CHARS", 14000),
            max_parallel=_int("AGENT_MAX_PARALLEL", 4),
            max_duration_seconds=_int("AGENT_MAX_DURATION_SECONDS", 120),
            max_tool_calls=_int("AGENT_MAX_TOOL_CALLS", 60),
            checkpoint=_first_env("AGENT_CHECKPOINT", default="memory"),
            mongo_uri=_first_env("MONGODB_URI", "MONGO_URI", "MONGODB_URL", "MONGODB_ATLAS_URI"),
            mongo_database=_first_env("MONGODB_DATABASE", "MONGODB_DB", "MONGO_DB", default="cyberintel"),
            rag_retriever=_first_env("RAG_RETRIEVER"),
            trace_dir=_first_env("AGENT_TRACE_DIR", default="outputs/investigations"),
            schema_cache=_first_env("AGENT_SCHEMA_CACHE", default="data/agent/graph_schema.json"),
        )

    def resolve(self, relative: str) -> Path:
        p = Path(relative)
        return p if p.is_absolute() else project_root() / p

    def missing_neo4j(self) -> list[str]:
        missing = []
        if not self.neo4j_uri:
            missing.append("NEO4J_URI")
        if not self.neo4j_user:
            missing.append("NEO4J_USERNAME")
        if not self.neo4j_password:
            missing.append("NEO4J_PASSWORD")
        return missing
