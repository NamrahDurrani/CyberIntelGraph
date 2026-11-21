"""Where a finished investigation is saved.

Default: a JSON file under outputs/investigations/ (git-ignored). Milestone 14
adds a MongoDB store through the 'post_finalize' hook; the file copy is always
written first, so a database outage can never lose a result."""

from __future__ import annotations

from typing import Any, Protocol

from .deps import Deps
from .trace import save_trace


class InvestigationStore(Protocol):
    def save(self, final: dict[str, Any]) -> str | None: ...


class JsonFileStore:
    def __init__(self, directory):
        self.directory = directory

    def save(self, final: dict[str, Any]) -> str | None:
        path = save_trace(final, self.directory)
        return str(path) if path else None


def get_store(deps: Deps) -> InvestigationStore:
    return deps.extras.get("store") or JsonFileStore(deps.settings.resolve(deps.settings.trace_dir))
